"""Python dependency audit (pip-audit) and static analysis (Bandit)."""

import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from securepipeline.core.models import Finding, Severity
from securepipeline.scanners.base import (
    BaseScanner,
    Check,
    CheckSkipped,
    NothingToScan,
    ScannerInfo,
    audit_dirs,
    load_json,
)
from securepipeline.utils.files import EXCLUDED_DIRS, manifest_dirs
from securepipeline.utils.process import run_command

PYTHON_MANIFESTS = {"requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "poetry.lock"}
OSV_URL = "https://api.osv.dev/v1/vulns/{}"
OSV_TIMEOUT = 10
OSV_WORKERS = 8


class PythonScanner(BaseScanner):
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Python",
            description="Dependency audit and Python SAST (pip-audit, Bandit)",
            stack="python",
        )

    def checks(self) -> list[Check]:
        return [Check("pip-audit", self._run_pip_audit), Check("bandit", self._run_bandit)]

    def _run_pip_audit(self, root: Path) -> list[Finding]:
        dirs = manifest_dirs(root, PYTHON_MANIFESTS)
        if not dirs:
            raise NothingToScan("no Python manifest")
        return audit_dirs(root, dirs, _pip_audit)

    def _run_bandit(self, root: Path) -> list[Finding]:
        excluded = ",".join(f"*/{name}/*" for name in sorted(EXCLUDED_DIRS))
        command = ["bandit", "-r", str(root), "-x", excluded, "-f", "json", "-q"]
        findings = parse_bandit(load_json(run_command(command, cwd=root, timeout=300)))
        return [f for f in findings if not (f.rule_id == "B101" and is_test_file(f.file_path))]


def is_test_file(path: str) -> bool:
    """pytest relies on assert, so B101 is only meaningful outside the tests."""
    p = Path(path)
    return (
        p.name == "conftest.py"
        or p.name.startswith("test_")
        or p.stem.endswith("_test")
        or any(part in ("test", "tests") for part in p.parent.parts)
    )


def _pip_audit(directory: Path) -> list[Finding]:
    command = ["pip-audit", "--format", "json", "--output", "-"]
    if (directory / "requirements.txt").exists():
        manifest = "requirements.txt"
        command.extend(["--requirement", str(directory / manifest)])
    elif (directory / "pyproject.toml").exists():
        manifest = "pyproject.toml"
        command.append(str(directory))
    else:
        raise CheckSkipped("no requirements.txt or pyproject.toml to audit")

    data = load_json(run_command(command, cwd=directory, timeout=600))
    findings = parse_pip_audit(data, _fetch_severities(data))
    for finding in findings:
        finding.file_path = manifest
    return findings


def _vulnerabilities(data: dict | list) -> list[dict]:
    dependencies = data if isinstance(data, list) else data.get("dependencies", [])
    return [vuln for dep in dependencies for vuln in dep.get("vulns", [])]


def _fetch_severities(data: dict | list) -> dict[str, Severity]:
    """Look up severities on OSV.dev, since pip-audit does not provide any."""
    vulns = _vulnerabilities(data)
    if not vulns:
        return {}
    with ThreadPoolExecutor(max_workers=OSV_WORKERS) as pool:
        labels = pool.map(_lookup_severity, vulns)
    return {
        vuln["id"]: Severity.from_label(label)
        for vuln, label in zip(vulns, labels, strict=True)
        if label
    }


def _lookup_severity(vuln: dict) -> str | None:
    """Read the severity from the GitHub advisory, the source that provides one."""
    identifiers = [vuln.get("id", ""), *vuln.get("aliases", [])]
    identifiers.sort(key=lambda value: not value.startswith("GHSA-"))
    url = OSV_URL.format(identifiers[0])
    try:
        with urllib.request.urlopen(url, timeout=OSV_TIMEOUT) as response:  # nosec B310 - fixed https URL
            record = json.load(response)
    except (OSError, ValueError):
        return None
    return record.get("database_specific", {}).get("severity")


def parse_pip_audit(data: dict | list, severities: dict[str, Severity]) -> list[Finding]:
    """An unknown severity stays MEDIUM, and the report says so."""
    dependencies = data if isinstance(data, list) else data.get("dependencies", [])
    findings = []
    for dep in dependencies:
        for vuln in dep.get("vulns", []):
            vuln_id = vuln.get("id", "UNKNOWN")
            fixes = vuln.get("fix_versions", [])
            description = vuln.get("description", "")[:500]
            if vuln_id not in severities:
                description = f"[Unknown severity, defaulted to MEDIUM] {description}"
            findings.append(Finding(
                rule_id=vuln_id,
                title=f"Vulnerability in {dep.get('name', '?')} {dep.get('version', '?')}",
                severity=severities.get(vuln_id, Severity.MEDIUM),
                file_path="Python dependencies",
                description=description,
                remediation=f"Upgrade to: {', '.join(fixes)}" if fixes else "No known fix",
                scanner="pip-audit",
            ))
    return findings


def parse_bandit(data: dict) -> list[Finding]:
    findings = []
    for issue in data.get("results", []):
        severity = str(issue.get("issue_severity", "MEDIUM")).upper()
        confidence = str(issue.get("issue_confidence", "MEDIUM")).upper()
        findings.append(Finding(
            rule_id=issue.get("test_id", "B000"),
            title=issue.get("issue_text", "Issue detected"),
            severity=(
                Severity.CRITICAL
                if severity == "HIGH" and confidence == "HIGH"
                else Severity.from_label(severity)
            ),
            file_path=issue.get("filename", ""),
            line=issue.get("line_number", 0),
            description=f"{issue.get('test_name', '')} (confidence: {confidence.lower()})",
            remediation=issue.get("more_info", ""),
            scanner="bandit",
        ))
    return findings
