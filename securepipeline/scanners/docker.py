"""Dockerfile lint (Hadolint) and filesystem audit (Trivy)."""

from pathlib import Path

from securepipeline.core.models import Finding, Severity
from securepipeline.scanners.base import BaseScanner, Check, NothingToScan, ScannerInfo, load_json
from securepipeline.utils.files import iter_project_files
from securepipeline.utils.process import run_command

HADOLINT_LEVELS = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "style": Severity.INFO,
}
TRIVY_SKIP_DIRS = "**/.git,**/.venv,**/venv,**/.securepipeline"


class DockerScanner(BaseScanner):
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Docker",
            description="Dockerfile lint (Hadolint), CVEs and misconfigurations (Trivy)",
            stack="docker",
        )

    def checks(self) -> list[Check]:
        return [Check("hadolint", self._run_hadolint), Check("trivy", self._run_trivy)]

    def _run_hadolint(self, root: Path) -> list[Finding]:
        dockerfiles = sorted(
            str(path.relative_to(root))
            for path in iter_project_files(root, _is_dockerfile)
        )
        if not dockerfiles:
            raise NothingToScan("no Dockerfile")
        # Hadolint returns 1 when it finds issues.
        command = ["hadolint", "--format", "json", *dockerfiles]
        return parse_hadolint(load_json(run_command(command, cwd=root, timeout=120)))

    def _run_trivy(self, root: Path) -> list[Finding]:
        command = [
            "trivy", "fs",
            "--format", "json",
            "--scanners", "vuln,misconfig",
            "--skip-dirs", TRIVY_SKIP_DIRS,
            "--quiet",
            str(root),
        ]
        return parse_trivy(load_json(run_command(command, cwd=root, timeout=900), ok_codes=(0,)))


def _is_dockerfile(name: str) -> bool:
    return name.startswith("Dockerfile") and not name.endswith(".dockerignore")


def parse_hadolint(data: list) -> list[Finding]:
    return [
        Finding(
            rule_id=item.get("code", "DL0000"),
            title=item.get("message", "Hadolint issue"),
            severity=HADOLINT_LEVELS.get(item.get("level", "warning"), Severity.MEDIUM),
            file_path=item.get("file", ""),
            line=item.get("line", 0),
            remediation=f"https://github.com/hadolint/hadolint/wiki/{item.get('code', '')}",
            scanner="hadolint",
        )
        for item in data
    ]


def parse_trivy(data: dict) -> list[Finding]:
    findings = []
    for result in data.get("Results") or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            fixed = vuln.get("FixedVersion")
            findings.append(Finding(
                rule_id=vuln.get("VulnerabilityID", "CVE-UNKNOWN"),
                title=f"{vuln.get('PkgName', '?')}: {vuln.get('Title', 'vulnerability')}",
                severity=Severity.from_label(vuln.get("Severity", "MEDIUM")),
                file_path=target,
                description=vuln.get("Description", "")[:300],
                remediation=f"Upgrade to {fixed}" if fixed else "No known fix",
                scanner="trivy",
            ))
        for misconfig in result.get("Misconfigurations") or []:
            findings.append(Finding(
                rule_id=misconfig.get("ID", "MISC-UNKNOWN"),
                title=misconfig.get("Title", "Misconfiguration"),
                severity=Severity.from_label(misconfig.get("Severity", "MEDIUM")),
                file_path=target,
                line=(misconfig.get("CauseMetadata") or {}).get("StartLine", 0),
                description=misconfig.get("Description", "")[:300],
                remediation=misconfig.get("Resolution", ""),
                scanner="trivy",
            ))
    return findings
