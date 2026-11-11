"""Node.js dependency audit (npm audit)."""

from pathlib import Path

from securepipeline.core.models import Finding, Severity
from securepipeline.scanners.base import (
    BaseScanner,
    Check,
    CheckSkipped,
    NothingToScan,
    ScannerInfo,
    ToolError,
    audit_dirs,
    load_json,
)
from securepipeline.utils.files import manifest_dirs
from securepipeline.utils.process import run_command

LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")


class NodeScanner(BaseScanner):
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Node.js",
            description="Dependency audit (npm audit)",
            stack="node",
        )

    def checks(self) -> list[Check]:
        return [Check("npm", self._run_npm_audit)]

    def _run_npm_audit(self, root: Path) -> list[Finding]:
        dirs = manifest_dirs(root, {"package.json"}, LOCKFILES)
        if not dirs:
            raise NothingToScan("no package.json")
        return audit_dirs(root, dirs, _npm_audit)


def _npm_audit(directory: Path) -> list[Finding]:
    if not any((directory / name).exists() for name in LOCKFILES):
        raise CheckSkipped("package-lock.json missing, npm audit cannot check anything")
    data = load_json(run_command(["npm", "audit", "--json"], cwd=directory, timeout=300))
    if data.get("error"):
        raise ToolError(str(data["error"].get("summary", "npm audit error"))[:160])
    return parse_npm_audit(data)


def parse_npm_audit(data: dict) -> list[Finding]:
    """Return one finding per vulnerable package."""
    findings = []
    for package, vuln in data.get("vulnerabilities", {}).items():
        advisories = [via for via in vuln.get("via", []) if isinstance(via, dict)]
        inherited = [via for via in vuln.get("via", []) if isinstance(via, str)]
        titles = [via.get("title", "") for via in advisories]
        description = " | ".join(titles) or f"Via: {', '.join(inherited)}"
        fix = "npm audit fix" if vuln.get("fixAvailable") else "No automatic fix"
        findings.append(Finding(
            rule_id=_advisory_id(advisories) or f"NPM-{package}",
            title=f"Vulnerability in {package} ({vuln.get('range', '?')})",
            severity=Severity.from_label(vuln.get("severity", "moderate")),
            file_path="package-lock.json",
            description=description[:500],
            remediation=fix,
            scanner="npm-audit",
        ))
    return findings


def _advisory_id(advisories: list[dict]) -> str:
    return advisories[0].get("url", "").rsplit("/", 1)[-1] if advisories else ""
