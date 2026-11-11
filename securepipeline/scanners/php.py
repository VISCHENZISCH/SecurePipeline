"""PHP/Laravel dependency audit (composer audit)."""

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
from securepipeline.utils.files import manifest_dirs
from securepipeline.utils.process import run_command


class PhpScanner(BaseScanner):
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="PHP/Laravel",
            description="Dependency audit (composer audit)",
            stack="php",
        )

    def checks(self) -> list[Check]:
        return [Check("composer", self._run_composer_audit)]

    def _run_composer_audit(self, root: Path) -> list[Finding]:
        dirs = manifest_dirs(root, {"composer.json", "composer.lock"})
        if not dirs:
            raise NothingToScan("no composer.json")
        return audit_dirs(root, dirs, _composer_audit)


def _composer_audit(directory: Path) -> list[Finding]:
    if not (directory / "composer.lock").exists():
        raise CheckSkipped("composer.lock missing, composer audit cannot check anything")
    command = ["composer", "audit", "--format", "json", "--no-interaction"]
    # Composer encodes its results in the return code: only the JSON is authoritative.
    return parse_composer_audit(
        load_json(run_command(command, cwd=directory, timeout=300), ok_codes=range(16)),
    )


def parse_composer_audit(data: dict) -> list[Finding]:
    # PHP encodes an empty table as []: "advisories" is not always an object.
    advisories = data.get("advisories") or {}
    findings = []
    for package, entries in advisories.items():
        # For the same reason, a package's advisories may be keyed by number.
        for advisory in entries.values() if isinstance(entries, dict) else entries:
            findings.append(Finding(
                rule_id=advisory.get("advisoryId", "COMPOSER-UNKNOWN"),
                title=advisory.get("title", f"Vulnerability in {package}"),
                severity=Severity.from_label(advisory.get("severity", "medium")),
                file_path="composer.lock",
                description=f"Package: {package} | CVE: {advisory.get('cve') or 'N/A'}",
                remediation=advisory.get("link", ""),
                scanner="composer-audit",
            ))
    return findings
