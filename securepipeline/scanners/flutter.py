"""Outdated Dart dependencies (no CVE audit is available for Dart)."""

from pathlib import Path

from securepipeline.core.models import Finding, Severity
from securepipeline.scanners.base import BaseScanner, Check, NothingToScan, ScannerInfo, load_json
from securepipeline.utils.process import run_command


class FlutterScanner(BaseScanner):
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Flutter/Dart",
            description="Outdated Dart dependencies (dart pub outdated)",
            stack="flutter",
        )

    def checks(self) -> list[Check]:
        return [Check("dart", self._run_pub_outdated)]

    def _run_pub_outdated(self, root: Path) -> list[Finding]:
        if not (root / "pubspec.yaml").exists():
            raise NothingToScan("no pubspec.yaml")
        command = ["dart", "pub", "outdated", "--json"]
        return parse_pub_outdated(load_json(run_command(command, cwd=root, timeout=300), ok_codes=(0,)))


def parse_pub_outdated(data: dict) -> list[Finding]:
    findings = []
    for package in data.get("packages", []):
        # Dart returns null for an unresolved version.
        current = (package.get("current") or {}).get("version", "?")
        latest = (package.get("latest") or {}).get("version", "")
        name = package.get("package", "?")
        if latest and current != latest:
            findings.append(Finding(
                rule_id="DART-OUTDATED",
                title=f"Outdated dependency: {name}",
                severity=Severity.LOW,
                file_path="pubspec.yaml",
                description=f"Current: {current} | Latest: {latest}",
                remediation=f"dart pub upgrade {name}",
                scanner="dart-pub",
            ))
    return findings
