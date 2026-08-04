"""SecurePipeline - Scanner Flutter/Dart."""

import json
from pathlib import Path
from securepipeline.core.models import Finding, Severity
from securepipeline.modules.base import BaseScanner, ScannerInfo
from securepipeline.utils.logger import log
from securepipeline.utils.subprocess_runner import run_command, check_tool


class FlutterScanner(BaseScanner):
    """Scanner pour projets Flutter/Dart (dart pub outdated, Semgrep)."""

    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Flutter/Dart Scanner",
            description="Audit dépendances Dart + SAST",
            tools_required=["dart"],
            stack="flutter",
        )

    def scan(self, path: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._run_pub_outdated(path))
        findings.extend(self._run_semgrep(path))
        return findings

    def _run_pub_outdated(self, path: str) -> list[Finding]:
        if not check_tool("dart") or not (Path(path) / "pubspec.yaml").exists():
            return []
        log.info("[Flutter] → dart pub outdated")
        result = run_command(["dart", "pub", "outdated", "--json"], cwd=path, timeout=120)
        if not result.stdout:
            return []
        findings = []
        try:
            data = json.loads(result.stdout)
            for pkg in data.get("packages", []):
                current = pkg.get("current", {}).get("version", "?")
                latest = pkg.get("latest", {}).get("version", "")
                if latest and current != latest:
                    findings.append(Finding(
                        rule_id="DART-OUTDATED", scanner="dart-pub",
                        title=f"Dépendance obsolète : {pkg.get('package', '?')}",
                        severity=Severity.LOW,
                        description=f"Actuelle: {current} | Dernière: {latest}",
                        remediation=f"dart pub upgrade {pkg.get('package', '')}",
                    ))
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(f"Erreur parsing dart pub : {e}")
        return findings

    def _run_semgrep(self, path: str) -> list[Finding]:
        if not check_tool("semgrep"):
            return []
        log.info("[Flutter] → semgrep")
        result = run_command(
            ["semgrep", "scan", "--config", "p/dart", "--json", "--quiet", path],
            cwd=path, timeout=180,
        )
        if not result.stdout:
            return []
        findings = []
        try:
            data = json.loads(result.stdout)
            sev_map = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.INFO}
            for res in data.get("results", []):
                findings.append(Finding(
                    rule_id=res.get("check_id", "semgrep.unknown"),
                    title=res.get("extra", {}).get("message", "Issue")[:200],
                    severity=sev_map.get(res.get("extra", {}).get("severity", "WARNING").upper(), Severity.MEDIUM),
                    file_path=res.get("path", ""), line=res.get("start", {}).get("line", 0),
                    scanner="semgrep-dart",
                ))
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(f"Erreur parsing semgrep Dart : {e}")
        return findings
