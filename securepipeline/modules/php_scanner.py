"""SecurePipeline - Scanner PHP/Laravel (composer audit, Semgrep PHP)."""

import json
from pathlib import Path

from securepipeline.core.models import Finding, Severity
from securepipeline.modules.base import BaseScanner, ScannerInfo
from securepipeline.utils.logger import log
from securepipeline.utils.subprocess_runner import run_command, check_tool


class PhpScanner(BaseScanner):
    """Scanner de sécurité pour les projets PHP / Laravel.

    Outils utilisés :
    - composer audit : audit des dépendances PHP (CVE)
    - semgrep        : règles SAST PHP
    """

    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="PHP/Laravel Scanner",
            description="Audit dépendances + SAST PHP (composer audit, Semgrep)",
            tools_required=["composer", "semgrep"],
            stack="php",
        )

    def scan(self, path: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._run_composer_audit(path))
        findings.extend(self._run_semgrep(path))
        return findings

    # composer audit

    def _run_composer_audit(self, path: str) -> list[Finding]:
        """Audit des dépendances PHP avec composer audit."""
        if not check_tool("composer"):
            log.warning("composer non installé, module ignoré")
            return []

        if not (Path(path) / "composer.json").exists():
            return []

        log.info("[PHP] composer audit")
        cmd = ["composer", "audit", "--format", "json", "--no-interaction"]
        result = run_command(cmd, cwd=path, timeout=120)

        if result.stdout:
            return self._parse_composer_audit(result.stdout)
        return []

    def _parse_composer_audit(self, output: str) -> list[Finding]:
        """Parse la sortie JSON de composer audit."""
        findings = []
        try:
            data = json.loads(output)
            advisories = data.get("advisories", {})

            for pkg_name, advisories_list in advisories.items():
                for advisory in advisories_list:
                    severity = self._map_composer_severity(
                        advisory.get("severity", "medium")
                    )
                    findings.append(Finding(
                        rule_id=advisory.get("advisoryId", "COMPOSER-UNKNOWN"),
                        title=advisory.get("title", f"Vulnérabilité dans {pkg_name}"),
                        severity=severity,
                        description=f"Package: {pkg_name} | CVE: {advisory.get('cve', 'N/A')}",
                        remediation=advisory.get("link", ""),
                        scanner="composer-audit",
                    ))
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(f"Erreur parsing composer audit : {e}")
        return findings

    @staticmethod
    def _map_composer_severity(severity: str) -> Severity:
        sev_map = {
            "critical": Severity.CRITICAL,
            "high":     Severity.HIGH,
            "medium":   Severity.MEDIUM,
            "low":      Severity.LOW,
        }
        return sev_map.get(severity.lower(), Severity.MEDIUM)

    # Semgrep PHP

    def _run_semgrep(self, path: str) -> list[Finding]:
        """Analyse SAST avec Semgrep (règles PHP)."""
        if not check_tool("semgrep"):
            log.warning("semgrep non installé, module ignoré")
            return []

        log.info("[PHP] semgrep")
        cmd = [
            "semgrep", "scan",
            "--config", "p/php",
            "--json", "--quiet",
            path,
        ]
        result = run_command(cmd, cwd=path, timeout=180)
        if result.stdout:
            return self._parse_semgrep(result.stdout)
        return []

    def _parse_semgrep(self, output: str) -> list[Finding]:
        """Parse la sortie JSON de Semgrep."""
        findings = []
        try:
            data = json.loads(output)
            for res in data.get("results", []):
                severity = self._map_semgrep_severity(
                    res.get("extra", {}).get("severity", "WARNING")
                )
                findings.append(Finding(
                    rule_id=res.get("check_id", "semgrep.unknown"),
                    title=res.get("extra", {}).get("message", "Issue Semgrep")[:200],
                    severity=severity,
                    file_path=res.get("path", ""),
                    line=res.get("start", {}).get("line", 0),
                    description=res.get("extra", {}).get("metadata", {}).get("shortlink", ""),
                    scanner="semgrep-php",
                ))
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(f"Erreur parsing semgrep PHP : {e}")
        return findings

    @staticmethod
    def _map_semgrep_severity(severity: str) -> Severity:
        sev_map = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.INFO,
        }
        return sev_map.get(severity.upper(), Severity.MEDIUM)
