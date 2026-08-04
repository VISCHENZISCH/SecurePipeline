"""SecurePipeline - Scanner Node.js (npm audit, Semgrep JS/TS)."""

import json
from pathlib import Path

from securepipeline.core.models import Finding, Severity
from securepipeline.modules.base import BaseScanner, ScannerInfo
from securepipeline.utils.logger import log
from securepipeline.utils.subprocess_runner import run_command, check_tool


class NodeScanner(BaseScanner):
    """Scanner de sécurité pour les projets Node.js / JavaScript / TypeScript.

    Outils utilisés :
    - npm audit    : audit des dépendances (CVE)
    - semgrep      : règles SAST JS/TS
    """

    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Node.js Scanner",
            description="Audit dépendances + SAST JS/TS (npm audit, Semgrep)",
            tools_required=["npm", "semgrep"],
            stack="node",
        )

    def scan(self, path: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._run_npm_audit(path))
        findings.extend(self._run_semgrep(path))
        return findings

    # ── npm audit ─────────────────────────────────────────────────────

    def _run_npm_audit(self, path: str) -> list[Finding]:
        """Audit des dépendances Node.js avec npm audit."""
        if not check_tool("npm"):
            log.warning("npm non installé, module ignoré")
            return []

        # Vérifier que package.json existe
        if not (Path(path) / "package.json").exists():
            return []

        log.info("[Node.js] → npm audit")
        cmd = ["npm", "audit", "--json"]
        result = run_command(cmd, cwd=path, timeout=120)

        # npm audit retourne code 1 s'il trouve des vulns
        if result.stdout:
            return self._parse_npm_audit(result.stdout)
        return []

    def _parse_npm_audit(self, output: str) -> list[Finding]:
        """Parse la sortie JSON de npm audit."""
        findings = []
        try:
            data = json.loads(output)
            vulnerabilities = data.get("vulnerabilities", {})

            for pkg_name, vuln_info in vulnerabilities.items():
                severity = self._map_npm_severity(vuln_info.get("severity", "moderate"))
                via_list = vuln_info.get("via", [])

                # Extraire la description depuis 'via'
                desc_parts = []
                for via in via_list:
                    if isinstance(via, dict):
                        desc_parts.append(via.get("title", ""))
                    elif isinstance(via, str):
                        desc_parts.append(via)

                findings.append(Finding(
                    rule_id=f"NPM-{vuln_info.get('severity', 'unknown').upper()}",
                    title=f"Vulnérabilité dans {pkg_name} ({vuln_info.get('range', '?')})",
                    severity=severity,
                    description=" | ".join(desc_parts)[:500] if desc_parts else "",
                    remediation=f"npm audit fix / Mettre à jour {pkg_name}",
                    scanner="npm-audit",
                ))
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(f"Erreur parsing npm audit : {e}")
        return findings

    @staticmethod
    def _map_npm_severity(severity: str) -> Severity:
        sev_map = {
            "critical": Severity.CRITICAL,
            "high":     Severity.HIGH,
            "moderate": Severity.MEDIUM,
            "low":      Severity.LOW,
            "info":     Severity.INFO,
        }
        return sev_map.get(severity.lower(), Severity.MEDIUM)

    # ── Semgrep ───────────────────────────────────────────────────────

    def _run_semgrep(self, path: str) -> list[Finding]:
        """Analyse SAST avec Semgrep (règles JavaScript/TypeScript)."""
        if not check_tool("semgrep"):
            log.warning("semgrep non installé, module ignoré")
            return []

        log.info("[Node.js] → semgrep")
        cmd = [
            "semgrep", "scan",
            "--config", "p/javascript",
            "--config", "p/typescript",
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
                    scanner="semgrep-js",
                ))
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(f"Erreur parsing semgrep JS : {e}")
        return findings

    @staticmethod
    def _map_semgrep_severity(severity: str) -> Severity:
        sev_map = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.INFO,
        }
        return sev_map.get(severity.upper(), Severity.MEDIUM)
