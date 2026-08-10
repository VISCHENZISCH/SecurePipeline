"""SecurePipeline - Scanner Python (pip-audit, Bandit, Semgrep)."""

import json
from pathlib import Path

from securepipeline.core.models import Finding, Severity
from securepipeline.modules.base import BaseScanner, ScannerInfo
from securepipeline.utils.logger import log
from securepipeline.utils.subprocess_runner import check_tool, run_command


class PythonScanner(BaseScanner):
    """Scanner de sécurité pour les projets Python.

    Outils utilisés :
    - pip-audit  : audit des dépendances (CVE)
    - bandit     : analyse statique (SAST) Python
    - semgrep    : règles SAST avancées Python
    """

    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Python Scanner",
            description="Audit dépendances + SAST Python (pip-audit, Bandit, Semgrep)",
            tools_required=["pip-audit", "bandit", "semgrep"],
            stack="python",
        )

    def scan(self, path: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._run_pip_audit(path))
        findings.extend(self._run_bandit(path))
        findings.extend(self._run_semgrep(path))
        return findings

    # pip-audit

    def _run_pip_audit(self, path: str) -> list[Finding]:
        """Audit des dépendances Python avec pip-audit."""
        if not check_tool("pip-audit"):
            log.warning("pip-audit non installé, module ignoré")
            return []

        log.info("[Python] pip-audit")

        # Chercher requirements.txt ou pyproject.toml
        req_file = Path(path) / "requirements.txt"
        cmd = ["pip-audit", "--format", "json", "--output", "-"]
        if req_file.exists():
            cmd.extend(["--requirement", str(req_file)])

        result = run_command(cmd, cwd=path, timeout=120)
        if result.stdout:
            return self._parse_pip_audit(result.stdout)
        return []

    def _parse_pip_audit(self, output: str) -> list[Finding]:
        """Parse la sortie JSON de pip-audit.

        pip-audit >= 2.x expose un champ ``severity`` (liste de dicts CVSS) par
        vulnérabilité. On l'utilise en priorité ; en l'absence, on extrait le score
        numérique CVSS pour estimer la sévérité plutôt que de tout mettre en HIGH.
        """
        findings = []
        try:
            data = json.loads(output)
            dependencies = data if isinstance(data, list) else data.get("dependencies", [])
            for dep in dependencies:
                for vuln in dep.get("vulns", []):
                    severity = self._map_pip_audit_severity(vuln)
                    findings.append(Finding(
                        rule_id=vuln.get("id", "UNKNOWN"),
                        title=f"Vulnérabilité dans {dep.get('name', '?')} {dep.get('version', '?')}",
                        severity=severity,
                        description=vuln.get("description", "")[:500],
                        remediation=f"Mettre à jour vers : {', '.join(vuln.get('fix_versions', []))}"
                        if vuln.get("fix_versions")
                        else "Aucune version corrective connue",
                        scanner="pip-audit",
                    ))
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(f"Erreur parsing pip-audit : {e}")
        return findings

    @staticmethod
    def _map_pip_audit_severity(vuln: dict) -> Severity:
        """Mappe la sévérité pip-audit vers Severity.

        Priorité :
        1. Champ ``severity`` direct (pip-audit >= 2.x, format OSV)
        2. Score CVSS numérique dans ``aliases`` / ``severity`` CVSS string
        3. Fallback MEDIUM (jamais HIGH par défaut — évite les faux positifs)
        """
        # Format pip-audit >= 2.x : [{"type": "cvssv3", "score": "CRITICAL"}, ...]
        for sev_entry in vuln.get("severity", []):
            label = str(sev_entry.get("score", "")).upper()
            mapping = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }
            if label in mapping:
                return mapping[label]
            # Certaines versions exposent un score numérique CVSS dans "score"
            try:
                score = float(label)
                if score >= 9.0:
                    return Severity.CRITICAL
                if score >= 7.0:
                    return Severity.HIGH
                if score >= 4.0:
                    return Severity.MEDIUM
                return Severity.LOW
            except ValueError:
                pass
        # Fallback conservateur : MEDIUM plutôt que HIGH aveugle
        return Severity.MEDIUM

    # Bandit

    def _run_bandit(self, path: str) -> list[Finding]:
        """Analyse statique Python avec Bandit."""
        if not check_tool("bandit"):
            log.warning("bandit non installé, module ignoré")
            return []

        log.info("[Python] bandit")
        cmd = ["bandit", "-r", path, "-f", "json", "-q"]
        result = run_command(cmd, cwd=path, timeout=120)

        # Bandit retourne code 1 s'il trouve des issues (pas une erreur)
        if result.stdout:
            return self._parse_bandit(result.stdout)
        return []

    def _parse_bandit(self, output: str) -> list[Finding]:
        """Parse la sortie JSON de Bandit."""
        findings = []
        try:
            data = json.loads(output)
            for issue in data.get("results", []):
                severity = self._map_bandit_severity(
                    issue.get("issue_severity", "MEDIUM"),
                    issue.get("issue_confidence", "MEDIUM"),
                )
                findings.append(Finding(
                    rule_id=issue.get("test_id", "B000"),
                    title=issue.get("issue_text", "Problème détecté"),
                    severity=severity,
                    file_path=issue.get("filename", ""),
                    line=issue.get("line_number", 0),
                    description=f"{issue.get('test_name', '')} - Confiance : {issue.get('issue_confidence', '')}",
                    remediation=issue.get("more_info", ""),
                    scanner="bandit",
                ))
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(f"Erreur parsing bandit : {e}")
        return findings

    @staticmethod
    def _map_bandit_severity(severity: str, confidence: str) -> Severity:
        sev_map = {
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        sev = sev_map.get(severity.upper(), Severity.MEDIUM)
        # Promouvoir en CRITICAL si haute sévérité + haute confiance
        if severity.upper() == "HIGH" and confidence.upper() == "HIGH":
            sev = Severity.CRITICAL
        return sev

    # Semgrep

    def _run_semgrep(self, path: str) -> list[Finding]:
        """Analyse SAST avancée avec Semgrep (règles Python)."""
        if not check_tool("semgrep"):
            log.warning("semgrep non installé, module ignoré")
            return []

        log.info("[Python] semgrep")
        cmd = [
            "semgrep", "scan",
            "--config", "p/python",
            "--json", "--quiet",
            path,
        ]
        result = run_command(cmd, cwd=path, timeout=180)
        if result.stdout:
            return self._parse_semgrep(result.stdout, "semgrep-python")
        return []

    def _parse_semgrep(self, output: str, scanner_name: str) -> list[Finding]:
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
                    scanner=scanner_name,
                ))
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(f"Erreur parsing semgrep : {e}")
        return findings

    @staticmethod
    def _map_semgrep_severity(severity: str) -> Severity:
        sev_map = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.INFO,
        }
        return sev_map.get(severity.upper(), Severity.MEDIUM)
