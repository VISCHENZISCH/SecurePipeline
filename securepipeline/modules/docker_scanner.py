"""SecurePipeline - Scanner Docker (Trivy, Hadolint)."""

import json
from pathlib import Path
from securepipeline.core.models import Finding, Severity
from securepipeline.modules.base import BaseScanner, ScannerInfo
from securepipeline.utils.logger import log
from securepipeline.utils.subprocess_runner import run_command, check_tool


class DockerScanner(BaseScanner):
    """Scanner pour Dockerfiles et images Docker (Trivy, Hadolint)."""

    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Docker Scanner",
            description="Scan images Docker + lint Dockerfile (Trivy, Hadolint)",
            tools_required=["trivy", "hadolint"],
            stack="docker",
        )

    def scan(self, path: str) -> list[Finding]:
        findings: list[Finding] = []
        # Trouver tous les Dockerfiles
        dockerfiles = self._find_dockerfiles(path)
        for df in dockerfiles:
            findings.extend(self._run_hadolint(df))
            findings.extend(self._run_trivy_fs(path))
        if not dockerfiles:
            findings.extend(self._run_trivy_fs(path))
        return findings

    def _find_dockerfiles(self, path: str) -> list[str]:
        p = Path(path)
        files = list(p.glob("**/Dockerfile*"))
        return [str(f) for f in files if f.is_file()]

    # Hadolint

    def _run_hadolint(self, dockerfile: str) -> list[Finding]:
        if not check_tool("hadolint"):
            log.warning("hadolint non installé, module ignoré")
            return []
        log.info(f"[Docker] hadolint {Path(dockerfile).name}")
        result = run_command(
            ["hadolint", "--format", "json", dockerfile], timeout=60,
        )
        if not result.stdout:
            return []
        findings = []
        try:
            data = json.loads(result.stdout)
            for item in data:
                sev_map = {"error": Severity.HIGH, "warning": Severity.MEDIUM,
                           "info": Severity.LOW, "style": Severity.INFO}
                findings.append(Finding(
                    rule_id=item.get("code", "DL0000"),
                    title=item.get("message", "Hadolint issue"),
                    severity=sev_map.get(item.get("level", "warning"), Severity.MEDIUM),
                    file_path=item.get("file", dockerfile),
                    line=item.get("line", 0),
                    description=item.get("column", ""),
                    remediation=f"https://github.com/hadolint/hadolint/wiki/{item.get('code', '')}",
                    scanner="hadolint",
                ))
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(f"Erreur parsing hadolint : {e}")
        return findings

    # Trivy filesystem

    def _run_trivy_fs(self, path: str) -> list[Finding]:
        if not check_tool("trivy"):
            log.warning("trivy non installé, module ignoré")
            return []
        log.info("[Docker] trivy fs")
        result = run_command(
            ["trivy", "fs", "--format", "json", "--security-checks", "vuln,config", path],
            cwd=path, timeout=180,
        )
        if not result.stdout:
            return []
        findings = []
        try:
            data = json.loads(result.stdout)
            for res in data.get("Results", []):
                for vuln in res.get("Vulnerabilities", []):
                    sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                               "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
                    findings.append(Finding(
                        rule_id=vuln.get("VulnerabilityID", "CVE-UNKNOWN"),
                        title=f"{vuln.get('PkgName', '?')} - {vuln.get('Title', 'CVE')}",
                        severity=sev_map.get(vuln.get("Severity", "MEDIUM"), Severity.MEDIUM),
                        file_path=res.get("Target", ""),
                        description=vuln.get("Description", "")[:300],
                        remediation=f"Mettre à jour vers {vuln.get('FixedVersion', 'N/A')}",
                        scanner="trivy",
                    ))
                for misconf in res.get("Misconfigurations", []):
                    sev_map2 = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                                "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
                    findings.append(Finding(
                        rule_id=misconf.get("ID", "MISC-UNKNOWN"),
                        title=misconf.get("Title", "Misconfiguration"),
                        severity=sev_map2.get(misconf.get("Severity", "MEDIUM"), Severity.MEDIUM),
                        file_path=res.get("Target", ""),
                        description=misconf.get("Description", "")[:300],
                        remediation=misconf.get("Resolution", ""),
                        scanner="trivy",
                    ))
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(f"Erreur parsing trivy : {e}")
        return findings
