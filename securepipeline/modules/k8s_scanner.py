"""SecurePipeline - Scanner Kubernetes (kube-score, checkov)."""

import json
from pathlib import Path

from securepipeline.core.models import Finding, Severity
from securepipeline.modules.base import BaseScanner, ScannerInfo
from securepipeline.utils.logger import log
from securepipeline.utils.subprocess_runner import check_tool, run_command


class K8sScanner(BaseScanner):
    """Scanner pour manifests Kubernetes (kube-score, checkov)."""

    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Kubernetes Scanner",
            description="Audit de sécurité des manifests K8s",
            tools_required=["kube-score", "checkov"],
            stack="k8s",
        )

    def scan(self, path: str) -> list[Finding]:
        findings: list[Finding] = []
        k8s_files = self._find_manifests(path)
        if not k8s_files:
            return findings

        findings.extend(self._run_kube_score(k8s_files))
        findings.extend(self._run_checkov(path))
        return findings

    def _find_manifests(self, path: str) -> list[str]:
        p = Path(path)
        # Chercher dans k8s/ ou kubernetes/ ou n'importe quel .yaml
        # (très basique pour l'exemple)
        files = []
        for ext in ["*.yaml", "*.yml"]:
            files.extend(list(p.glob(f"**/{ext}")))
        # Filtrer un peu naïvement
        return [str(f) for f in files if "k8s" in str(f).lower() or "kubernetes" in str(f).lower()]

    def _run_kube_score(self, files: list[str]) -> list[Finding]:
        if not check_tool("kube-score"):
            log.warning("kube-score non installé")
            return []
        
        log.info("[K8s] kube-score")
        findings = []
        for f in files:
            result = run_command(["kube-score", "score", "--output-format", "json", f], timeout=60)
            if not result.stdout:
                continue
            try:
                data = json.loads(result.stdout)
                for item in data:
                    for check in item.get("checks", []):
                        if check.get("grade", 10) < 10:
                            findings.append(Finding(
                                rule_id=check.get("check", {}).get("id", "KUBE-SCORE"),
                                title=check.get("check", {}).get("name", "Problème K8s"),
                                severity=Severity.HIGH if check.get("grade", 10) < 5 else Severity.MEDIUM,
                                file_path=f,
                                description=check.get("check", {}).get("description", ""),
                                scanner="kube-score",
                            ))
            except json.JSONDecodeError:
                pass
        return findings

    def _run_checkov(self, path: str) -> list[Finding]:
        if not check_tool("checkov"):
            log.warning("checkov non installé")
            return []
        
        log.info("[K8s] checkov")
        result = run_command(
            ["checkov", "-d", path, "--framework", "kubernetes", "-o", "json"],
            timeout=180
        )
        if not result.stdout:
            return []
        
        findings = []
        try:
            data = json.loads(result.stdout)
            # Checkov peut retourner une liste (si multi-framework) ou un dict
            results = data if isinstance(data, list) else [data]
            for res in results:
                failed = res.get("results", {}).get("failed_checks", [])
                for check in failed:
                    findings.append(Finding(
                        rule_id=check.get("check_id", "CKV-UNKNOWN"),
                        title=check.get("check_name", "Checkov issue"),
                        severity=Severity.HIGH,  # Checkov ne donne pas tjs la sévérité via JSON simple
                        file_path=check.get("file_path", ""),
                        line=check.get("file_line_range", [0])[0],
                        remediation=check.get("guideline", ""),
                        scanner="checkov",
                    ))
        except json.JSONDecodeError:
            pass
        return findings
