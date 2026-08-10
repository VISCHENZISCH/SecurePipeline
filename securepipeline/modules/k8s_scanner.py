"""SecurePipeline - Scanner Kubernetes (kube-score, checkov, kubesec)."""

import json
from pathlib import Path

from securepipeline.core.models import Finding, Severity
from securepipeline.modules.base import BaseScanner, ScannerInfo
from securepipeline.utils.logger import log
from securepipeline.utils.subprocess_runner import check_tool, run_command

# Dossiers à ignorer lors du scan des manifests K8s
_EXCLUDE_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".securepipeline"}


class K8sScanner(BaseScanner):
    """Scanner pour manifests Kubernetes (kube-score, checkov, kubesec)."""

    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Kubernetes Scanner",
            description="Audit de sécurité des manifests K8s (kube-score, checkov, kubesec)",
            tools_required=["kube-score", "checkov", "kubesec"],
            stack="k8s",
        )

    def scan(self, path: str) -> list[Finding]:
        findings: list[Finding] = []
        k8s_files = self._find_manifests(path)
        if not k8s_files:
            log.warning("[K8s] Aucun manifest Kubernetes non-vide trouvé.")
            return findings

        log.info(f"[K8s] {len(k8s_files)} manifest(s) détecté(s)")
        findings.extend(self._run_kube_score(k8s_files))
        findings.extend(self._run_checkov(path))
        findings.extend(self._run_kubesec(k8s_files))
        return findings

    # ------------------------------------------------------------------
    # Détection des manifests
    # ------------------------------------------------------------------

    def _find_manifests(self, path: str) -> list[str]:
        """Retourne les manifests Kubernetes réels (non vides, contenant apiVersion).

        Critères de sélection :
        - Situé dans un dossier nommé k8s/, kubernetes/ ou helm/
        - Contient le mot-clé « apiVersion » (détection de contenu)
        - Taille > 0 octet (exclut les fichiers placeholder vides)
        """
        p = Path(path)
        candidates: list[Path] = []

        for ext in ("*.yaml", "*.yml"):
            for f in p.rglob(ext):
                # Exclure les dossiers système
                if any(part in _EXCLUDE_DIRS for part in f.parts):
                    continue
                # Critère de chemin : doit être dans un répertoire K8s connu
                path_lower = str(f).lower()
                in_k8s_dir = any(
                    seg in path_lower
                    for seg in ("/k8s/", "/kubernetes/", "/helm/", "\\k8s\\", "\\kubernetes\\")
                )
                if not in_k8s_dir:
                    continue
                # Critère de contenu : fichier non vide ET contient apiVersion
                if f.stat().st_size == 0:
                    log.debug(f"[K8s] Ignoré (vide) : {f}")
                    continue
                try:
                    content = f.read_text(encoding="utf-8", errors="replace")
                    if "apiVersion" not in content:
                        log.debug(f"[K8s] Ignoré (pas de apiVersion) : {f}")
                        continue
                except OSError:
                    continue
                candidates.append(f)

        return [str(f) for f in candidates]

    # ------------------------------------------------------------------
    # kube-score
    # ------------------------------------------------------------------

    def _run_kube_score(self, files: list[str]) -> list[Finding]:
        if not check_tool("kube-score"):
            log.warning("kube-score non installé, module ignoré")
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
                        grade = check.get("grade", 10)
                        if grade >= 10:
                            continue
                        findings.append(Finding(
                            rule_id=check.get("check", {}).get("id", "KUBE-SCORE"),
                            title=check.get("check", {}).get("name", "Problème K8s"),
                            severity=Severity.HIGH if grade < 5 else Severity.MEDIUM,
                            file_path=f,
                            description=check.get("check", {}).get("description", ""),
                            scanner="kube-score",
                        ))
            except json.JSONDecodeError as e:
                log.warning(f"[K8s] Erreur parsing kube-score pour {f}: {e}")
        return findings

    # ------------------------------------------------------------------
    # checkov
    # ------------------------------------------------------------------

    def _run_checkov(self, path: str) -> list[Finding]:
        if not check_tool("checkov"):
            log.warning("checkov non installé, module ignoré")
            return []

        log.info("[K8s] checkov")
        result = run_command(
            ["checkov", "-d", path, "--framework", "kubernetes", "-o", "json"],
            timeout=180,
        )
        if not result.stdout:
            return []

        findings = []
        try:
            data = json.loads(result.stdout)
            # checkov peut retourner une liste (multi-framework) ou un dict
            results = data if isinstance(data, list) else [data]
            for res in results:
                failed = res.get("results", {}).get("failed_checks", [])
                for check in failed:
                    sev_label = check.get("check_result", {}).get("severity", "HIGH")
                    sev_map = {
                        "CRITICAL": Severity.CRITICAL,
                        "HIGH": Severity.HIGH,
                        "MEDIUM": Severity.MEDIUM,
                        "LOW": Severity.LOW,
                    }
                    findings.append(Finding(
                        rule_id=check.get("check_id", "CKV-UNKNOWN"),
                        title=check.get("check_name", "Checkov issue"),
                        severity=sev_map.get(str(sev_label).upper(), Severity.HIGH),
                        file_path=check.get("file_path", ""),
                        line=check.get("file_line_range", [0])[0],
                        remediation=check.get("guideline", ""),
                        scanner="checkov",
                    ))
        except json.JSONDecodeError as e:
            log.warning(f"[K8s] Erreur parsing checkov : {e}")
        return findings

    # ------------------------------------------------------------------
    # kubesec  (CDC §2.2 — 3ème outil K8s requis)
    # ------------------------------------------------------------------

    def _run_kubesec(self, files: list[str]) -> list[Finding]:
        """Analyse les manifests avec kubesec (https://kubesec.io).

        kubesec sort un tableau JSON :
        [{
            "object": "...", "valid": true, "score": 4,
            "scoring": {
                "critical": [{"id": "...", "selector": "...", "reason": "...", "weight": 7}],
                "advise":   [...]
            }
        }]
        On remonte tous les items « critical » comme HIGH et « advise » comme LOW.
        """
        if not check_tool("kubesec"):
            log.warning("kubesec non installé, module ignoré")
            return []

        log.info("[K8s] kubesec")
        findings = []
        for f in files:
            result = run_command(["kubesec", "scan", f], timeout=60)
            if not result.stdout:
                continue
            try:
                data = json.loads(result.stdout)
                reports = data if isinstance(data, list) else [data]
                for report in reports:
                    if not report.get("valid", True):
                        log.warning(f"[K8s] kubesec : manifest invalide ({report.get('message', '')})")
                        continue
                    scoring = report.get("scoring", {})
                    for item in scoring.get("critical", []):
                        findings.append(Finding(
                            rule_id=item.get("id", "KUBESEC"),
                            title=item.get("selector", "Problème kubesec critique"),
                            severity=Severity.HIGH,
                            file_path=f,
                            description=item.get("reason", ""),
                            scanner="kubesec",
                        ))
                    for item in scoring.get("advise", []):
                        findings.append(Finding(
                            rule_id=item.get("id", "KUBESEC-ADVISE"),
                            title=item.get("selector", "Recommandation kubesec"),
                            severity=Severity.LOW,
                            file_path=f,
                            description=item.get("reason", ""),
                            scanner="kubesec",
                        ))
            except json.JSONDecodeError as e:
                log.warning(f"[K8s] Erreur parsing kubesec pour {f}: {e}")
        return findings
