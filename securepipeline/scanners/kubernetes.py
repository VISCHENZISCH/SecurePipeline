"""Kubernetes manifest audit (kube-score, Checkov, kubesec)."""

from pathlib import Path

from securepipeline.core.models import Finding, Severity
from securepipeline.scanners.base import BaseScanner, Check, NothingToScan, ScannerInfo, load_json
from securepipeline.utils.files import iter_project_files
from securepipeline.utils.logger import log
from securepipeline.utils.process import run_command

K8S_DIRS = {"k8s", "kubernetes", "helm"}
KUBE_SCORE_OK_GRADE = 10
KUBE_SCORE_CRITICAL_GRADE = 1


class KubernetesScanner(BaseScanner):
    def __init__(self) -> None:
        self._manifests: dict[Path, list[str]] = {}

    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Kubernetes",
            description="Manifest audit (kube-score, Checkov, kubesec)",
            stack="k8s",
        )

    def checks(self) -> list[Check]:
        return [
            Check("kube-score", self._run_kube_score),
            Check("checkov", self._run_checkov),
            Check("kubesec", self._run_kubesec),
        ]

    def _manifests_for(self, root: Path) -> list[str]:
        if root not in self._manifests:
            self._manifests[root] = find_manifests(root)
        if not self._manifests[root]:
            raise NothingToScan("no Kubernetes manifest")
        return self._manifests[root]

    def _run_kube_score(self, root: Path) -> list[Finding]:
        command = ["kube-score", "score", "--output-format", "json", *self._manifests_for(root)]
        # kube-score returns 1 when a resource fails a check.
        return parse_kube_score(load_json(run_command(command, cwd=root, timeout=120)))

    def _run_checkov(self, root: Path) -> list[Finding]:
        command = [
            "checkov",
            "--framework", "kubernetes",
            "--output", "json",
            "--quiet",
            "--compact",
            "--skip-download",
            "--file", *self._manifests_for(root),
        ]
        return parse_checkov(load_json(run_command(command, cwd=root, timeout=300)))

    def _run_kubesec(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for manifest in self._manifests_for(root):
            # kubesec returns 2 for a resource kind it does not support (Service...).
            result = run_command(["kubesec", "scan", manifest], cwd=root, timeout=60)
            findings.extend(parse_kubesec(load_json(result, ok_codes=(0, 1, 2)), manifest))
        return findings


def find_manifests(root: Path) -> list[str]:
    """Return the manifests under a k8s/, kubernetes/ or helm/ directory.

    Unrendered Helm templates are excluded: they are not valid YAML, and a single
    invalid file would make the analysis of all the others fail.
    """
    manifests = []
    for path in iter_project_files(root, lambda name: name.endswith((".yaml", ".yml"))):
        relative = path.relative_to(root)
        if not K8S_DIRS.intersection(part.lower() for part in relative.parts[:-1]):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log.debug("Unreadable manifest %s: %s", path, e)
            continue
        if "apiVersion" in content and "{{" not in content:
            manifests.append(str(relative))
    return sorted(manifests)


def parse_kube_score(data: list) -> list[Finding]:
    findings = []
    for resource in data:
        for check in resource.get("checks", []):
            grade = check.get("grade", KUBE_SCORE_OK_GRADE)
            if check.get("skipped") or grade >= KUBE_SCORE_OK_GRADE:
                continue
            meta = check.get("check", {})
            comments = [c.get("summary", "") for c in check.get("comments") or []]
            findings.append(Finding(
                rule_id=meta.get("id", "KUBE-SCORE"),
                title=f"{meta.get('name', 'Kubernetes issue')} ({resource.get('object_name', '?')})",
                severity=Severity.HIGH if grade <= KUBE_SCORE_CRITICAL_GRADE else Severity.MEDIUM,
                file_path=resource.get("file_name", ""),
                line=resource.get("file_row", 0),
                description="; ".join(filter(None, comments)) or meta.get("comment", ""),
                scanner="kube-score",
            ))
    return findings


def parse_checkov(data: dict | list) -> list[Finding]:
    """Open source Checkov reports no severity, so findings default to MEDIUM."""
    findings = []
    for report in data if isinstance(data, list) else [data]:
        for check in report.get("results", {}).get("failed_checks", []):
            line_range = check.get("file_line_range") or [0]
            findings.append(Finding(
                rule_id=check.get("check_id", "CKV-UNKNOWN"),
                title=check.get("check_name", "Checkov issue"),
                severity=Severity.from_label(check.get("severity")),
                file_path=check.get("file_path", "").lstrip("/"),
                line=line_range[0],
                remediation=check.get("guideline") or "",
                scanner="checkov",
            ))
    return findings


def parse_kubesec(data: list | dict, manifest: str) -> list[Finding]:
    """Map kubesec "critical" items to HIGH and "advise" items to LOW."""
    findings = []
    for report in data if isinstance(data, list) else [data]:
        scoring = report.get("scoring") or {}
        groups = (("critical", Severity.HIGH), ("advise", Severity.LOW))
        for group, severity in groups:
            for item in scoring.get(group) or []:
                findings.append(Finding(
                    rule_id=item.get("id", "KUBESEC"),
                    title=item.get("reason") or item.get("selector", "kubesec issue"),
                    severity=severity,
                    file_path=manifest,
                    description=item.get("selector", ""),
                    scanner="kubesec",
                ))
    return findings
