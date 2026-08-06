"""SecurePipeline - Module de rapport Markdown (refactoring).

Ce module encapsule la logique de generation de rapports Markdown
extraite de generator.py pour une meilleure separation des responsabilites.
"""

from datetime import datetime
from collections import defaultdict

from securepipeline.core.models import ScanResult, Severity


_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_FR = {
    "critical": "CRITIQUE",
    "high":     "ELEVE",
    "medium":   "MOYEN",
    "low":      "FAIBLE",
    "info":     "INFO",
}


def render_severity_badge(severity: str) -> str:
    """Retourne un badge textuel de severite pour Markdown."""
    return _SEV_FR.get(severity, severity.upper())


def render_stats_block(stats: dict[str, int], total: int) -> list[str]:
    """Genere le bloc de statistiques du resume executif.

    Args:
        stats: Dict {severity_value: count}.
        total: Total des findings.

    Returns:
        Liste de lignes Markdown.
    """
    lines = [
        "## Resume Executif",
        "",
        f"- Critique: {stats.get('critical', 0)}",
        f"- Eleve: {stats.get('high', 0)}",
        f"- Moyen: {stats.get('medium', 0)}",
        f"- Faible: {stats.get('low', 0)}",
        f"- Info: {stats.get('info', 0)}",
        "",
        f"**Total Vulnerabilites:** {total}",
        "",
    ]
    return lines


def render_findings_table(scanner: str, findings: list) -> list[str]:
    """Genere une section de findings pour un scanner donne.

    Args:
        scanner: Nom du scanner.
        findings: Liste de Finding.

    Returns:
        Liste de lignes Markdown.
    """
    lines = [
        f"### Module: {scanner}",
        "",
        "| Severite | Regle/CVE | Titre | Fichier | Ligne |",
        "|---|---|---|---|---|",
    ]

    sorted_findings = sorted(
        findings,
        key=lambda x: _SEV_ORDER.index(x.severity.value) if x.severity.value in _SEV_ORDER else 5
    )

    for f in sorted_findings:
        sev_badge = render_severity_badge(f.severity.value)
        file_link = f"`{f.file_path}`" if f.file_path else "N/A"
        line = f"`{f.line}`" if f.line else "N/A"
        lines.append(f"| {sev_badge} | `{f.rule_id}` | {f.title} | {file_link} | {line} |")

    lines.append("")

    # Details pliables
    lines.append("<details><summary><b>Details & Remediations</b></summary>")
    lines.append("")
    for f in sorted_findings:
        lines.append(f"#### {f.title} (`{f.rule_id}`)")
        if f.description:
            lines.append(f"**Description:** {f.description}")
        if f.remediation:
            lines.append(f"**Remediation:** {f.remediation}")
        lines.append("")
    lines.append("</details>")
    lines.append("")

    return lines


def generate_full_markdown(result: ScanResult, path: str, project_name: str = "Projet") -> str:
    """Genere un rapport Markdown complet.

    Args:
        result: Resultat du scan.
        path: Chemin du projet scanne.
        project_name: Nom du projet.

    Returns:
        Contenu Markdown complet.
    """
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    stats: dict[str, int] = defaultdict(int)
    for f in result.findings:
        stats[f.severity.value] += 1

    md: list[str] = [
        f"# Rapport de Securite DevSecOps - {project_name}",
        "",
        f"**Date du scan:** {date_str}",
        f"**Duree:** {result.duration_seconds:.2f}s",
        f"**Stacks detectees:** {', '.join(result.stacks_scanned) if result.stacks_scanned else 'Aucune'}",
        "",
    ]

    md.extend(render_stats_block(stats, result.total))

    md.append("## Details des Vulnerabilites par Module")
    md.append("")

    by_scanner: dict[str, list] = defaultdict(list)
    for f in result.findings:
        by_scanner[f.scanner].append(f)

    if not result.findings:
        md.append("**Aucune vulnerabilite detectee ! Bon travail.**")
    else:
        for scanner, findings in by_scanner.items():
            md.extend(render_findings_table(scanner, findings))

    return "\n".join(md)
