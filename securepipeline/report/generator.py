"""SecurePipeline - Générateur de rapports Markdown/HTML."""

from pathlib import Path
from datetime import datetime
from collections import defaultdict

from securepipeline.core.models import ScanResult, Severity


def generate_markdown(result: ScanResult, path: str, project_name: str = "Projet") -> str:
    """Génère un rapport Markdown à partir d'un ScanResult."""
    
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Statistiques
    stats = defaultdict(int)
    for f in result.findings:
        stats[f.severity.value] += 1
        
    md = [
        f"# Rapport de Sécurité DevSecOps - {project_name}",
        "",
        f"**Date du scan:** {date_str}",
        f"**Durée:** {result.duration_seconds:.2f}s",
        f"**Stacks détectées:** {', '.join(result.stacks_scanned) if result.stacks_scanned else 'Aucune'}",
        "",
        "## Résumé Exécutif",
        "",
        f"- Critique: {stats.get(Severity.CRITICAL.value, 0)}",
        f"- Élevé: {stats.get(Severity.HIGH.value, 0)}",
        f"- Moyen: {stats.get(Severity.MEDIUM.value, 0)}",
        f"- Faible: {stats.get(Severity.LOW.value, 0)}",
        f"- Info: {stats.get(Severity.INFO.value, 0)}",
        "",
        f"**Total Vulnérabilités:** {result.total}",
        "",
        "## Détails des Vulnérabilités par Module",
        ""
    ]

    # Grouper par scanner
    by_scanner = defaultdict(list)
    for f in result.findings:
        by_scanner[f.scanner].append(f)

    if not result.findings:
        md.append("**Aucune vulnérabilité détectée ! Bon travail.**")

    for scanner, findings in by_scanner.items():
        md.append(f"### Module: {scanner}")
        md.append("")
        
        # Table Header
        md.append("| Sévérité | Règle/CVE | Titre | Fichier | Ligne |")
        md.append("|---|---|---|---|---|")
        
        # Sort by severity
        sorted_findings = sorted(findings, key=lambda x: {"critical":0, "high":1, "medium":2, "low":3, "info":4}.get(x.severity.value, 5))
        
        badge_map = {
            "critical": "CRITIQUE",
            "high":     "ÉLEVÉ",
            "medium":   "MOYEN",
            "low":      "FAIBLE",
            "info":     "INFO",
        }
        
        for f in sorted_findings:
            sev_badge = badge_map.get(f.severity.value, f.severity.value.upper())
            file_link = f"`{f.file_path}`" if f.file_path else "N/A"
            line = f"`{f.line}`" if f.line else "N/A"
            md.append(f"| {sev_badge} | `{f.rule_id}` | {f.title} | {file_link} | {line} |")
        
        md.append("")
        md.append("<details><summary><b>Détails & Remédiations</b></summary>")
        md.append("")
        for f in sorted_findings:
            md.append(f"#### {f.title} (`{f.rule_id}`)")
            if f.description:
                md.append(f"**Description:** {f.description}")
            if f.remediation:
                md.append(f"**Remédiation:** {f.remediation}")
            md.append("")
        md.append("</details>")
        md.append("")

    return "\n".join(md)


def save_report(content: str, out_dir: str, filename: str = "securepipeline-report.md") -> str:
    """Sauvegarde le rapport sur le disque."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    file_path = out_path / filename
    
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
        
    return str(file_path)
