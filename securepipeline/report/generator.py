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
        
    # Badges SVG Shields.io pour les statistiques
    md = [
        f"# <img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/master/svgs/solid/shield-halved.svg' width='30' align='center'/> Rapport de Sécurité DevSecOps - {project_name}",
        "",
        f"**Date du scan:** {date_str}",
        f"**Durée:** {result.duration_seconds:.2f}s",
        f"**Stacks détectées:** {', '.join(result.stacks_scanned) if result.stacks_scanned else 'Aucune'}",
        "",
        "## 📊 Résumé Exécutif",
        "",
        f"![Critique](https://img.shields.io/badge/Critique-{stats.get(Severity.CRITICAL.value, 0)}-ef4444?style=flat-square) "
        f"![Élevé](https://img.shields.io/badge/Élevé-{stats.get(Severity.HIGH.value, 0)}-f59e0b?style=flat-square) "
        f"![Moyen](https://img.shields.io/badge/Moyen-{stats.get(Severity.MEDIUM.value, 0)}-3b82f6?style=flat-square) "
        f"![Faible](https://img.shields.io/badge/Faible-{stats.get(Severity.LOW.value, 0)}-8892a4?style=flat-square) "
        f"![Info](https://img.shields.io/badge/Info-{stats.get(Severity.INFO.value, 0)}-6366f1?style=flat-square)",
        "",
        f"**Total Vulnérabilités:** {result.total}",
        "",
        "## 📋 Détails des Vulnérabilités par Module",
        ""
    ]

    # Grouper par scanner
    by_scanner = defaultdict(list)
    for f in result.findings:
        by_scanner[f.scanner].append(f)

    if not result.findings:
        md.append("![Sécurisé](https://img.shields.io/badge/Statut-Sécurisé_✅-10b981?style=for-the-badge)")
        md.append("")
        md.append("**Aucune vulnérabilité détectée ! Bon travail.**")

    for scanner, findings in by_scanner.items():
        md.append(f"### <img src='https://raw.githubusercontent.com/FortAwesome/Font-Awesome/master/svgs/solid/magnifying-glass.svg' width='20' align='center'/> Module: {scanner}")
        md.append("")
        
        # Table Header
        md.append("| Sévérité | Règle/CVE | Titre | Fichier | Ligne |")
        md.append("|---|---|---|---|---|")
        
        # Sort by severity
        sorted_findings = sorted(findings, key=lambda x: {"critical":0, "high":1, "medium":2, "low":3, "info":4}.get(x.severity.value, 5))
        
        # Badges SVG pour le tableau
        badge_map = {
            "critical": "![CRIT](https://img.shields.io/badge/-CRITIQUE-ef4444?style=flat-square)",
            "high":     "![HIGH](https://img.shields.io/badge/-ÉLEVÉ-f59e0b?style=flat-square)",
            "medium":   "![MED](https://img.shields.io/badge/-MOYEN-3b82f6?style=flat-square)",
            "low":      "![LOW](https://img.shields.io/badge/-FAIBLE-8892a4?style=flat-square)",
            "info":     "![INFO](https://img.shields.io/badge/-INFO-6366f1?style=flat-square)",
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
