"""SecurePipeline - Generateur de rapports HTML autonome."""

from collections import defaultdict
from datetime import datetime
from pathlib import Path

from securepipeline.core.models import ScanResult, Severity
from securepipeline import __version__

# html_report.py::Template CSS Dark Theme-------------------------------------------#

_CSS = """
:root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-card: #1c2128;
    --bg-hover: #21262d;
    --border: #30363d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --text-muted: #484f58;
    --accent-cyan: #00e6e6;
    --accent-green: #30d158;
    --accent-blue: #58a6ff;
    --sev-critical: #ff453a;
    --sev-critical-bg: #3d1114;
    --sev-high: #ff9f0a;
    --sev-high-bg: #3d2e0a;
    --sev-medium: #ffd60a;
    --sev-medium-bg: #3d370f;
    --sev-low: #64a0ff;
    --sev-low-bg: #192332;
    --sev-info: #30d158;
    --sev-info-bg: #0f2819;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: 'JetBrains Mono', 'Fira Code', 'SF Mono', Consolas, monospace;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2rem;
}

.container { max-width: 1100px; margin: 0 auto; }

/* Header */
.header {
    text-align: center;
    padding: 2rem 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
}
.header h1 {
    font-size: 1.8rem;
    color: var(--accent-cyan);
    letter-spacing: 2px;
    margin-bottom: 0.5rem;
}
.header .meta {
    color: var(--text-secondary);
    font-size: 0.85rem;
}
.header .meta span { margin: 0 1rem; }

/* Summary Cards */
.summary-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 1rem;
    margin-bottom: 2rem;
}
.summary-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem;
    text-align: center;
    transition: transform 0.2s;
}
.summary-card:hover { transform: translateY(-2px); }
.summary-card .count {
    font-size: 2rem;
    font-weight: 700;
    display: block;
    margin-bottom: 0.3rem;
}
.summary-card .label {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-secondary);
}
.card-critical .count { color: var(--sev-critical); }
.card-high .count { color: var(--sev-high); }
.card-medium .count { color: var(--sev-medium); }
.card-low .count { color: var(--sev-low); }
.card-info .count { color: var(--sev-info); }

/* Severity Bars */
.severity-bars { margin-bottom: 2rem; }
.sev-bar-row {
    display: flex;
    align-items: center;
    margin-bottom: 0.4rem;
}
.sev-bar-label {
    width: 80px;
    font-size: 0.75rem;
    text-transform: uppercase;
    color: var(--text-secondary);
}
.sev-bar-track {
    flex: 1;
    height: 8px;
    background: var(--bg-hover);
    overflow: hidden;
    margin: 0 0.8rem;
}
.sev-bar-fill {
    height: 100%;
    transition: width 0.8s ease-out;
}
.sev-bar-count {
    width: 30px;
    text-align: right;
    font-size: 0.85rem;
}

/* Sections */
.section {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 1.5rem;
    overflow: hidden;
}
.section-header {
    background: var(--bg-secondary);
    padding: 0.8rem 1.2rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
}
.section-header h2 {
    font-size: 1rem;
    color: var(--accent-cyan);
}
.section-header .badge {
    font-size: 0.75rem;
    padding: 0.2rem 0.6rem;
    border-radius: 12px;
    font-weight: 600;
}

/* Table */
table {
    width: 100%;
    border-collapse: collapse;
}
th {
    background: var(--bg-hover);
    padding: 0.6rem 1rem;
    text-align: left;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
}
td {
    padding: 0.6rem 1rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.85rem;
}
tr:hover { background: var(--bg-hover); }
.sev-badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
}
.sev-critical { background: var(--sev-critical-bg); color: var(--sev-critical); }
.sev-high { background: var(--sev-high-bg); color: var(--sev-high); }
.sev-medium { background: var(--sev-medium-bg); color: var(--sev-medium); }
.sev-low { background: var(--sev-low-bg); color: var(--sev-low); }
.sev-info { background: var(--sev-info-bg); color: var(--sev-info); }

/* Details */
details { margin: 0.5rem 1rem; }
details summary {
    cursor: pointer;
    color: var(--accent-blue);
    font-size: 0.85rem;
    padding: 0.3rem 0;
}
details .detail-content {
    padding: 0.5rem 1rem;
    background: var(--bg-secondary);
    border-radius: 4px;
    margin-top: 0.3rem;
    font-size: 0.8rem;
    color: var(--text-secondary);
}

/* Footer */
.footer {
    text-align: center;
    padding: 2rem 0;
    color: var(--text-muted);
    font-size: 0.75rem;
    border-top: 1px solid var(--border);
    margin-top: 2rem;
}

/* Status Banner */
.status-banner {
    padding: 1rem 1.5rem;
    border-radius: 8px;
    margin-bottom: 2rem;
    font-weight: 600;
    text-align: center;
}
.status-clean {
    background: var(--sev-info-bg);
    color: var(--sev-info);
    border: 1px solid var(--sev-info);
}
.status-warning {
    background: var(--sev-high-bg);
    color: var(--sev-high);
    border: 1px solid var(--sev-high);
}
.status-critical {
    background: var(--sev-critical-bg);
    color: var(--sev-critical);
    border: 1px solid var(--sev-critical);
}
"""


# html_report.py::Generateur HTML-----------------------------------------

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_FR = {
    "critical": "Critique",
    "high":     "Élevé",
    "medium":   "Moyen",
    "low":      "Faible",
    "info":     "Info",
}


def generate_html(result: ScanResult, path: str, project_name: str = "Projet") -> str:
    """rapport HTML autonome (single-file) avec CSS intégré.

    Args:
        result: Résultat du scan.
        path: Chemin du projet scanne.
        project_name: Nom du projet.

    Returns:
        Contenu HTML complet.
    """
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Stats
    stats: dict[str, int] = defaultdict(int)
    for f in result.findings:
        stats[f.severity.value] += 1

    # Status banner
    if result.total == 0:
        status_class = "status-clean"
        status_text = "Aucune vulnerabilite detectee"
    elif stats.get("critical", 0) > 0:
        status_class = "status-critical"
        status_text = f"{stats['critical']} vulnerabilite(s) critique(s) detectee(s)"
    else:
        status_class = "status-warning"
        status_text = f"{result.total} vulnerabilite(s) detectee(s)"

    # Summary cards
    cards_html = ""
    for sev in _SEV_ORDER:
        count = stats.get(sev, 0)
        cards_html += f"""
        <div class="summary-card card-{sev}">
            <span class="count">{count}</span>
            <span class="label">{_SEV_FR[sev]}</span>
        </div>"""

    # Severity bars
    max_count = max(stats.values()) if stats else 1
    bars_html = ""
    sev_colors = {
        "critical": "var(--sev-critical)",
        "high":     "var(--sev-high)",
        "medium":   "var(--sev-medium)",
        "low":      "var(--sev-low)",
        "info":     "var(--sev-info)",
    }
    for sev in _SEV_ORDER:
        count = stats.get(sev, 0)
        pct = (count / max(max_count, 1)) * 100
        bars_html += f"""
        <div class="sev-bar-row">
            <span class="sev-bar-label">{_SEV_FR[sev]}</span>
            <div class="sev-bar-track">
                <div class="sev-bar-fill" style="width:{pct:.0f}%;background:{sev_colors[sev]}"></div>
            </div>
            <span class="sev-bar-count" style="color:{sev_colors[sev]}">{count}</span>
        </div>"""

    # Findings by scanner
    by_scanner: dict[str, list] = defaultdict(list)
    for f in result.findings:
        by_scanner[f.scanner].append(f)

    sections_html = ""
    if not result.findings:
        sections_html = """
        <div class="section">
            <div class="section-header">
                <h2>Aucune vulnerabilite</h2>
            </div>
            <div style="padding: 2rem; text-align: center; color: var(--sev-info);">
                Excellent ! Aucune vulnerabilite n'a ete detectee dans ce projet.
            </div>
        </div>"""
    else:
        for scanner, findings in by_scanner.items():
            badge_class = "sev-high" if any(f.severity == Severity.CRITICAL for f in findings) else "sev-medium"
            rows = ""
            for f in sorted(findings, key=lambda x: _SEV_ORDER.index(x.severity.value) if x.severity.value in _SEV_ORDER else 5):
                sev_class = f"sev-{f.severity.value}"
                sev_label = _SEV_FR.get(f.severity.value, f.severity.value.upper())
                file_link = f"<code>{_escape(f.file_path)}</code>" if f.file_path else "N/A"
                line_str = str(f.line) if f.line else "N/A"

                detail_parts = []
                if f.description:
                    detail_parts.append(f"<strong>Description:</strong> {_escape(f.description)}")
                if f.remediation:
                    detail_parts.append(f"<strong>Rémediation:</strong> {_escape(f.remediation)}")
                detail_html = "<br>".join(detail_parts) if detail_parts else ""

                rows += f"""
                <tr>
                    <td><span class="sev-badge {sev_class}">{sev_label}</span></td>
                    <td><code>{_escape(f.rule_id)}</code></td>
                    <td>{_escape(f.title)}</td>
                    <td>{file_link}</td>
                    <td>{line_str}</td>
                </tr>"""
                if detail_html:
                    rows += f"""
                <tr>
                    <td colspan="5">
                        <details>
                            <summary>Details & Remediation</summary>
                            <div class="detail-content">{detail_html}</div>
                        </details>
                    </td>
                </tr>"""

            sections_html += f"""
        <div class="section">
            <div class="section-header">
                <h2>{_escape(scanner)}</h2>
                <span class="badge {badge_class}">{len(findings)} finding(s)</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width:100px">Severite</th>
                        <th style="width:150px">Regle/CVE</th>
                        <th>Titre</th>
                        <th style="width:180px">Fichier</th>
                        <th style="width:60px">Ligne</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>"""

    # Assemblage final
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecurePipeline - Rapport de Securite - {_escape(project_name)}</title>
    <style>{_CSS}</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SECUREPIPELINE</h1>
            <div class="meta">
                <span>Projet: {_escape(project_name)}</span>
                <span>Date: {date_str}</span>
                <span>Duree: {result.duration_seconds:.2f}s</span>
                <span>Stacks: {', '.join(result.stacks_scanned) if result.stacks_scanned else 'Aucune'}</span>
            </div>
        </div>

        <div class="{status_class} status-banner">{status_text}</div>

        <div class="summary-grid">
            {cards_html}
        </div>

        <div class="severity-bars">
            {bars_html}
        </div>

        {sections_html}

        <div class="footer">
            SecurePipeline v{__version__} &mdash; Rapport genere le {date_str}
        </div>
    </div>
</body>
</html>"""

    return html


def save_html_report(content: str, out_dir: str, filename: str = "securepipeline-report.html") -> str:
    """Sauvegarde le rapport HTML sur le disque.

    Args:
        content: Contenu HTML.
        out_dir: Repertoire de sortie.
        filename: Nom du fichier.

    Returns:
        Chemin complet du fichier genere.
    """
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    file_path = out_path / filename

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

    return str(file_path)


def _escape(text: str) -> str:
    """Echappe les caracteres HTML."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
