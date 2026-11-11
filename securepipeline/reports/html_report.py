"""Standalone HTML report: all external content is escaped."""

from datetime import datetime
from html import escape
from importlib import resources

from securepipeline import __version__
from securepipeline.core.models import SEVERITY_RANK, ScanResult, Severity
from securepipeline.reports.markdown_report import check_outcome

FONTS_URL = (
    "https://fonts.googleapis.com/css2?family=Red+Hat+Display:wght@500;700"
    "&family=Red+Hat+Mono:wght@400;500&family=Red+Hat+Text:wght@400;600;700&display=swap"
)

# Open every "Details" block before printing so remediation text is on paper.
PRINT_SCRIPT = (
    'addEventListener("beforeprint",()=>document.querySelectorAll("details")'
    ".forEach(d=>d.open=true));"
)


def _stylesheet() -> str:
    return resources.files("securepipeline.reports").joinpath("assets/report.css").read_text(encoding="utf-8")


def _status_banner(result: ScanResult, counts: dict[Severity, int]) -> tuple[str, str]:
    if counts[Severity.CRITICAL]:
        return "status-critical", f"{counts[Severity.CRITICAL]} critical finding(s)"
    if not result.is_complete:
        names = ", ".join(check.tool for check in result.incomplete_checks)
        return "status-warning", f"Incomplete scan: no results from {names}"
    if result.total:
        return "status-warning", f"{result.total} finding(s)"
    return "status-clean", "No findings"


def _summary_text(result: ScanResult, counts: dict[Severity, int]) -> str:
    tools = len(result.checks)
    failed = len(result.incomplete_checks)
    parts = [f"{tools} tool(s) ran in {result.duration_seconds:.1f}s."]
    if result.total:
        worst = next(s for s in Severity if counts[s])
        parts.append(f"{result.total} finding(s), the most severe rated {worst.value}.")
    if failed:
        parts.append(f"{failed} tool(s) returned no result, so this scan cannot be read as clean.")
    return " ".join(parts)


def _severity_chapter(counts: dict[Severity, int]) -> str:
    largest = max(max(counts.values()), 1)
    rows = "".join(
        f"""
                <tr>
                    <td><span class="badge sev-{s.value}">{s.value.capitalize()}</span></td>
                    <td class="num">{counts[s]}</td>
                    <td style="width:60%"><div class="bar"><span class="fill-{s.value}" style="width:{counts[s] / largest * 100:.0f}%"></span></div></td>
                </tr>"""
        for s in Severity
    )
    return f"""
        <section class="chapter">
            <p class="overline">Chapter 1</p>
            <h2>Findings by severity</h2>
            <p class="lede">Count of findings across all tools, from critical down to informational.</p>
            <div class="table-wrap"><table>
                <thead><tr><th>Severity</th><th class="num">Findings</th><th>Share</th></tr></thead>
                <tbody>{rows}
                </tbody>
            </table></div>
        </section>"""


def _coverage_chapter(result: ScanResult) -> str:
    rows = "".join(
        f"""
                <tr>
                    <td><code>{escape(c.tool)}</code></td>
                    <td>{escape(c.module)}</td>
                    <td><span class="badge check-{c.status.value}">{escape(c.status.value)}</span>
                        <span class="outcome">{escape(check_outcome(c))}</span></td>
                    <td class="num">{c.duration:.1f}s</td>
                </tr>"""
        for c in result.checks
    )
    body = (
        f"""<div class="table-wrap"><table>
                <thead><tr><th>Tool</th><th>Module</th><th>Result</th><th class="num">Duration</th></tr></thead>
                <tbody>{rows}
                </tbody>
            </table></div>"""
        if result.checks
        else '<p class="empty">No tool ran.</p>'
    )
    return f"""
        <section class="chapter">
            <p class="overline">Chapter 2</p>
            <h2>Scan coverage</h2>
            <p class="lede">Each tool that ran and what it returned. A skipped or failed tool means part of the code was not checked.</p>
            {body}
        </section>"""


def _finding_rows(findings: list) -> str:
    rows = ""
    for f in sorted(findings, key=lambda item: -SEVERITY_RANK[item.severity]):
        location = f"<code>{escape(f.location)}</code>" if f.location else "N/A"
        details = []
        if f.description:
            details.append(f"<p><strong>Description:</strong> {escape(f.description)}</p>")
        if f.remediation:
            details.append(f"<p><strong>Remediation:</strong> {escape(f.remediation)}</p>")
        row_class = ' class="has-detail"' if details else ""
        rows += f"""
                <tr{row_class}>
                    <td><span class="badge sev-{f.severity.value}">{f.severity.value.capitalize()}</span></td>
                    <td><code>{escape(f.rule_id)}</code></td>
                    <td>{escape(f.title)}</td>
                    <td>{location}</td>
                </tr>"""
        if details:
            rows += f"""
                <tr class="detail-row">
                    <td colspan="4">
                        <details>
                            <summary>Details and remediation</summary>
                            <div class="detail-content">{"".join(details)}</div>
                        </details>
                    </td>
                </tr>"""
    return rows


def _findings_chapter(result: ScanResult) -> str:
    by_scanner: dict[str, list] = {}
    for finding in result.findings:
        by_scanner.setdefault(finding.scanner or "Other", []).append(finding)

    sections = "".join(
        f"""
            <h3>3.{index} {escape(scanner)} <span class="count">{len(findings)} finding(s)</span></h3>
            <div class="table-wrap"><table>
                <thead><tr><th style="width:96px">Severity</th><th style="width:22%">Rule or CVE</th><th>Title</th><th style="width:26%">Location</th></tr></thead>
                <tbody>{_finding_rows(findings)}
                </tbody>
            </table></div>"""
        for index, (scanner, findings) in enumerate(by_scanner.items(), start=1)
    )
    return f"""
        <section class="chapter">
            <p class="overline">Chapter 3</p>
            <h2>Findings</h2>
            <p class="lede">Findings grouped by scanner, most severe first. Open a row's details for the description and the fix.</p>
            {sections or '<p class="empty">Nothing to list.</p>'}
        </section>"""


def generate_html(result: ScanResult, project_name: str = "Project") -> str:
    now = datetime.now()
    date_str = f"{now:%Y-%m-%d %H:%M}"
    project = escape(project_name)
    counts = result.severity_counts()
    status_class, status_text = _status_banner(result, counts)
    stacks = "".join(f'<span class="pill">{escape(s)}</span>' for s in result.stacks_scanned)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecurePipeline - {project}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="stylesheet" href="{FONTS_URL}">
    <style>{_stylesheet()}</style>
</head>
<body>
    <main class="page">
        <header class="doc-header">
            <div class="brand"><span class="mark" aria-hidden="true">SP</span><strong>SecurePipeline</strong><span>Security scan report</span></div>
            <div>{project} &middot; {date_str}</div>
        </header>

        <section class="cover">
            <p class="overline">Security scan report</p>
            <h1>{project}</h1>
            <p class="subtitle">Static analysis, dependency audit, infrastructure checks and secret detection, run by SecurePipeline.</p>
            <div class="pills">{stacks or '<span class="pill">No stack detected</span>'}</div>

            <dl class="meta">
                <div><dt>Project</dt><dd>{project}</dd></div>
                <div><dt>Date</dt><dd>{date_str}</dd></div>
                <div><dt>Duration</dt><dd>{result.duration_seconds:.2f}s</dd></div>
                <div><dt>Version</dt><dd>SecurePipeline {__version__}</dd></div>
            </dl>

            <div class="summary">
                <h2>Summary</h2>
                <div class="status {status_class}">{escape(status_text)}</div>
                <p>{escape(_summary_text(result, counts))}</p>
            </div>
        </section>
{_severity_chapter(counts)}
{_coverage_chapter(result)}
{_findings_chapter(result)}

        <footer class="doc-footer">
            <span>SecurePipeline {__version__} &middot; {project}</span>
            <span>Generated on {date_str}</span>
        </footer>
    </main>
    <script>{PRINT_SCRIPT}</script>
</body>
</html>"""
