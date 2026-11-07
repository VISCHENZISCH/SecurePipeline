"""Standalone HTML report: all external content is escaped."""

from datetime import datetime
from html import escape
from importlib import resources

from securepipeline import __version__
from securepipeline.core.models import SEVERITY_RANK, ScanResult, Severity
from securepipeline.reports.markdown_report import check_outcome


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


def _coverage_section(result: ScanResult) -> str:
    rows = "".join(
        f"""
                <tr>
                    <td><code>{escape(c.tool)}</code></td>
                    <td>{escape(c.module)}</td>
                    <td class="check-{c.status.value}">{escape(check_outcome(c))}</td>
                    <td>{c.duration:.1f}s</td>
                </tr>"""
        for c in result.checks
    )
    return f"""
        <div class="section">
            <div class="section-header"><h2>Scan coverage</h2></div>
            <table>
                <thead><tr><th>Tool</th><th>Module</th><th>Result</th><th>Duration</th></tr></thead>
                <tbody>{rows}
                </tbody>
            </table>
        </div>"""


def _finding_rows(findings: list) -> str:
    rows = ""
    for f in sorted(findings, key=lambda item: -SEVERITY_RANK[item.severity]):
        location = f"<code>{escape(f.location)}</code>" if f.location else "N/A"
        details = []
        if f.description:
            details.append(f"<strong>Description:</strong> {escape(f.description)}")
        if f.remediation:
            details.append(f"<strong>Remediation:</strong> {escape(f.remediation)}")
        rows += f"""
                <tr>
                    <td><span class="sev-badge sev-{f.severity.value}">{f.severity.label}</span></td>
                    <td><code>{escape(f.rule_id)}</code></td>
                    <td>{escape(f.title)}</td>
                    <td>{location}</td>
                </tr>"""
        if details:
            rows += f"""
                <tr>
                    <td colspan="4">
                        <details>
                            <summary>Details and remediation</summary>
                            <div class="detail-content">{"<br>".join(details)}</div>
                        </details>
                    </td>
                </tr>"""
    return rows


def generate_html(result: ScanResult, project_name: str = "Project") -> str:
    date_str = f"{datetime.now():%Y-%m-%d %H:%M:%S}"
    project = escape(project_name)
    counts = result.severity_counts()
    status_class, status_text = _status_banner(result, counts)

    cards = "".join(
        f"""
        <div class="summary-card card-{severity.value}">
            <span class="count">{counts[severity]}</span>
            <span class="label">{severity.value.capitalize()}</span>
        </div>"""
        for severity in Severity
    )

    largest = max(max(counts.values()), 1)
    bars = "".join(
        f"""
        <div class="sev-bar-row">
            <span class="sev-bar-label">{severity.value.capitalize()}</span>
            <div class="sev-bar-track">
                <div class="sev-bar-fill" style="width:{counts[severity] / largest * 100:.0f}%;background:var(--sev-{severity.value})"></div>
            </div>
            <span class="sev-bar-count" style="color:var(--sev-{severity.value})">{counts[severity]}</span>
        </div>"""
        for severity in Severity
    )

    by_scanner: dict[str, list] = {}
    for finding in result.findings:
        by_scanner.setdefault(finding.scanner, []).append(finding)

    sections = "".join(
        f"""
        <div class="section">
            <div class="section-header">
                <h2>{escape(scanner)}</h2>
                <span class="badge sev-{'high' if any(f.severity == Severity.CRITICAL for f in findings) else 'medium'}">{len(findings)} finding(s)</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width:100px">Severity</th>
                        <th style="width:150px">Rule/CVE</th>
                        <th>Title</th>
                        <th style="width:200px">Location</th>
                    </tr>
                </thead>
                <tbody>{_finding_rows(findings)}
                </tbody>
            </table>
        </div>"""
        for scanner, findings in by_scanner.items()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecurePipeline - {project}</title>
    <style>{_stylesheet()}</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SECUREPIPELINE</h1>
            <div class="meta">
                <span>Project: {project}</span>
                <span>Date: {date_str}</span>
                <span>Duration: {result.duration_seconds:.2f}s</span>
                <span>Stacks: {escape(", ".join(result.stacks_scanned)) or "None"}</span>
            </div>
        </div>

        <div class="{status_class} status-banner">{escape(status_text)}</div>

        <div class="summary-grid">{cards}
        </div>

        <div class="severity-bars">{bars}
        </div>
{_coverage_section(result)}
{sections}

        <div class="footer">
            SecurePipeline v{__version__} &mdash; Report generated on {date_str}
        </div>
    </div>
</body>
</html>"""
