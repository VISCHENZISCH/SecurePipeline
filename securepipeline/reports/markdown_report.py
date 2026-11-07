"""Markdown report."""

from datetime import datetime

from securepipeline.core.models import (
    SEVERITY_RANK,
    CheckResult,
    CheckStatus,
    ScanResult,
    Severity,
)

CHECK_LABELS = {
    CheckStatus.OK: "OK",
    CheckStatus.NOTHING: "Nothing to scan",
    CheckStatus.SKIPPED: "Skipped",
    CheckStatus.ERROR: "Error",
}


def check_outcome(check: CheckResult) -> str:
    label = CHECK_LABELS[check.status]
    if check.detail:
        return f"{label}: {check.detail}"
    if check.status == CheckStatus.OK:
        return f"{label} ({check.findings} finding(s))"
    return label


def _cell(text: object) -> str:
    """Neutralize external text so it cannot break the table or inject HTML."""
    return (
        " ".join(str(text).split())
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _code(text: object) -> str:
    return f"`{_cell(text).replace('`', chr(39))}`"


def generate_markdown(result: ScanResult, project_name: str = "Project") -> str:
    counts = result.severity_counts()
    md = [
        f"# DevSecOps security report - {_cell(project_name)}",
        "",
        f"**Scan date:** {datetime.now():%Y-%m-%d %H:%M:%S}  ",
        f"**Duration:** {result.duration_seconds:.2f}s  ",
        f"**Detected stacks:** {', '.join(result.stacks_scanned) or 'None'}",
        "",
        "## Summary",
        "",
        *(f"- {severity.value.capitalize()}: {counts[severity]}" for severity in Severity),
        "",
        f"**Total:** {result.total} finding(s)",
        "",
    ]

    if not result.is_complete:
        names = ", ".join(check.tool for check in result.incomplete_checks)
        md += [
            f"> **Incomplete scan.** These tools returned no results: {_cell(names)}.",
            "> The absence of findings does not prove that the project is healthy.",
            "",
        ]

    md += ["## Scan coverage", "", "| Tool | Module | Result | Duration |", "|---|---|---|---|"]
    md += [
        f"| {_cell(c.tool)} | {_cell(c.module)} | {_cell(check_outcome(c))} | {c.duration:.1f}s |"
        for c in result.checks
    ]
    md += ["", "## Details by tool", ""]

    if not result.findings:
        md.append("No findings from the tools that ran.")

    by_scanner: dict[str, list] = {}
    for finding in result.findings:
        by_scanner.setdefault(finding.scanner, []).append(finding)

    for scanner, findings in by_scanner.items():
        ordered = sorted(findings, key=lambda f: -SEVERITY_RANK[f.severity])
        md += [
            f"### {_cell(scanner)}",
            "",
            "| Severity | Rule/CVE | Title | Location |",
            "|---|---|---|---|",
        ]
        md += [
            f"| {f.severity.label} | {_code(f.rule_id)} | {_cell(f.title)} "
            f"| {_code(f.location) if f.location else 'N/A'} |"
            for f in ordered
        ]
        md += ["", "<details><summary><b>Details and remediation</b></summary>", ""]
        for finding in ordered:
            md.append(f"#### {_cell(finding.title)} ({_code(finding.rule_id)})")
            if finding.description:
                md.append(f"**Description:** {_cell(finding.description)}  ")
            if finding.remediation:
                md.append(f"**Remediation:** {_cell(finding.remediation)}")
            md.append("")
        md += ["</details>", ""]

    return "\n".join(md)
