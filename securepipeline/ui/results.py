"""Rendering of scan results."""

from collections.abc import Collection

from securepipeline.core.models import TOOL_NOT_INSTALLED, Finding, ScanResult, Severity
from securepipeline.ui.console import (
    display_path,
    plural,
    print_field,
    print_section,
    term_width,
    truncate,
    truncate_left,
)
from securepipeline.ui.theme import (
    ARROW,
    BOLD,
    CHECK,
    CROSS,
    CYAN,
    DOT,
    GRAY,
    GREEN,
    RED,
    RESET,
    SEVERITY_COLORS,
    WARN,
    WHITE,
    YELLOW,
)

LABEL_WIDTH = 9


def severity_counts_line(result: ScanResult) -> str:
    """Summarize the severities on one line, leaving out those at zero."""
    parts = [
        f"{SEVERITY_COLORS[severity]}{BOLD}{count}{RESET} {severity.value}"
        for severity, count in result.severity_counts().items()
        if count
    ]
    return f"  {GRAY}{DOT}{RESET}  ".join(parts)


def print_findings(findings: list[Finding], limit: int | None = None) -> None:
    """Print findings from most to least severe, fitted to the terminal width."""
    if not findings:
        return

    print_section(f"Findings ({len(findings)})")
    width = term_width() - LABEL_WIDTH - 4
    ordered = sorted(findings, key=lambda f: list(Severity).index(f.severity))
    shown = ordered if limit is None else ordered[:limit]

    for finding in shown:
        color = SEVERITY_COLORS[finding.severity]
        label = finding.severity.label
        print(f"  {color}{BOLD}{label:<{LABEL_WIDTH}}{RESET} {WHITE}{truncate(finding.title, width)}{RESET}")
        meta = f"{finding.rule_id} {DOT} {finding.scanner}"
        if finding.location:
            meta = f"{truncate_left(finding.location, max(width - len(meta) - 3, 20))} {DOT} {meta}"
        print(f"  {' ' * LABEL_WIDTH} {GRAY}{truncate(meta, width)}{RESET}")

    hidden = len(ordered) - len(shown)
    if hidden:
        print(f"\n  {GRAY}… and {hidden} more in the report (--all prints them here).{RESET}")


def print_verdict(
    result: ScanResult,
    fail_on: str,
    allow_incomplete: bool = False,
    reports: list | None = None,
    installable: Collection[str] = (),
) -> None:
    """End the scan with a clear verdict and the possible next steps."""
    code = result.exit_code(fail_on, allow_incomplete)
    print()

    if code == 1:
        blocking = plural(len(result.blocking_findings(fail_on)), "finding")
        print(f"  {RED}{BOLD}{CROSS} FAILED{RESET}  {blocking} at or above \"{fail_on}\"")
    elif not result.is_complete:
        print(f"  {YELLOW}{BOLD}{WARN} INCOMPLETE{RESET}  the result does not cover the whole project")
    elif result.total:
        print(f"  {GREEN}{BOLD}{CHECK} PASSED{RESET}  nothing at or above \"{fail_on}\"")
    else:
        print(f"  {GREEN}{BOLD}{CHECK} PASSED{RESET}  no findings")

    if result.total:
        print(f"  {severity_counts_line(result)}")

    _print_incomplete(result, installable)

    print()
    print_field("Duration", f"{result.duration_seconds:.1f}s")
    for report in reports or []:
        print_field("Report", f"{CYAN}{display_path(report)}{RESET}")


def _print_incomplete(result: ScanResult, installable: Collection[str]) -> None:
    checks = result.incomplete_checks
    if not checks:
        return
    print()
    for check in checks:
        print(f"  {YELLOW}{WARN}{RESET} {WHITE}{check.tool}{RESET} {GRAY}{check.detail}{RESET}")
    if any(c.tool in installable and c.detail == TOOL_NOT_INSTALLED for c in checks):
        print(f"  {GRAY}{ARROW} To install them: {RESET}{GREEN}securepipeline tools install{RESET}")


def print_stacks(stacks: list[str]) -> None:
    if stacks:
        print_field("Stacks", f" {DOT} ".join(f"{WHITE}{stack}{RESET}" for stack in stacks))
    else:
        print_field("Stacks", f"{GRAY}none recognized, secret detection only{RESET}")
