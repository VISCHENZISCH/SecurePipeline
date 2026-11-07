"""Actions shared by the commands and the interactive menu.

Heavy modules are imported inside functions to keep `--help` and the menu fast.
"""

from pathlib import Path

from securepipeline import __author__, __repository__, __version__
from securepipeline.core.config import Config
from securepipeline.core.detector import detect_stacks
from securepipeline.core.models import CheckResult, CheckStatus, ScanResult
from securepipeline.tools.catalog import tool_descriptions
from securepipeline.ui.console import (
    plural,
    print_command,
    print_field,
    print_section,
    print_status,
)
from securepipeline.ui.results import print_findings, print_stacks, print_verdict
from securepipeline.ui.theme import (
    BLUE,
    BOLD,
    CHECK,
    CROSS,
    CYAN,
    DOT,
    GRAY,
    GREEN,
    RED,
    RESET,
    WHITE,
)
from securepipeline.utils.process import check_tool, run_command

DISPLAY_LIMIT = 20


class ReportError(Exception):
    """The report could not be written."""


def _check_display(check: CheckResult) -> tuple[str, str]:
    from securepipeline.ui import task_panel as panel

    if check.status == CheckStatus.ERROR:
        return panel.FAILED, check.detail
    if check.status == CheckStatus.SKIPPED:
        return panel.WARNING, check.detail
    if check.status == CheckStatus.NOTHING:
        return panel.NEUTRAL, check.detail
    if check.findings:
        return panel.FOUND, plural(check.findings, "finding")
    return panel.OK, "no findings"


def run_full_scan(
    config: Config,
    quiet: bool = False,
    show_all: bool = False,
    allow_incomplete: bool = False,
) -> ScanResult:
    """Run the scan, show its progress and write the reports.

    Raises:
        ReportError: the report directory is not writable.
    """
    from securepipeline.core.orchestrator import planned_tools, run_scan
    from securepipeline.ui.task_panel import TaskPanel

    root = config.project_root
    stacks = detect_stacks(root)

    if not quiet:
        print()
        print(f"  {BOLD}{WHITE}SecurePipeline{RESET} {GRAY}{DOT} v{__version__}{RESET}\n")
        print_field("Project", f"{CYAN}{root}{RESET}")
        print_stacks(stacks)
        print_field("Fail on", f"{config.fail_on} {GRAY}{DOT} {plural(config.jobs, 'tool')} in parallel{RESET}")
        print()

    with TaskPanel("Scan", planned_tools(stacks), quiet=quiet) as panel:
        def on_done(check: CheckResult) -> None:
            state, note = _check_display(check)
            panel.finish(check.tool, state, note, check.duration)

        result = run_scan(root, stacks, jobs=config.jobs, on_start=panel.start, on_done=on_done)

    reports = write_reports(result, config)

    if not quiet:
        print_findings(result.findings, limit=None if show_all else DISPLAY_LIMIT)
    print_verdict(result, config.fail_on, allow_incomplete, reports, tool_descriptions())
    return result


def write_reports(result: ScanResult, config: Config) -> list[Path]:
    """Write the requested reports and return their paths."""
    from securepipeline.reports.html_report import generate_html
    from securepipeline.reports.markdown_report import generate_markdown
    from securepipeline.reports.storage import (
        HTML_REPORT,
        MARKDOWN_REPORT,
        save_json_report,
        save_report,
    )

    out_dir = config.report_path
    project_name = config.project_root.name
    reports: list[Path] = []
    try:
        save_json_report(result, out_dir)
        if config.output_format in ("md", "both"):
            reports.append(save_report(generate_markdown(result, project_name), out_dir, MARKDOWN_REPORT))
        if config.output_format in ("html", "both"):
            reports.append(save_report(generate_html(result, project_name), out_dir, HTML_REPORT))
    except OSError as e:
        raise ReportError(f"Cannot write reports to {out_dir}: {e}") from e
    return reports


def print_tools_status() -> list[str]:
    """Print the state of every tool and return those that can be installed."""
    from securepipeline.scanners import all_scanners

    installable = tool_descriptions()
    used_by: dict[str, list[str]] = {}
    for scanner in all_scanners():
        for tool in scanner.tools_required:
            used_by.setdefault(tool, []).append(scanner.info().name)

    print_section("Security tools")
    width = max(len(tool) for tool in used_by)
    missing: list[str] = []
    manual: list[str] = []
    for tool, modules in sorted(used_by.items()):
        symbol = f"{GREEN}{CHECK}" if check_tool(tool) else f"{RED}{CROSS}"
        print(f"  {symbol}{RESET} {WHITE}{tool:<{width}}{RESET}  {GRAY}{', '.join(modules)}{RESET}")
        if not check_tool(tool):
            (missing if tool in installable else manual).append(tool)
    print()

    if manual:
        print_status(f"Install these yourself if the stack applies to you: {', '.join(manual)}", "info")
    if not missing:
        print_status("All installable tools are present.", "success")
    return missing


def install_missing(names: list[str], bin_dir: Path | None = None) -> bool:
    """Install tools with live progress; return True if all of them succeeded."""
    from securepipeline.tools.installer import install_tools
    from securepipeline.ui.task_panel import FAILED, OK, TaskPanel

    print()
    with TaskPanel("Install", names) as panel:
        results = install_tools(
            names,
            bin_dir=bin_dir,
            on_start=panel.start,
            on_done=lambda name, ok, error: panel.finish(name, OK if ok else FAILED, "installed" if ok else error),
        )
    print()

    failed = [name for name, ok in results.items() if not ok]
    if failed:
        print_status(f"Failed: {', '.join(failed)}", "error")
    else:
        print_status(f"{plural(len(results), 'tool')} installed.", "success")
    return not failed


def print_modules() -> None:
    from securepipeline.scanners import all_scanners

    print_section("Scan modules")
    for scanner in all_scanners():
        info = scanner.info()
        print(f"  {BLUE}{BOLD}{info.name}{RESET}  {GRAY}{', '.join(scanner.tools_required)}{RESET}")
        print(f"  {WHITE}{info.description}{RESET}\n")


def print_help_screen() -> None:
    print_section("Help")
    print_field("Version", __version__, width=14)
    print_field("Author", __author__, width=14)
    print_field("Repository", __repository__, width=14)
    print_field("Documentation", "docs/USAGE.md, docs/INSTALL.md, docs/DEVSECOPS.md", width=14)

    print(f"\n  {BLUE}{BOLD}Commands{RESET}")
    print_command("securepipeline", "interactive menu")
    print_command("securepipeline scan [PATH]", "non-interactive scan")
    print_command("securepipeline detect [PATH]", "detected stacks and planned tools")
    print_command("securepipeline tools check", "tool status")
    print_command("securepipeline tools install", "verified installation")
    print_command("securepipeline modules", "available modules")

    print(f"\n  {BLUE}{BOLD}CI/CD{RESET}")
    print_command("securepipeline scan . --fail-on critical", "block on critical findings")
    print_command("securepipeline scan . --format both", "Markdown and HTML reports")
    print_command("securepipeline scan . --quiet", "verdict only in the logs")
    print_command("securepipeline scan . --allow-incomplete", "tolerate a missing tool")
    print(f"    {GRAY}GitHub Actions example: .github/workflows/securepipeline.yml{RESET}")

    print(f"\n  {BLUE}{BOLD}Scan exit codes{RESET}")
    print_field("0", "no finding at the threshold, complete scan", width=2)
    print_field("1", "at least one finding at the threshold", width=2)
    print_field("2", "incomplete scan or error", width=2)


def update_installation() -> None:
    """Update the installation repository, whatever the current directory is."""
    repo = Path(__file__).resolve().parents[2]
    if not (repo / ".git").exists():
        print_status("Not a Git installation: update with pip.", "warning")
        return
    print_status(f"Updating {repo}", "info")
    result = run_command(["git", "-C", str(repo), "pull", "--ff-only"], timeout=120)
    if result.success:
        output = result.stdout.strip()
        print_status(output.splitlines()[-1] if output else "Up to date.", "success")
    else:
        print_status(result.stderr.strip() or "Update failed.", "error")
