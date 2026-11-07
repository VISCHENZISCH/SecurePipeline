"""Command definitions."""

import shutil
import sys
from pathlib import Path

import click

from securepipeline import __version__
from securepipeline.cli.actions import (
    ReportError,
    install_missing,
    print_modules,
    print_tools_status,
    run_full_scan,
)
from securepipeline.core.config import (
    DEFAULT_REPORT_DIR,
    FAIL_ON_CHOICES,
    FORMAT_ALIASES,
    FORMAT_CHOICES,
    Config,
    default_jobs,
)
from securepipeline.core.detector import detect_stacks
from securepipeline.tools.catalog import tool_descriptions
from securepipeline.ui.console import print_field, print_status
from securepipeline.ui.results import print_stacks
from securepipeline.ui.theme import ARROW, DOT, GRAY, RESET, WHITE
from securepipeline.utils.process import extend_tool_path

EXIT_INTERRUPTED = 130


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="SecurePipeline")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Multi-stack DevSecOps security scanner.

    Without a command, opens the interactive menu.
    """
    if ctx.invoked_subcommand is None:
        if sys.stdin.isatty():
            from securepipeline.cli.menu import interactive_loop

            interactive_loop()
        else:
            click.echo(ctx.get_help())


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option("--fail-on", type=click.Choice(FAIL_ON_CHOICES, case_sensitive=False), default="critical",
              envvar="SECUREPIPELINE_FAIL_ON", show_default=True, help="Severity from which the scan fails.")
@click.option("--format", "output_format", type=click.Choice((*FORMAT_CHOICES, *FORMAT_ALIASES)), default="md",
              envvar="SECUREPIPELINE_FORMAT", show_default=True, help="Report format.")
@click.option("--report-dir", default=DEFAULT_REPORT_DIR, envvar="SECUREPIPELINE_REPORT_DIR", show_default=True,
              help="Report directory (relative to the scanned project).")
@click.option("-j", "--jobs", type=click.IntRange(min=1), default=default_jobs, show_default="based on CPU",
              help="Number of tools to run in parallel.")
@click.option("--allow-incomplete", is_flag=True, help="Do not fail when a tool is missing or fails.")
@click.option("--all", "show_all", is_flag=True, help="Print all findings in the terminal.")
@click.option("-q", "--quiet", is_flag=True, help="Print the verdict only.")
def scan(path, fail_on, output_format, report_dir, jobs, allow_incomplete, show_all, quiet) -> None:
    """Scan a project without interaction (PATH defaults to the current directory).

    \b
    Exit codes:
      0  no finding at the threshold, complete scan
      1  at least one finding at the threshold
      2  incomplete scan (tool missing or failed) or error
    """
    config = Config(
        project_path=path,
        output_format=output_format,
        fail_on=fail_on.lower(),
        report_dir=report_dir,
        jobs=jobs,
    )
    try:
        result = run_full_scan(config, quiet=quiet, show_all=show_all, allow_incomplete=allow_incomplete)
    except KeyboardInterrupt:
        print()
        print_status("Scan interrupted.", "warning")
        sys.exit(EXIT_INTERRUPTED)
    except ReportError as e:
        print_status(str(e), "error")
        sys.exit(2)
    sys.exit(result.exit_code(config.fail_on, allow_incomplete))


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False))
def detect(path) -> None:
    """Show the detected stacks and planned tools, without scanning."""
    from securepipeline.core.orchestrator import planned_tools

    stacks = detect_stacks(path)
    print()
    print_stacks(stacks)
    print_field("Tools", ", ".join(planned_tools(stacks)))


@cli.command()
def modules() -> None:
    """List the scan modules."""
    print_modules()


@cli.group()
def tools() -> None:
    """Check and install the security tools."""


@tools.command("check")
def tools_check() -> None:
    """Show tool status (exit code 1 if an installable tool is missing)."""
    missing = print_tools_status()
    if missing:
        print_status(f"{ARROW} To install them: securepipeline tools install", "warning")
        sys.exit(1)


@tools.command("install")
@click.argument("names", nargs=-1)
@click.option("--bin-dir", type=click.Path(file_okay=False, path_type=Path),
              help="Binary directory (default: active venv, otherwise ~/.local/bin).")
@click.option("-y", "--yes", is_flag=True, help="Do not ask for confirmation.")
def tools_install(names, bin_dir, yes) -> None:
    """Install the missing tools, or the named ones (binaries are SHA-256 verified)."""
    from securepipeline.tools.installer import get_missing_tools

    catalog = tool_descriptions()
    unknown = [name for name in names if name not in catalog]
    if unknown:
        raise click.BadParameter(f"unknown tool: {', '.join(unknown)}. Choices: {', '.join(catalog)}")

    targets = list(names) or get_missing_tools()
    if not targets:
        print_status("All tools are already installed.", "success")
        return

    if not yes:
        print()
        for name in targets:
            print(f"  {GRAY}{DOT}{RESET} {WHITE}{name}{RESET}  {GRAY}{catalog[name]}{RESET}")
        print()
        click.confirm("  Install these tools?", abort=True)

    if not install_missing(targets, bin_dir):
        sys.exit(1)
    if bin_dir and shutil.which(targets[-1]) is None:
        print_status(f"Add {bin_dir} to your PATH.", "warning")


def main() -> None:
    # A non-UTF-8 terminal must not crash on the symbols.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    extend_tool_path()
    cli()
