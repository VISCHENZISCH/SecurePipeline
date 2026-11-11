"""Interactive menu."""

import shlex
import subprocess  # nosec B404 - runs the user's own ! commands, without a shell
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from securepipeline.cli.actions import (
    ReportError,
    install_missing,
    print_help_screen,
    print_modules,
    print_tools_status,
    run_full_scan,
    update_installation,
)
from securepipeline.core.config import FAIL_ON_CHOICES, FORMAT_CHOICES, Config
from securepipeline.core.detector import detect_stacks
from securepipeline.ui.console import (
    AlternateScreen,
    clear_screen,
    format_age,
    home_path,
    print_field,
    print_section,
    print_status,
)
from securepipeline.ui.menu_view import MENU_MIN_HEIGHT, get_prompt, print_header, print_menu
from securepipeline.ui.results import print_findings, print_verdict, severity_counts_line
from securepipeline.ui.theme import CYAN, DOT, GRAY, GREEN, RESET, WHITE, YELLOW

QUIT_WORDS = ("q", "0", "quit", "exit")


@dataclass(frozen=True)
class MenuItem:
    key: str
    label: str
    handler: Callable[[Config], None]
    pause: bool = True
    prepare: Callable[[Config], bool] | None = None


def _ask(prompt: str) -> str | None:
    """Read an answer; return None on Ctrl-C or end of input."""
    try:
        return input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def _pause() -> None:
    _ask(f"\n{GRAY}Press Enter to return to the menu{RESET} ")


def _confirm(question: str) -> bool:
    """Only an explicit yes counts."""
    answer = _ask(f"  {CYAN}{question}{RESET} {GRAY}[y/N]{RESET} ")
    return bool(answer) and answer.lower() in ("y", "yes")


def _scan(config: Config) -> None:
    try:
        run_full_scan(config)
    except KeyboardInterrupt:
        print()
        print_status("Scan interrupted.", "warning")
    except ReportError as e:
        print_status(str(e), "error")


def _parse_path(answer: str) -> Path:
    """Accept a path as a shell would write it: quoted or with escaped spaces."""
    return Path(answer.strip("'\"").replace("\\ ", " ")).expanduser()


def _choose_project(config: Config) -> bool:
    """Ask for the project to scan; return False if there is nothing to scan."""
    answer = _ask(f"{get_prompt('~/project')}{GRAY}project path to scan:{RESET} ")
    if not answer:
        return False
    path = _parse_path(answer)
    if not path.is_dir():
        print_status(f"Directory not found: {path}", "error")
        _pause()
        return False
    config.project_path = str(path)
    return True


def _last_results(config: Config) -> None:
    from securepipeline.reports.storage import load_json_report

    result = load_json_report(config.report_path)
    if result is None:
        print_status("No results for this project yet: run a scan first.", "warning")
        return
    print_findings(result.findings)
    print_verdict(result, config.fail_on)


def _export_html(config: Config) -> None:
    from securepipeline.reports.html_report import generate_html
    from securepipeline.reports.storage import HTML_REPORT, load_json_report, save_report

    result = load_json_report(config.report_path)
    if result is None:
        print_status("No results for this project yet: run a scan first.", "warning")
        return
    try:
        report = save_report(generate_html(result, config.project_root.name), config.report_path, HTML_REPORT)
    except OSError as e:
        print_status(f"Cannot write the report: {e}", "error")
        return
    print_status(f"HTML report: {report}", "success")


def _tools(_config: Config) -> None:
    missing = print_tools_status()
    if missing and _confirm(f"Install {', '.join(missing)}?"):
        install_missing(missing)


def _next_choice(choices: tuple[str, ...], current: str) -> str:
    return choices[(choices.index(current) + 1) % len(choices)]


def _settings(config: Config) -> None:
    while True:
        clear_screen()
        print_section("Scan settings")
        print(f"  {GREEN}1{RESET}  {WHITE}{'Fail on':<16}{RESET} {CYAN}{config.fail_on}{RESET}")
        print(f"  {GREEN}2{RESET}  {WHITE}{'Report format':<16}{RESET} {CYAN}{config.output_format}{RESET}")
        print(f"  {GREEN}3{RESET}  {WHITE}{'Parallel tools':<16}{RESET} {CYAN}{config.jobs}{RESET}")
        print()
        print_field("Reports", f"{GRAY}{config.report_dir}{RESET}")
        print(f"\n  {GRAY}1 and 2 switch to the next value {DOT} Enter to go back{RESET}\n")

        choice = _ask(get_prompt("~/settings"))
        if not choice:
            return
        if choice == "1":
            config.fail_on = _next_choice(FAIL_ON_CHOICES, config.fail_on)
        elif choice == "2":
            config.output_format = _next_choice(FORMAT_CHOICES, config.output_format)
        elif choice == "3":
            jobs = _ask(f"  {CYAN}Tools to run in parallel:{RESET} ")
            if jobs and jobs.isdigit() and int(jobs) > 0:
                config.jobs = int(jobs)


def _help(_config: Config) -> None:
    print_help_screen()


def _modules(_config: Config) -> None:
    print_modules()


def _update(_config: Config) -> None:
    update_installation()


TOOLS_ITEM = MenuItem("5", "Check / install tools", _tools)

MENU: tuple[tuple[str, tuple[MenuItem, ...]], ...] = (
    ("Scan", (
        MenuItem("1", "Scan this project", _scan),
        MenuItem("2", "Scan another project", _scan, prepare=_choose_project),
    )),
    ("Results", (
        MenuItem("3", "View last results", _last_results),
        MenuItem("4", "Export HTML report", _export_html),
    )),
    ("Tools", (
        TOOLS_ITEM,
        MenuItem("6", "List scan modules", _modules),
    )),
    ("Options", (
        MenuItem("7", "Scan settings", _settings, pause=False),
        MenuItem("8", "Help and CI/CD", _help),
        MenuItem("u", "Update SecurePipeline", _update),
    )),
)

MENU_ITEMS = {item.key: item for _, items in MENU for item in items}


def _run_command(command: str) -> None:
    """Run a command prefixed with "!", without a shell."""
    try:
        args = shlex.split(command)
    except ValueError as e:
        print_status(f"Cannot read the command: {e}", "error")
        return
    if not args:
        print_status("Type the command right after the !, for example !ls", "warning")
        return
    try:
        subprocess.run(args, check=False)  # nosec B603 - the user typed this command
    except FileNotFoundError:
        print_status(
            f"Command not found: {args[0]}. Type it right after the !, for example !ls "
            "(shell built-ins such as cd are not available).",
            "error",
        )
    except OSError as e:
        print_status(f"Cannot run the command: {e}", "error")
    except KeyboardInterrupt:
        print_status("Command interrupted.", "warning")


def _last_scan_summary(config: Config) -> str:
    from securepipeline.reports.storage import load_json_report, report_age_seconds

    result = load_json_report(config.report_path)
    age = report_age_seconds(config.report_path)
    if result is None or age is None:
        return f"{GRAY}never{RESET}"
    parts = [severity_counts_line(result) or "no findings"]
    if not result.is_complete:
        parts.append(f"{YELLOW}incomplete{RESET}")
    parts.append(f"{GRAY}{format_age(age)}{RESET}")
    return f"  {GRAY}{DOT}{RESET}  ".join(parts)


def _print_home(config: Config) -> None:
    from securepipeline.tools.installer import get_missing_tools

    print_header(
        project=home_path(config.project_root),
        stacks=detect_stacks(config.project_root),
        missing_tools=get_missing_tools(),
        tools_key=TOOLS_ITEM.key,
        last_scan=_last_scan_summary(config),
        fail_on=config.fail_on,
    )
    print_menu([(title, [(item.key, item.label) for item in items]) for title, items in MENU])


def interactive_loop() -> None:
    """Run the menu on its own screen; actions print on the normal screen.

    Scan results therefore stay scrollable, and remain in the terminal after quitting.
    """
    config = Config.from_env()
    screen = AlternateScreen(MENU_MIN_HEIGHT)
    notice = ""
    try:
        while True:
            screen.enter()
            _print_home(config)
            if notice:
                print(f"  {YELLOW}{notice}{RESET}\n")
                notice = ""

            choice = _ask(get_prompt())
            if choice is None or choice.lower() in QUIT_WORDS:
                return
            if not choice:
                continue

            if choice.startswith("!"):
                screen.leave()
                print()
                _run_command(choice[1:])
                _pause()
                continue

            item = MENU_ITEMS.get(choice.lower())
            if item is None:
                notice = f"Unknown choice: {choice}. Prefix with ! to run a command."
                continue

            if item.prepare and not item.prepare(config):
                continue
            if item.pause:
                screen.leave()
            item.handler(config)
            if item.pause:
                _pause()
    finally:
        screen.leave()
