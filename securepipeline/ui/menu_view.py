"""Rendering of the interactive menu."""

from collections.abc import Sequence
from itertools import zip_longest

from securepipeline import __version__
from securepipeline.ui.console import (
    print_field,
    term_height,
    term_width,
    truncate,
    truncate_left,
    visible_len,
)
from securepipeline.ui.theme import (
    ARROW,
    BLUE,
    BOLD,
    CHECK,
    CYAN,
    DEEP_RED,
    DOT,
    GRAY,
    GREEN,
    RED,
    RESET,
    WARN,
    WHITE,
    YELLOW,
    rgb,
)

LOGO_LINES = (
    '   _____                           ____  _            ___',
    '  / ___/___  _______  __________  / __ \\(_)___  ___  / (_)___  ___',
    '  \\__ \\/ _ \\/ ___/ / / / ___/ _ \\/ /_/ / / __ \\/ _ \\/ / / __ \\/ _ \\',
    ' ___/ /  __/ /__/ /_/ / /  /  __/ ____/ / /_/ /  __/ / / / / /  __/',
    '/____/\\___/\\___/\\__,_/_/   \\___/_/   /_/ .___/\\___/_/_/_/ /_/\\___/',
    '                                      /_/',
)
LOGO_GRADIENT = (
    rgb(171, 4, 21),
    rgb(192, 30, 29),
    rgb(213, 55, 37),
    rgb(234, 81, 45),
    rgb(255, 107, 53),
    rgb(255, 130, 70),
)
LOGO_MIN_WIDTH = 72
FULL_LAYOUT_MIN_HEIGHT = 28
MENU_MIN_HEIGHT = 24
TWO_COLUMNS_MIN_WIDTH = 76
COLUMN_WIDTH = 38


def print_header(
    project: str,
    stacks: list[str],
    missing_tools: list[str],
    tools_key: str,
    last_scan: str,
    fail_on: str,
) -> None:
    """Print the title and the state of the current project."""
    compact = _is_compact()
    if not compact:
        print()
    if term_width() >= LOGO_MIN_WIDTH:
        for color, line in zip(LOGO_GRADIENT, LOGO_LINES, strict=True):
            print(f"  {BOLD}{color}{line}{RESET}")
        if not compact:
            print()
        print(f"  {GRAY}Multi-stack DevSecOps scanner {DOT} v{__version__}{RESET}")
        if not compact:
            print()
    else:
        print(f"  {BOLD}{CYAN}SecurePipeline{RESET} {GRAY}{DOT} v{__version__}{RESET}\n")

    print_field("Project", f"{CYAN}{truncate_left(project, term_width() - 15)}{RESET}")
    print_field("Stacks", f" {DOT} ".join(stacks) if stacks else f"{GRAY}none detected{RESET}")
    if missing_tools:
        names = truncate(", ".join(missing_tools), term_width() - 34)
        print_field("Tools", f"{YELLOW}{WARN} missing: {names}{RESET} {GRAY}{ARROW} press {tools_key}{RESET}")
    else:
        print_field("Tools", f"{GREEN}{CHECK} all installed{RESET}")
    print_field("Last scan", last_scan)
    print_field("Fail on", fail_on)
    print()


def _is_compact() -> bool:
    """Drop the spacing that would push the logo off a 24-line terminal."""
    return term_height() < FULL_LAYOUT_MIN_HEIGHT


def _section_lines(title: str, items: Sequence[tuple[str, str]]) -> list[str]:
    lines = [f"  {BLUE}{BOLD}{title}{RESET}"]
    for index, (key, label) in enumerate(items):
        branch = "└──" if index == len(items) - 1 else "├──"
        lines.append(f"  {DEEP_RED}{branch}{RESET} {GREEN}{BOLD}{key}{RESET}  {WHITE}{label}{RESET}")
    return lines


def _pad(line: str, width: int) -> str:
    return line + " " * max(width - visible_len(line), 0)


def print_menu(sections: Sequence[tuple[str, Sequence[tuple[str, str]]]]) -> None:
    """Print the sections, in two columns when the terminal is wide enough."""
    rendered = [_section_lines(title, items) for title, items in sections]

    if term_width() >= TWO_COLUMNS_MIN_WIDTH:
        for start in range(0, len(rendered), 2):
            pair = rendered[start:start + 2]
            for left, right in zip_longest(pair[0], pair[-1] if len(pair) > 1 else [], fillvalue=""):
                print(f"{_pad(left, COLUMN_WIDTH)}{right}".rstrip())
            print()
    else:
        for lines in rendered:
            print("\n".join(lines))
        print()

    print(f"  {GREEN}{BOLD}q{RESET}  {GRAY}Quit   {DOT}   !<command>  run a command, e.g. !ls{RESET}")
    if not _is_compact():
        print()


def get_prompt(path: str = "~/menu") -> str:
    return f"{GREEN}sec{RESET}{RED}@{RESET}{CYAN}pipeline{RESET}{RED}:{RESET}{BLUE}{path}{RESET}{GREEN}${RESET} "
