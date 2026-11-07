"""Generic terminal output helpers."""

import os
import re
import shutil
import sys
from pathlib import Path

from securepipeline.ui.theme import (
    BLUE,
    BOLD,
    BULLET,
    CHECK,
    CROSS,
    CYAN,
    DOT,
    GRAY,
    GREEN,
    RED,
    RESET,
    WARN,
    YELLOW,
)

ANSI_PATTERN = re.compile(r"\033\[[0-9;]*m")


def term_width() -> int:
    return shutil.get_terminal_size((100, 24)).columns


def term_height() -> int:
    return shutil.get_terminal_size((100, 24)).lines


def visible_len(text: str) -> int:
    return len(ANSI_PATTERN.sub("", text))


def truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(width - 1, 0)] + "…"


def truncate_left(text: str, width: int) -> str:
    """Cut the start: the end of a path is the most useful part."""
    return text if len(text) <= width else "…" + text[-max(width - 1, 0):]


def plural(count: int, singular: str, plural_form: str | None = None) -> str:
    return f"{count} {singular if count == 1 else plural_form or singular + 's'}"


def is_terminal() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM") != "dumb"


def clear_screen() -> None:
    """Clear the visible screen, leaving the terminal's scrollback untouched."""
    if is_terminal():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


class AlternateScreen:
    """Full-screen buffer for the menu, as used by vim or htop.

    Redraws never pile up in the scrollback, and leaving restores the terminal.
    The buffer has no scrollback of its own, so a terminal too short to show the
    whole menu stays on the normal screen, where the user can scroll up.
    """

    def __init__(self, min_height: int = 0):
        self.min_height = min_height
        self.active = False

    def enter(self) -> None:
        if is_terminal() and not self.active and term_height() >= self.min_height:
            sys.stdout.write("\033[?1049h")
            self.active = True
        clear_screen()

    def leave(self) -> None:
        if self.active:
            sys.stdout.write("\033[?1049l")
            sys.stdout.flush()
            self.active = False


def display_path(path: object) -> str:
    """Shorten a path located under the current directory."""
    absolute = os.path.abspath(str(path))
    relative = os.path.relpath(absolute, os.getcwd())
    return absolute if relative.startswith("..") else relative


def home_path(path: object) -> str:
    """Abbreviate the home directory to ~."""
    absolute = Path(os.path.abspath(str(path)))
    try:
        return f"~/{absolute.relative_to(Path.home())}"
    except ValueError:
        return str(absolute)


def format_age(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} h ago"
    return f"{plural(hours // 24, 'day')} ago"


def print_section(title: str) -> None:
    print(f"\n  {CYAN}{BOLD}{title}{RESET}\n")


def print_status(message: str, status: str = "info") -> None:
    symbols = {
        "info": f"{BLUE}{BULLET}{RESET}",
        "success": f"{GREEN}{CHECK}{RESET}",
        "warning": f"{YELLOW}{WARN}{RESET}",
        "error": f"{RED}{CROSS}{RESET}",
    }
    print(f"  {symbols.get(status, DOT)} {message}")


def print_field(label: str, value: str, width: int = 10) -> None:
    print(f"  {GRAY}{label:<{width}}{RESET} {value}")


def print_command(command: str, comment: str = "") -> None:
    note = f"  {GRAY}{comment}{RESET}" if comment else ""
    print(f"    {GREEN}{command}{RESET}{note}")
