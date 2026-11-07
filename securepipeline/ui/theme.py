"""Terminal colors and symbols."""

import os
import sys

from securepipeline.core.models import Severity


def supports_color() -> bool:
    """Honor NO_COLOR and FORCE_COLOR; no color outside a terminal."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty() and os.environ.get("TERM") != "dumb"


COLOR = supports_color()


def _style(code: str) -> str:
    return f"\033[{code}m" if COLOR else ""


def rgb(r: int, g: int, b: int) -> str:
    return _style(f"38;2;{r};{g};{b}")


RESET = _style("0")
BOLD = _style("1")

RED = rgb(255, 69, 58)
DEEP_RED = rgb(171, 4, 21)
ORANGE = rgb(255, 159, 10)
YELLOW = rgb(255, 214, 10)
GREEN = rgb(48, 209, 88)
CYAN = rgb(0, 230, 230)
BLUE = rgb(100, 160, 255)
WHITE = rgb(230, 230, 230)
GRAY = rgb(135, 135, 145)
DARK_GRAY = rgb(72, 72, 78)

CHECK = "✔"
CROSS = "✖"
WARN = "▲"
BULLET = "●"
DOT = "·"
ARROW = "→"

SEVERITY_COLORS = {
    Severity.CRITICAL: RED,
    Severity.HIGH: ORANGE,
    Severity.MEDIUM: YELLOW,
    Severity.LOW: BLUE,
    Severity.INFO: GRAY,
}
