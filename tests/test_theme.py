"""Tests for the terminal symbols."""

import os
import subprocess  # nosec B404 - imports the theme in a fresh interpreter
import sys
from pathlib import Path

PRINT_SYMBOLS = (
    "from securepipeline.ui.theme import ARROW, BULLET, CHECK, CROSS, DOT, SPINNER, WARN;"
    "print(CHECK, CROSS, WARN, BULLET, DOT, ARROW, SPINNER)"
)


def symbols_with_encoding(encoding: str) -> str:
    """Import the theme in a new process, since it picks its symbols at import."""
    result = subprocess.run(  # nosec B603 - runs this Python with a fixed script
        [sys.executable, "-c", PRINT_SYMBOLS],
        capture_output=True,
        check=True,
        cwd=Path(__file__).parent.parent,
        env={**os.environ, "PYTHONIOENCODING": encoding},
    )
    return result.stdout.decode(encoding).strip()


def test_utf8_output_gets_the_dot_spinner():
    assert symbols_with_encoding("utf-8") == "✓ ✗ ! • · › ⠉⠘⠰⢠⣀⡄⠆⠃"


def test_other_encodings_fall_back_to_ascii():
    assert symbols_with_encoding("ascii") == "+ x ! * . -> .:':"
    assert symbols_with_encoding("cp1252") == "+ x ! * . -> .:':"
