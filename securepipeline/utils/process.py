"""Subprocess execution without a shell."""

import json
import os
import shutil
import subprocess  # nosec B404 - runs the security tools, never through a shell
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from securepipeline.utils.logger import log


@dataclass
class CommandResult:
    command: list[str]
    return_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.return_code == 0

    def json(self) -> Any:
        """Return stdout parsed as JSON, or None if it is not valid JSON."""
        try:
            return json.loads(self.stdout)
        except ValueError:
            return None


def extend_tool_path() -> None:
    """Make tools from the venv and ~/.local/bin visible without activation."""
    current = os.environ.get("PATH", "").split(os.pathsep)
    candidates = [str(Path(sys.executable).parent), str(Path.home() / ".local" / "bin")]
    extra = [p for p in candidates if p not in current]
    if extra:
        os.environ["PATH"] = os.pathsep.join([*extra, *current])


def check_tool(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def run_command(
    command: list[str],
    cwd: str | Path | None = None,
    timeout: int = 300,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run a command and capture its output; return_code is -1 if it could not run."""
    log.debug("Running: %s", " ".join(command))
    # On Windows, tools such as npm are .cmd scripts: CreateProcess ignores PATHEXT,
    # so "npm" alone gives WinError 2. shutil.which resolves the full path.
    executable = shutil.which(command[0]) if command else None
    if executable:
        command = [executable, *command[1:]]

    try:
        result = subprocess.run(  # nosec B603 - argument list, no shell
            command,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(command, -1, stderr=f"Timed out after {timeout}s", timed_out=True)
    except OSError as e:
        return CommandResult(command, -1, stderr=str(e))

    return CommandResult(command, result.returncode, result.stdout or "", result.stderr or "")
