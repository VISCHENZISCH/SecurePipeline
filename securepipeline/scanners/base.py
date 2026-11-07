"""Base classes shared by the scanners."""

from abc import ABC, abstractmethod
from collections.abc import Callable, Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from securepipeline.core.models import Finding
from securepipeline.utils.process import CommandResult


class ToolError(Exception):
    """The tool failed: its results cannot be trusted."""


class CheckSkipped(Exception):
    """The target exists but this tool cannot audit it."""


class NothingToScan(Exception):
    """This project has nothing for this tool to analyze."""


@dataclass(frozen=True)
class ScannerInfo:
    name: str
    description: str
    stack: str = ""


@dataclass(frozen=True)
class Check:
    tool: str
    run: Callable[[Path], list[Finding]]


class BaseScanner(ABC):
    """A scanner describes itself and the checks to run.

    Checks raise ToolError, CheckSkipped or NothingToScan instead of returning an
    empty list, so that a failure cannot pass for a healthy project.
    """

    @abstractmethod
    def info(self) -> ScannerInfo:
        ...

    @abstractmethod
    def checks(self) -> list[Check]:
        ...

    @property
    def tools_required(self) -> list[str]:
        return [check.tool for check in self.checks()]


def load_json(result: CommandResult, ok_codes: Collection[int] = (0, 1)) -> Any:
    """Validate a tool run and return its JSON output.

    Raises:
        ToolError: unexpected return code, timeout or output that is not JSON.
    """
    if result.return_code not in ok_codes:
        raise ToolError(_failure_reason(result))
    data = result.json()
    if data is None:
        raise ToolError(f"invalid JSON output ({_failure_reason(result)})")
    return data


def _failure_reason(result: CommandResult) -> str:
    lines = [line.strip() for line in result.stderr.splitlines() if line.strip()]
    return lines[-1][:160] if lines else f"return code {result.return_code}"
