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


class PartialScan(CheckSkipped):
    """Some folders were audited, others could not be: the check stays incomplete."""

    def __init__(self, reason: str, findings: list[Finding]):
        super().__init__(reason)
        self.findings = findings


def audit_dirs(root: Path, dirs: list[Path], audit: Callable[[Path], list[Finding]]) -> list[Finding]:
    """Run `audit` in each folder and gather the findings, with project-relative paths.

    A folder that `audit` cannot check (CheckSkipped) does not hide the findings of
    the others, but it keeps the check incomplete.
    """
    findings: list[Finding] = []
    skipped: list[str] = []
    for directory in dirs:
        folder = directory.relative_to(root).as_posix()
        try:
            results = audit(directory)
        except CheckSkipped as e:
            skipped.append(f"{folder}: {e}" if folder != "." else str(e))
            continue
        for finding in results:
            if folder != "." and finding.file_path and not Path(finding.file_path).is_absolute():
                finding.file_path = f"{folder}/{finding.file_path}"
        findings.extend(results)

    if skipped:
        reason = "; ".join(skipped)
        if len(skipped) == len(dirs):
            raise CheckSkipped(reason)
        raise PartialScan(reason, findings)
    return findings


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
