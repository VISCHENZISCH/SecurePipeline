"""Runs the security tools of a scan in parallel."""

import os
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from securepipeline.core.config import default_jobs
from securepipeline.core.models import (
    TOOL_NOT_INSTALLED,
    CheckResult,
    CheckStatus,
    Finding,
    ScanResult,
)
from securepipeline.scanners import get_scanners_for_stacks
from securepipeline.scanners.base import Check, CheckSkipped, NothingToScan, ToolError
from securepipeline.utils.logger import log
from securepipeline.utils.process import check_tool


def planned_tools(stacks: list[str]) -> list[str]:
    return [c.tool for s in get_scanners_for_stacks(stacks) for c in s.checks()]


def run_scan(
    path: str | Path,
    stacks: list[str],
    jobs: int = 0,
    on_start: Callable[[str], None] | None = None,
    on_done: Callable[[CheckResult], None] | None = None,
) -> ScanResult:
    """Run every tool and aggregate the results.

    The tools spend their time in subprocesses, so threads are enough to run them
    in parallel. The project path is made absolute because tools run with cwd=root.
    """
    root = Path(path).resolve()
    started_at = time.perf_counter()
    scheduled = [
        (scanner.info().name, check)
        for scanner in get_scanners_for_stacks(stacks)
        for check in scanner.checks()
    ]

    def execute(module: str, check: Check) -> tuple[CheckResult, list[Finding]]:
        if on_start:
            on_start(check.tool)
        return _run_check(module, check, root)

    findings: list[Finding] = []
    checks: list[CheckResult] = []

    pool = ThreadPoolExecutor(max_workers=jobs or default_jobs())
    try:
        futures = [pool.submit(execute, module, check) for module, check in scheduled]
        for future in as_completed(futures):
            check_result, check_findings = future.result()
            checks.append(check_result)
            findings.extend(check_findings)
            if on_done:
                on_done(check_result)
    finally:
        # On Ctrl-C, do not wait for the tools still in the queue.
        pool.shutdown(wait=False, cancel_futures=True)

    order = {check.tool: index for index, (_, check) in enumerate(scheduled)}
    checks.sort(key=lambda c: order[c.tool])

    return ScanResult(
        findings=_normalize(findings, root),
        stacks_scanned=stacks,
        duration_seconds=time.perf_counter() - started_at,
        checks=checks,
    )


def _run_check(module: str, check: Check, root: Path) -> tuple[CheckResult, list[Finding]]:
    started_at = time.perf_counter()
    findings: list[Finding] = []
    detail = ""
    status = CheckStatus.OK

    if not check_tool(check.tool):
        status, detail = CheckStatus.SKIPPED, TOOL_NOT_INSTALLED
    else:
        try:
            findings = check.run(root)
        except NothingToScan as e:
            status, detail = CheckStatus.NOTHING, str(e)
        except CheckSkipped as e:
            status, detail = CheckStatus.SKIPPED, str(e)
        except ToolError as e:
            status, detail = CheckStatus.ERROR, str(e)
        except Exception as e:  # noqa: BLE001 - one failing tool must not stop the others
            log.debug("Unexpected failure in %s", check.tool, exc_info=True)
            status, detail = CheckStatus.ERROR, f"internal error: {e}"

    return (
        CheckResult(
            tool=check.tool,
            module=module,
            status=status,
            detail=detail,
            findings=len(findings),
            duration=time.perf_counter() - started_at,
        ),
        findings,
    )


def _normalize(findings: list[Finding], root: Path) -> list[Finding]:
    """Make paths project-relative and drop exact duplicates."""
    unique: dict[tuple, Finding] = {}
    for finding in findings:
        finding.file_path = _relative_path(finding.file_path, root)
        key = (finding.scanner, finding.rule_id, finding.file_path, finding.line, finding.title)
        unique.setdefault(key, finding)
    return list(unique.values())


def _relative_path(file_path: str, root: Path) -> str:
    if not file_path or not os.path.isabs(file_path):
        return file_path
    relative = os.path.relpath(file_path, root)
    return file_path if relative.startswith("..") else relative
