"""Tests for the scan engine and the scanner registry."""

import threading

import pytest

from securepipeline.core import orchestrator
from securepipeline.core.models import CheckStatus, Finding, Severity
from securepipeline.scanners import get_scanners_for_stacks
from securepipeline.scanners.base import (
    BaseScanner,
    Check,
    CheckSkipped,
    NothingToScan,
    PartialScan,
    ScannerInfo,
    ToolError,
)
from securepipeline.scanners.semgrep import SemgrepScanner


class FakeScanner(BaseScanner):
    def __init__(self, *checks: Check):
        self._checks = list(checks)

    def info(self) -> ScannerInfo:
        return ScannerInfo("Fake", "Test scanner")

    def checks(self) -> list[Check]:
        return self._checks


@pytest.fixture
def use_checks(monkeypatch):
    monkeypatch.setattr(orchestrator, "check_tool", lambda tool: tool != "missing")

    def install(*checks: Check) -> None:
        monkeypatch.setattr(orchestrator, "get_scanners_for_stacks", lambda _s: [FakeScanner(*checks)])

    return install


def raising(error: Exception):
    def run(_root):
        raise error
    return run


def test_missing_tool_is_skipped_not_clean(use_checks, tmp_path):
    use_checks(Check("missing", lambda _root: []))
    result = orchestrator.run_scan(tmp_path, [])
    assert result.checks[0].status == CheckStatus.SKIPPED
    assert not result.is_complete
    assert result.exit_code() == 2


@pytest.mark.parametrize(("error", "status", "complete"), [
    (ToolError("failed"), CheckStatus.ERROR, False),
    (CheckSkipped("no manifest"), CheckStatus.SKIPPED, False),
    (NothingToScan("nothing"), CheckStatus.NOTHING, True),
    (RuntimeError("bug"), CheckStatus.ERROR, False),
])
def test_check_failures_are_reported(use_checks, tmp_path, error, status, complete):
    use_checks(Check("tool", raising(error)), Check("other", lambda _root: []))
    result = orchestrator.run_scan(tmp_path, [])
    by_tool = {c.tool: c for c in result.checks}
    assert by_tool["tool"].status == status
    assert by_tool["other"].status == CheckStatus.OK
    assert result.is_complete is complete


def test_checks_run_in_parallel(use_checks, tmp_path):
    barrier = threading.Barrier(2, timeout=5)

    def wait_for_other(_root):
        barrier.wait()
        return []

    use_checks(Check("a", wait_for_other), Check("b", wait_for_other))
    result = orchestrator.run_scan(tmp_path, [], jobs=2)
    assert all(c.status == CheckStatus.OK for c in result.checks)


def test_results_keep_declaration_order(use_checks, tmp_path):
    use_checks(*(Check(name, lambda _root: []) for name in "abcd"))
    assert [c.tool for c in orchestrator.run_scan(tmp_path, []).checks] == list("abcd")


def test_paths_are_relative_and_duplicates_removed(use_checks, tmp_path):
    absolute = str(tmp_path / "src" / "app.py")

    def duplicates(_root):
        return [Finding("R", "T", Severity.LOW, file_path=absolute, line=1, scanner="s") for _ in range(2)]

    use_checks(Check("tool", duplicates))
    result = orchestrator.run_scan(tmp_path, [])
    assert [f.file_path for f in result.findings] == ["src/app.py"]


def test_relative_project_path_reaches_tools_as_absolute(use_checks, tmp_path, monkeypatch):
    (tmp_path / "project").mkdir()
    monkeypatch.chdir(tmp_path)
    seen = []
    use_checks(Check("tool", lambda root: seen.append(root) or []))
    orchestrator.run_scan("project", [])
    assert seen == [tmp_path / "project"]


def tools_for(stacks: list[str]) -> list[str]:
    return [check.tool for scanner in get_scanners_for_stacks(stacks) for check in scanner.checks()]


def test_secrets_scanner_runs_without_any_stack():
    assert tools_for([]) == ["gitleaks"]


def test_semgrep_runs_once_for_all_stacks():
    assert tools_for(["node", "php", "python"]).count("semgrep") == 1


def test_no_semgrep_without_rules():
    assert "semgrep" not in tools_for(["flutter", "docker"])


def test_semgrep_rule_files_are_packaged():
    configs = SemgrepScanner(["node", "php", "flutter"])._configs()
    local = [config for config in configs if config.endswith(".yml")]
    assert len(local) == 2
    for path in local:
        with open(path, encoding="utf-8") as handle:
            assert handle.read().startswith("rules:")
    assert not any("dart" in config for config in configs)


def test_partial_scan_keeps_findings_but_stays_incomplete(use_checks, tmp_path):
    finding = Finding("R1", "Found", Severity.HIGH, "api/package-lock.json", scanner="tool")
    use_checks(Check("tool", raising(PartialScan("web: lockfile missing", [finding]))))
    result = orchestrator.run_scan(tmp_path, [])
    assert result.checks[0].status == CheckStatus.SKIPPED
    assert "web: lockfile missing" in result.checks[0].detail
    assert [f.rule_id for f in result.findings] == ["R1"]
    assert result.exit_code() == 2
