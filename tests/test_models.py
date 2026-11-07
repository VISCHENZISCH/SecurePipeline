"""Tests for the models and the exit code."""

import pytest

from securepipeline.core.models import CheckResult, CheckStatus, Finding, ScanResult, Severity


def finding(severity: Severity) -> Finding:
    return Finding(rule_id="R", title="T", severity=severity, scanner="s")


def check(status: CheckStatus) -> CheckResult:
    return CheckResult(tool="t", module="m", status=status)


@pytest.mark.parametrize(("severities", "statuses", "fail_on", "allow", "expected"), [
    ([], [CheckStatus.OK], "critical", False, 0),
    ([Severity.HIGH], [CheckStatus.OK], "critical", False, 0),
    ([Severity.HIGH], [CheckStatus.OK], "high", False, 1),
    ([Severity.CRITICAL], [CheckStatus.ERROR], "critical", True, 1),
    ([], [CheckStatus.SKIPPED], "critical", False, 2),
    ([], [CheckStatus.ERROR], "critical", False, 2),
    ([], [CheckStatus.ERROR], "critical", True, 0),
    ([], [CheckStatus.NOTHING], "critical", False, 0),
    ([Severity.CRITICAL], [CheckStatus.ERROR], "critical", False, 1),
])
def test_exit_code(severities, statuses, fail_on, allow, expected):
    result = ScanResult(findings=[finding(s) for s in severities], checks=[check(s) for s in statuses])
    assert result.exit_code(fail_on, allow) == expected


def test_round_trip_through_dict():
    original = ScanResult(
        findings=[finding(Severity.LOW)],
        stacks_scanned=["python"],
        duration_seconds=1.5,
        checks=[check(CheckStatus.SKIPPED)],
    )
    restored = ScanResult.from_dict(original.to_dict())
    assert restored == original
    assert restored.findings[0].severity is Severity.LOW
    assert restored.checks[0].status is CheckStatus.SKIPPED


@pytest.mark.parametrize(("label", "expected"), [
    ("CRITICAL", Severity.CRITICAL),
    ("moderate", Severity.MEDIUM),
    ("low", Severity.LOW),
    (None, Severity.MEDIUM),
    ("unknown", Severity.MEDIUM),
])
def test_severity_from_label(label, expected):
    assert Severity.from_label(label) is expected


def test_location():
    assert Finding("R", "T", Severity.LOW, file_path="a.py", line=3).location == "a.py:3"
    assert Finding("R", "T", Severity.LOW, file_path="a.py").location == "a.py"
