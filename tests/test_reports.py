"""Report tests."""

from securepipeline.core.models import CheckResult, CheckStatus, Finding, ScanResult, Severity
from securepipeline.reports.html_report import generate_html
from securepipeline.reports.markdown_report import generate_markdown
from securepipeline.reports.storage import load_json_report, save_json_report


def result(findings=(), status=CheckStatus.OK, detail="") -> ScanResult:
    return ScanResult(
        findings=list(findings),
        stacks_scanned=["python"],
        duration_seconds=1.0,
        checks=[CheckResult("bandit", "Python", status, detail)],
    )


HOSTILE = Finding(
    rule_id="R",
    title='a | b\nc <script>alert("x")</script>',
    severity=Severity.HIGH,
    file_path="x.py",
    line=2,
    description="<img src=x onerror=y>",
    scanner="<b>s</b>",
)


def test_markdown_keeps_one_table_row_per_finding():
    report = generate_markdown(result([HOSTILE]))
    row = next(line for line in report.splitlines() if line.startswith("| HIGH"))
    assert "a \\| b c" in row
    assert "<script>" not in report
    assert "<img" not in report


def test_html_escapes_external_content():
    report = generate_html(result([HOSTILE]))
    assert "<script>alert" not in report
    assert "<img src=x" not in report
    assert "<b>s</b>" not in report
    assert "&lt;script&gt;" in report


def test_clean_report_is_only_claimed_when_complete():
    assert "Incomplete scan" not in generate_markdown(result())
    assert "No findings" in generate_html(result())

    incomplete = result(status=CheckStatus.ERROR, detail="timeout")
    assert "Incomplete scan" in generate_markdown(incomplete)
    assert "timeout" in generate_markdown(incomplete)
    html = generate_html(incomplete)
    assert "Incomplete scan" in html
    assert "No findings" not in html


def test_json_report_round_trip(tmp_path):
    original = result([HOSTILE])
    save_json_report(original, tmp_path / "reports")
    assert load_json_report(tmp_path / "reports") == original


def test_json_report_absent_or_corrupt_returns_none(tmp_path):
    assert load_json_report(tmp_path) is None
    (tmp_path / "securepipeline-report.json").write_text("{not json")
    assert load_json_report(tmp_path) is None
    (tmp_path / "securepipeline-report.json").write_text('{"findings": [{"unknown": 1}]}')
    assert load_json_report(tmp_path) is None
