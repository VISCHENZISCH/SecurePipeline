"""CLI tests: documented commands, exit codes and menu."""

import builtins
import json
import shutil
import stat

import pytest
from click.testing import CliRunner

from securepipeline import __version__
from securepipeline.cli import actions, app, cli
from securepipeline.cli import menu as menu_module
from securepipeline.core import orchestrator
from securepipeline.core.models import (
    TOOL_NOT_INSTALLED,
    CheckResult,
    CheckStatus,
    Finding,
    ScanResult,
    Severity,
)
from securepipeline.tools.installer import _write_executable
from securepipeline.ui import console, menu_view
from securepipeline.ui.console import format_age
from securepipeline.utils.process import CommandResult


def scan_result(*severities, status=CheckStatus.OK, detail="") -> ScanResult:
    return ScanResult(
        findings=[Finding("R", f"Title {s.value}", s, file_path="a.py", line=1, scanner="s") for s in severities],
        checks=[CheckResult("gitleaks", "Secrets", status, detail, findings=len(severities))],
    )


@pytest.fixture
def fake_scan(monkeypatch):
    """Replace the engine and record the received path."""
    calls = []

    def install(result: ScanResult):
        def run_scan(path, stacks, **_kwargs):
            calls.append(path)
            return result

        monkeypatch.setattr(orchestrator, "run_scan", run_scan)
        return calls

    return install


def invoke(*args: str, **kwargs):
    return CliRunner().invoke(cli, list(args), **kwargs)


@pytest.mark.parametrize(("severities", "fail_on", "expected"), [
    ((), "critical", 0),
    ((Severity.HIGH,), "critical", 0),
    ((Severity.HIGH,), "high", 1),
    ((Severity.CRITICAL,), "critical", 1),
])
def test_scan_exit_codes(fake_scan, tmp_path, severities, fail_on, expected):
    fake_scan(scan_result(*severities))
    outcome = invoke("scan", str(tmp_path), "--fail-on", fail_on)
    assert outcome.exit_code == expected, outcome.output


def test_scan_defaults_to_current_directory(fake_scan, tmp_path, monkeypatch):
    calls = fake_scan(scan_result())
    monkeypatch.chdir(tmp_path)
    assert invoke("scan").exit_code == 0
    assert calls == [tmp_path]


def test_relative_path_is_resolved(fake_scan, tmp_path, monkeypatch):
    (tmp_path / "project").mkdir()
    calls = fake_scan(scan_result())
    monkeypatch.chdir(tmp_path)
    assert invoke("scan", "project").exit_code == 0
    assert calls == [tmp_path / "project"]
    assert (tmp_path / "project/.securepipeline/reports/securepipeline-report.md").exists()


def test_incomplete_scan_fails_unless_allowed(fake_scan, tmp_path):
    fake_scan(scan_result(status=CheckStatus.SKIPPED, detail=TOOL_NOT_INSTALLED))
    strict = invoke("scan", str(tmp_path))
    assert strict.exit_code == 2
    assert "INCOMPLETE" in strict.output
    assert "securepipeline tools install" in strict.output
    assert "no findings" not in strict.output
    assert invoke("scan", str(tmp_path), "--allow-incomplete").exit_code == 0


@pytest.mark.parametrize(("output_format", "extensions"), [
    ("md", {".md", ".json"}),
    ("html", {".html", ".json"}),
    ("both", {".md", ".html", ".json"}),
])
def test_scan_formats(fake_scan, tmp_path, output_format, extensions):
    fake_scan(scan_result())
    assert invoke("scan", str(tmp_path), "--format", output_format).exit_code == 0
    written = {p.suffix for p in (tmp_path / ".securepipeline/reports").iterdir()}
    assert written == extensions


def test_report_dir_from_environment(fake_scan, tmp_path):
    fake_scan(scan_result())
    out = tmp_path / "elsewhere"
    assert invoke("scan", str(tmp_path), env={"SECUREPIPELINE_REPORT_DIR": str(out)}).exit_code == 0
    assert (out / "securepipeline-report.md").exists()


def test_fail_on_from_environment(fake_scan, tmp_path):
    fake_scan(scan_result(Severity.HIGH))
    assert invoke("scan", str(tmp_path), env={"SECUREPIPELINE_FAIL_ON": "high"}).exit_code == 1


def test_format_from_environment(fake_scan, tmp_path):
    fake_scan(scan_result())
    assert invoke("scan", str(tmp_path), env={"SECUREPIPELINE_FORMAT": "html"}).exit_code == 0
    assert (tmp_path / ".securepipeline/reports/securepipeline-report.html").exists()


def test_unwritable_report_dir_exits_with_2(fake_scan, tmp_path):
    fake_scan(scan_result())
    blocker = tmp_path / "file"
    blocker.write_text("")
    outcome = invoke("scan", str(tmp_path), "--report-dir", str(blocker / "subdir"))
    assert outcome.exit_code == 2
    assert "Cannot write reports" in outcome.output


def test_findings_display_is_limited_unless_all(fake_scan, tmp_path):
    fake_scan(scan_result(*[Severity.LOW] * 25))
    assert "and 5 more" in invoke("scan", str(tmp_path)).output
    assert "more in the report" not in invoke("scan", str(tmp_path), "--all").output


def test_quiet_only_prints_verdict(fake_scan, tmp_path):
    fake_scan(scan_result(Severity.CRITICAL))
    output = invoke("scan", str(tmp_path), "--quiet").output
    assert "FAILED" in output
    assert "Title critical" not in output


def test_nonexistent_path_is_rejected():
    assert invoke("scan", "/no/such/path").exit_code == 2


def test_version():
    assert __version__ in invoke("--version").output


def test_help_describes_the_tool():
    outcome = invoke("--help")
    assert outcome.exit_code == 0
    assert "Multi-stack DevSecOps security scanner" in outcome.output


def test_markdown_is_an_alias_of_md(fake_scan, tmp_path):
    fake_scan(scan_result())
    assert invoke("scan", str(tmp_path), "--format", "markdown").exit_code == 0
    assert (tmp_path / ".securepipeline/reports/securepipeline-report.md").exists()


def test_no_command_without_terminal_shows_help():
    outcome = invoke()
    assert outcome.exit_code == 0
    assert "scan" in outcome.output


def test_detect_lists_planned_tools(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    outcome = invoke("detect", str(tmp_path))
    assert "python" in outcome.output
    assert "semgrep" in outcome.output


def test_modules_lists_scanners():
    output = invoke("modules").output
    assert "Semgrep SAST" in output
    assert "Secrets" in output


def test_tools_install_rejects_unknown_name():
    assert invoke("tools", "install", "unknown", "--yes").exit_code == 2


def test_tools_install_requires_confirmation(monkeypatch):
    called = []
    monkeypatch.setattr(app, "install_missing", lambda *a: called.append(a) or True)
    outcome = invoke("tools", "install", "trivy", input="n\n")
    assert outcome.exit_code == 1
    assert not called


def test_tools_install_with_yes_reports_failure(monkeypatch):
    monkeypatch.setattr(app, "install_missing", lambda *_a: False)
    assert invoke("tools", "install", "trivy", "--yes").exit_code == 1


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_real_scan_finds_secret_without_stack(tmp_path, fake_aws_key):
    (tmp_path / "creds.txt").write_text(f'aws_access_key_id = "{fake_aws_key}"\n')
    outcome = invoke("scan", str(tmp_path))
    assert outcome.exit_code == 1, outcome.output
    report = (tmp_path / ".securepipeline/reports/securepipeline-report.json").read_text()
    assert json.loads(report)["findings"]
    assert fake_aws_key not in report


@pytest.mark.parametrize(("seconds", "expected"), [
    (10, "just now"),
    (300, "5 min ago"),
    (7200, "2 h ago"),
    (86400, "1 day ago"),
    (172800, "2 days ago"),
])
def test_format_age(seconds, expected):
    assert format_age(seconds) == expected


@pytest.fixture
def menu(monkeypatch, tmp_path, capsys):
    """Run the menu with prepared answers and return its output."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("securepipeline.tools.installer.get_missing_tools", list)

    def play(*answers: str) -> str:
        queue = iter(answers)

        def fake_input(_prompt=""):
            try:
                return next(queue)
            except StopIteration:
                raise EOFError from None

        monkeypatch.setattr(builtins, "input", fake_input)
        menu_module.interactive_loop()
        return capsys.readouterr().out

    return play


def test_menu_exits_on_end_of_input(menu):
    assert "Scan current project" in menu()


def test_menu_header_shows_project_state(menu, tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    output = menu("q")
    assert tmp_path.name in output
    assert "python" in output
    assert "all installed" in output
    assert "never" in output


def test_menu_header_reports_missing_tools(menu, monkeypatch):
    monkeypatch.setattr("securepipeline.tools.installer.get_missing_tools", lambda: ["trivy"])
    output = menu("q")
    assert "missing: trivy" in output
    assert f"press {menu_module.TOOLS_ITEM.key}" in output


def test_menu_keys_are_unique():
    keys = [item.key for _, items in menu_module.MENU for item in items]
    assert len(keys) == len(set(keys))


def test_menu_unknown_choice_runs_nothing(menu, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("no command must run")

    monkeypatch.setattr(menu_module.subprocess, "run", forbidden)
    assert "Unknown choice: ls" in menu("ls", "q")


def test_menu_bang_runs_command_without_shell(menu, monkeypatch):
    calls = []
    monkeypatch.setattr(menu_module.subprocess, "run", lambda *a, **k: calls.append((a, k)))
    menu("!echo 'two words'", "", "q")
    assert calls[0][0][0] == ["echo", "two words"]
    assert "shell" not in calls[0][1]


@pytest.mark.parametrize("command", ["cmd-that-does-not-exist ls", ""])
def test_menu_bang_explains_how_to_type_a_command(menu, command):
    output = menu(f"!{command}", "", "q")
    assert "right after the !" in output


def test_menu_bang_rejects_unbalanced_quotes(menu):
    assert "Cannot read the command" in menu("!echo 'oops", "", "q")


def test_menu_hint_shows_a_real_command(menu):
    output = menu("q")
    assert "!ls" in output
    assert "!cmd" not in output


@pytest.mark.parametrize(("width", "height", "logo"), [
    (100, 40, True),
    (100, 24, True),
    (100, 15, True),
    (60, 40, False),
])
def test_menu_logo_only_depends_on_width(menu, monkeypatch, width, height, logo):
    monkeypatch.setattr(menu_view, "term_width", lambda: width)
    monkeypatch.setattr(menu_view, "term_height", lambda: height)
    assert ("/____/" in menu("q")) is logo


def test_menu_with_logo_fits_in_24_lines(menu, monkeypatch):
    monkeypatch.setattr(menu_view, "term_width", lambda: 100)
    monkeypatch.setattr(menu_view, "term_height", lambda: 24)
    output = menu("q")
    assert len(output.splitlines()) <= 23  # The prompt takes the last line.


def fake_terminal(monkeypatch, height):
    monkeypatch.setattr(console, "is_terminal", lambda: True)
    monkeypatch.setattr(console, "term_height", lambda: height)


def test_action_output_goes_to_the_normal_screen(menu, monkeypatch, fake_scan):
    fake_terminal(monkeypatch, 40)
    fake_scan(scan_result(Severity.HIGH))
    output = menu("1", "", "q")
    enter, leave = "\033[?1049h", "\033[?1049l"
    assert output.count(enter) == 2
    assert output.count(leave) == 2
    assert output.index(leave) < output.index("Title high") < output.rindex(enter)
    assert output.endswith(leave)


def test_settings_stay_on_the_menu_screen(menu, monkeypatch):
    fake_terminal(monkeypatch, 40)
    output = menu("7", "", "q")
    assert output.count("\033[?1049h") == 1


def test_short_terminal_stays_on_the_normal_screen(menu, monkeypatch):
    fake_terminal(monkeypatch, 15)
    assert "\033[?1049" not in menu("q")


def test_screen_is_restored_when_the_menu_crashes(menu, monkeypatch, capsys):
    fake_terminal(monkeypatch, 40)

    def crash(_config):
        raise RuntimeError("boom")

    monkeypatch.setattr(menu_module, "_print_home", crash)
    with pytest.raises(RuntimeError):
        menu("q")
    assert capsys.readouterr().out.endswith("\033[?1049l")


def test_no_escape_sequences_outside_a_terminal(menu):
    assert "\033[" not in menu("q")


def test_menu_scan_uses_current_project_without_asking(menu, tmp_path, fake_scan):
    calls = fake_scan(scan_result())
    menu("1", "", "q")
    assert calls == [tmp_path]


def test_menu_scan_another_project_scans_right_away(menu, tmp_path, fake_scan):
    target = tmp_path / "other"
    target.mkdir()
    calls = fake_scan(scan_result())
    menu("2", str(target), "", "q")
    assert calls == [target]


def test_menu_scan_another_project_stays_current(menu, tmp_path, fake_scan):
    target = tmp_path / "other"
    target.mkdir()
    calls = fake_scan(scan_result())
    menu("2", str(target), "", "1", "", "q")
    assert calls == [target, target]


@pytest.mark.parametrize("answer", [
    "{path}",
    "'{path}'",
    '"{path}"',
    "{escaped}",
])
def test_menu_scan_another_project_accepts_spaces_in_path(menu, tmp_path, fake_scan, answer):
    target = tmp_path / "project with spaces"
    target.mkdir()
    calls = fake_scan(scan_result())
    menu("2", answer.format(path=target, escaped=str(target).replace(" ", "\\ ")), "", "q")
    assert calls == [target]


def test_menu_scan_another_project_shows_live_output_on_normal_screen(menu, tmp_path, monkeypatch, fake_scan):
    target = tmp_path / "other"
    target.mkdir()
    fake_terminal(monkeypatch, 40)
    fake_scan(scan_result(Severity.HIGH))
    output = menu("2", str(target), "", "q")
    assert output.index("\033[?1049l") < output.index("Title high")


def test_menu_scan_another_project_rejects_invalid_path(menu, fake_scan):
    calls = fake_scan(scan_result())
    output = menu("2", "/no/such/path", "", "q")
    assert "Directory not found" in output
    assert calls == []


def test_menu_scan_another_project_empty_answer_scans_nothing(menu, tmp_path, fake_scan):
    calls = fake_scan(scan_result())
    menu("2", "", "q")
    assert calls == []
    menu("1", "", "q")
    assert calls == [tmp_path]


def test_menu_scan_then_view_and_export_without_rescan(menu, tmp_path, fake_scan):
    calls = fake_scan(scan_result(Severity.HIGH))
    output = menu("1", "", "3", "", "4", "", "q")
    assert len(calls) == 1
    assert "Title high" in output
    assert (tmp_path / ".securepipeline/reports/securepipeline-report.html").exists()


def test_menu_header_summarizes_last_scan(menu, fake_scan):
    fake_scan(scan_result(Severity.HIGH))
    output = menu("1", "", "q")
    assert "1 high" in output
    assert "just now" in output


def test_menu_results_without_scan_explains(menu):
    assert "run a scan first" in menu("3", "", "q")


@pytest.mark.parametrize(("answer", "installed"), [("", False), ("n", False), ("maybe", False), ("y", True)])
def test_menu_install_needs_explicit_yes(menu, monkeypatch, answer, installed):
    calls = []
    monkeypatch.setattr(menu_module, "print_tools_status", lambda: ["trivy"])
    monkeypatch.setattr(menu_module, "install_missing", lambda names: calls.append(names) or True)
    menu("5", answer, "", "q")
    assert bool(calls) is installed


def test_menu_settings_change_threshold_format_and_jobs(menu):
    output = menu("7", "1", "2", "3", "4", "", "q")
    assert "high" in output
    assert "html" in output


def test_menu_settings_apply_to_scan(menu, tmp_path, fake_scan):
    fake_scan(scan_result())
    menu("7", "2", "", "1", "", "q")
    assert (tmp_path / ".securepipeline/reports/securepipeline-report.html").exists()


def test_settings_cycle_wraps_around():
    assert menu_module._next_choice(("a", "b"), "b") == "a"


def test_update_targets_install_repository(menu, monkeypatch, tmp_path):
    repo = tmp_path / "installation"
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(actions, "__file__", str(repo / "securepipeline" / "cli" / "actions.py"))
    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        return CommandResult(command, 0, "Already up to date.\n")

    monkeypatch.setattr(actions, "run_command", run)
    assert "Already up to date." in menu("u", "", "q")
    assert calls == [["git", "-C", str(repo), "pull", "--ff-only"]]


def test_installed_binary_is_readable_and_executable_by_all(tmp_path):
    _write_executable(b"x", tmp_path / "tool")
    assert stat.S_IMODE((tmp_path / "tool").stat().st_mode) == 0o755
