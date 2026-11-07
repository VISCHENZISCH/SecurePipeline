"""Tests for the live progress panel."""

import re

from securepipeline.ui.task_panel import (
    FAILED,
    FOUND,
    OK,
    RUNNING_MAX_PROGRESS,
    WARNING,
    TaskPanel,
    progress_bar,
    running_progress,
)
from securepipeline.ui.theme import CHECK, CROSS, SPINNER, WARN


def panel_output(capsys, live: bool) -> str:
    with TaskPanel("Scan", ["bandit", "semgrep", "trivy", "npm"], live=live) as panel:
        for name in panel.tasks:
            panel.start(name)
        panel.finish("bandit", OK, "no findings", 0.1)
        panel.finish("semgrep", FOUND, "2 findings", 0.2)
        panel.finish("trivy", WARNING, "not installed", 0.0)
        panel.finish("npm", FAILED, "timed out", 0.0)
    return capsys.readouterr().out


def test_progress_bar_fills_with_completed_tasks():
    assert progress_bar(0, 4).startswith("░" * 24)
    assert "50%" in progress_bar(2, 4)
    assert progress_bar(4, 4).startswith("█" * 24)
    assert "100%" in progress_bar(4, 4)


def test_empty_panel_does_not_divide_by_zero():
    assert "0%" in progress_bar(0, 0)


def test_tools_that_ran_get_a_check_even_with_findings(capsys):
    output = panel_output(capsys, live=False)
    assert re.search(rf"{re.escape(CHECK)} bandit .* no findings", output)
    assert re.search(rf"{re.escape(CHECK)} semgrep .* 2 findings", output)


def test_tools_that_did_not_run_get_no_check(capsys):
    output = panel_output(capsys, live=False)
    assert re.search(rf"{re.escape(WARN)} trivy .* not installed", output)
    assert re.search(rf"{re.escape(CROSS)} npm .* timed out", output)


def test_live_panel_ends_with_full_bar_and_restored_cursor(capsys):
    output = panel_output(capsys, live=True)
    assert "\033[?25l" in output
    assert output.endswith("\033[?25h")
    last_frame = output[output.rfind("Scan"):]
    assert "100%" in last_frame
    assert "4/4" in last_frame


def test_running_task_shows_spinner_and_elapsed_time(capsys):
    panel = TaskPanel("Scan", ["bandit"], live=True)
    panel.start("bandit")
    panel._draw()
    output = capsys.readouterr().out
    assert f"{SPINNER[0]} bandit" in output
    assert "running" in output
    assert "0%" in output


def test_running_progress_grows_but_never_claims_completion():
    assert running_progress(0) == 0
    assert running_progress(1) < running_progress(10) < running_progress(1000)
    assert running_progress(10**9) < RUNNING_MAX_PROGRESS + 1e-6


def test_bar_moves_while_a_task_runs_and_counter_stays_honest(capsys):
    panel = TaskPanel("Scan", ["a", "b"], live=True)
    panel.start("a")
    panel.tasks["a"].started_at -= 60
    assert 0 < panel._progress() < 1
    panel._draw()
    output = capsys.readouterr().out
    assert "0/2" in output
    assert "100%" not in output


def test_finished_tasks_count_fully_in_the_progress():
    panel = TaskPanel("Scan", ["a", "b"], live=True)
    panel.finish("a", OK, "", 0.1)
    panel.finish("b", FAILED, "", 0.1)
    assert panel._progress() == 2
