"""Live progress of parallel tasks."""

import sys
import threading
import time
from dataclasses import dataclass
from typing import Self

from securepipeline.ui.console import term_width, truncate
from securepipeline.ui.theme import (
    BOLD,
    CHECK,
    CROSS,
    CYAN,
    DARK_GRAY,
    DOT,
    GRAY,
    GREEN,
    ORANGE,
    RED,
    RESET,
    WARN,
    WHITE,
    YELLOW,
)

SPINNER = "|/-\\"
REFRESH_SECONDS = 0.1
BAR_WIDTH = 24
BAR_FILLED = "█"
BAR_EMPTY = "░"
# A running task fills up to this share of its slot, so the bar keeps moving
# between completions without ever claiming that the task is done.
RUNNING_MAX_PROGRESS = 0.9
RUNNING_PROGRESS_RATE = 0.17

PENDING = "pending"
RUNNING = "running"
OK = "ok"
FOUND = "found"
NEUTRAL = "neutral"
WARNING = "warning"
FAILED = "failed"

# (symbol color, symbol, note color): a tool that ran gets a check, even with findings.
_STATE_STYLES = {
    OK: (GREEN, CHECK, GREEN),
    FOUND: (GREEN, CHECK, ORANGE),
    NEUTRAL: (GRAY, DOT, GRAY),
    WARNING: (YELLOW, WARN, YELLOW),
    FAILED: (RED, CROSS, RED),
}


def running_progress(elapsed: float) -> float:
    return RUNNING_MAX_PROGRESS * (1 - 1 / (1 + elapsed * RUNNING_PROGRESS_RATE))


def progress_bar(done: float, total: int) -> str:
    filled = int(BAR_WIDTH * done / max(total, 1))
    percent = int(100 * done / max(total, 1))
    bar = f"{GREEN}{BAR_FILLED * filled}{DARK_GRAY}{BAR_EMPTY * (BAR_WIDTH - filled)}{RESET}"
    return f"{bar} {WHITE}{percent:3d}%{RESET}"


@dataclass
class _Task:
    state: str = PENDING
    note: str = ""
    started_at: float = 0.0
    duration: float = 0.0


class TaskPanel:
    """Show the progress of tasks.

    In a terminal the panel redraws in place. Elsewhere (CI, redirection) it prints
    one line per finished task, so that logs stay readable.
    """

    def __init__(self, title: str, names: list[str], live: bool | None = None, quiet: bool = False):
        self.title = title
        self.tasks = {name: _Task() for name in names}
        self.live = sys.stdout.isatty() if live is None else live
        self.quiet = quiet
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._frame = 0
        self._lines_drawn = 0
        self._name_width = max((len(name) for name in names), default=0)
        self._started_at = 0.0

    def start(self, name: str) -> None:
        with self._lock:
            task = self.tasks[name]
            task.state = RUNNING
            task.started_at = time.perf_counter()

    def finish(self, name: str, state: str, note: str = "", duration: float | None = None) -> None:
        with self._lock:
            task = self.tasks[name]
            task.state = state
            task.note = note
            if duration is not None:
                task.duration = duration
            elif task.started_at:
                task.duration = time.perf_counter() - task.started_at
            if not self.live and not self.quiet:
                print(self._row(name, task), flush=True)

    def __enter__(self) -> Self:
        self._started_at = time.perf_counter()
        if self.quiet:
            return self
        if self.live:
            sys.stdout.write("\033[?25l")  # Hide the cursor during the animation.
            self._thread = threading.Thread(target=self._animate, daemon=True)
            self._thread.start()
        else:
            print(f"  {self.title}", flush=True)
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        if self.live and not self.quiet:
            self._draw(final=True)
            sys.stdout.write("\033[?25h")
            sys.stdout.flush()

    def _animate(self) -> None:
        while not self._stop.is_set():
            self._draw()
            self._frame += 1
            self._stop.wait(REFRESH_SECONDS)

    def _row(self, name: str, task: _Task) -> str:
        label = f"{WHITE}{name:<{self._name_width}}{RESET}"
        if task.state == PENDING:
            return f"  {DARK_GRAY}{DOT}{RESET} {GRAY}{name:<{self._name_width}}  waiting{RESET}"
        if task.state == RUNNING:
            spin = SPINNER[self._frame % len(SPINNER)]
            elapsed = time.perf_counter() - task.started_at
            return f"  {CYAN}{spin}{RESET} {label}  {GRAY}running {elapsed:5.1f}s{RESET}"

        color, symbol, note_color = _STATE_STYLES[task.state]
        # A line must never wrap: that would break the redraw.
        room = term_width() - self._name_width - 16
        return (
            f"  {color}{symbol}{RESET} {label}  {GRAY}{task.duration:5.1f}s{RESET}"
            f"  {note_color}{truncate(task.note, room)}{RESET}"
        )

    def _progress(self) -> float:
        now = time.perf_counter()
        return sum(
            0.0 if task.state == PENDING
            else running_progress(now - task.started_at) if task.state == RUNNING
            else 1.0
            for task in self.tasks.values()
        )

    def _draw(self, final: bool = False) -> None:
        with self._lock:
            finished = sum(t.state not in (PENDING, RUNNING) for t in self.tasks.values())
            elapsed = time.perf_counter() - self._started_at
            spin = " " if final else SPINNER[self._frame % len(SPINNER)]
            head = (
                f"  {CYAN}{BOLD}{self.title}{RESET} {CYAN}{spin}{RESET} "
                f"{progress_bar(self._progress(), len(self.tasks))} "
                f"{GRAY}{finished}/{len(self.tasks)} {DOT} {elapsed:.1f}s{RESET}"
            )
            lines = [head, *(self._row(name, task) for name, task in self.tasks.items())]

        up = f"\033[{self._lines_drawn}A" if self._lines_drawn else ""
        sys.stdout.write(up + "".join(f"\033[2K{line}\n" for line in lines))
        sys.stdout.flush()
        self._lines_drawn = len(lines)
