"""SecurePipeline - Widget de progression animee."""

import sys
import time
import threading

from securepipeline.ui.display import (
    RESET, BOLD, DIM,
    CYAN, GREEN, GRAY, WHITE, DARK_GRAY, YELLOW,
    BLOCK_FULL, BLOCK_LIGHT, BAR_H, DOT, CHECK,
)


# Frames d'animation du spinner
SPINNER_FRAMES = ["[    ]", "[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]", "[    ]"]
SPINNER_FAST   = ["|", "/", "-", "\\"]


class ScanProgress:
    """Barre de progression animee pour le scan.

    Usage:
        with ScanProgress(total=5) as progress:
            for scanner in scanners:
                progress.update(scanner.info().name)
                # ... run scan ...
                progress.advance()
    """

    def __init__(self, total: int):
        self.total = total
        self.current = 0
        self.current_name = ""
        self._running = False
        self._thread: threading.Thread | None = None
        self._frame = 0
        self._start_time = 0.0

    def __enter__(self):
        self._start_time = time.time()
        self._running = True
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *args):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        # Effacer la ligne de progression
        sys.stdout.write(f"\r{' ' * 80}\r")
        sys.stdout.flush()

    def update(self, name: str) -> None:
        """Met a jour le nom du module en cours."""
        self.current_name = name

    def advance(self) -> None:
        """Avance d'une etape."""
        self.current += 1

    def _animate(self) -> None:
        """Thread d'animation."""
        while self._running:
            elapsed = time.time() - self._start_time
            frame = SPINNER_FAST[self._frame % len(SPINNER_FAST)]
            self._frame += 1

            # Barre de progression
            bar_width = 25
            if self.total > 0:
                filled = int((self.current / self.total) * bar_width)
            else:
                filled = 0
            empty = bar_width - filled
            bar = f"{GREEN}{BLOCK_FULL * filled}{DARK_GRAY}{BLOCK_LIGHT * empty}{RESET}"

            # Pourcentage
            pct = int((self.current / max(self.total, 1)) * 100)

            # Ligne de progression
            line = (
                f"\r  {CYAN}{frame}{RESET} "
                f"{bar} "
                f"{WHITE}{pct:3d}%{RESET} "
                f"{GRAY}{BAR_H}{RESET} "
                f"{WHITE}{self.current_name:<24}{RESET} "
                f"{DIM}{GRAY}({elapsed:.1f}s){RESET}"
            )

            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.12)


def print_progress_bar(current: int, total: int, label: str = "", width: int = 30) -> None:
    """Affiche une barre de progression statique.

    Args:
        current: Valeur actuelle.
        total: Valeur totale.
        label: Label a afficher.
        width: Largeur de la barre.
    """
    if total == 0:
        filled = 0
    else:
        filled = int((current / total) * width)
    empty = width - filled
    pct = int((current / max(total, 1)) * 100)

    bar = f"{GREEN}{BLOCK_FULL * filled}{DARK_GRAY}{BLOCK_LIGHT * empty}{RESET}"
    print(f"  {bar} {WHITE}{pct:3d}%{RESET} {GRAY}{label}{RESET}")


def print_elapsed_time(start_time: float) -> None:
    """Affiche le temps ecoule."""
    elapsed = time.time() - start_time
    minutes = int(elapsed // 60)
    seconds = elapsed % 60
    if minutes > 0:
        print(f"  {GRAY}{DOT} Temps ecoule: {minutes}m {seconds:.1f}s{RESET}")
    else:
        print(f"  {GRAY}{DOT} Temps ecoule: {seconds:.1f}s{RESET}")


def print_scan_complete(total_findings: int, duration: float) -> None:
    """Affiche un bandeau de fin de scan."""
    if total_findings == 0:
        color = GREEN
        msg = "Scan termine - Aucune vulnerabilite detectee"
    else:
        color = YELLOW if total_findings < 5 else CYAN
        msg = f"Scan termine - {total_findings} vulnerabilite(s) detectee(s)"

    print()
    print(f"  {color}{BOLD}{CHECK} {msg}{RESET}")
    print(f"  {GRAY}{DOT} Duree totale: {duration:.2f}s{RESET}")
    print()
