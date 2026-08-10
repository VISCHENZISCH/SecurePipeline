"""SecurePipeline - Widget de progression animee."""

import sys
import threading
import time

from securepipeline.ui.display import (
    BLOCK_FULL,
    BLOCK_LIGHT,
    BOLD,
    CHECK,
    CYAN,
    DARK_GRAY,
    DEB_RED,
    DIM_GREEN,
    DOT,
    GRAY,
    GREEN,
    RESET,
    WHITE,
    YELLOW,
)

# Frames d'animation du spinner
SPINNER_FRAMES = ["[    ]", "[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]", "[    ]"]
SPINNER_FAST   = ["|", "/", "-", "\\"]


class ScanProgress:
    """Barre de progression animee pour le scan."""

    def __init__(self, scanner_names: list[str]):
        self.scanner_names = scanner_names
        self.total = len(scanner_names)
        self.completed = 0
        self.statuses = {name: "PENDING" for name in scanner_names}
        self._running = False
        self._thread: threading.Thread | None = None
        self._frame = 0
        self._start_time = 0.0
        self._lines_drawn = 0
        self._suppress_initial = True

    def start_scanner(self, name: str) -> None:
        """Marque un scanner comme demarre."""
        self.statuses[name] = "RUNNING"
        self._suppress_initial = False  # Dès qu'un scanner démarre on peut afficher

    def finish_scanner(self, name: str, status: str) -> None:
        """Marque un scanner comme termine."""
        self.statuses[name] = status
        self.completed += 1

    def __enter__(self):
        self._start_time = time.time()
        self._running = True
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *args):
        self._running = False
        self._suppress_initial = False  # Toujours afficher le bilan final
        if self._thread:
            self._thread.join(timeout=1)
        self._draw()  # Dernier dessin garanti (100 %)
        print()       # Nouvelle ligne à la fin

    def _animate(self) -> None:
        """Thread d'animation."""
        while self._running:
            if not self._suppress_initial:
                self._draw()
            self._frame += 1
            time.sleep(0.12)

    def _draw(self) -> None:
        """Dessine la progression dans le terminal."""
        lines = []
        lines.append(f"  {CYAN}Scanning repository{RESET}")
        lines.append("")

        # Barre de progression globale
        bar_width = 25
        if self.total > 0:
            filled = int((self.completed / self.total) * bar_width)
        else:
            filled = 0
        empty = bar_width - filled
        pct = int((self.completed / max(self.total, 1)) * 100)
        bar = f"{DIM_GREEN}{BLOCK_FULL * filled}{DARK_GRAY}{BLOCK_LIGHT * empty}{RESET}"
        
        lines.append(f"  {bar} {WHITE}{pct}%{RESET}")
        lines.append("")

        frame_char = SPINNER_FAST[self._frame % len(SPINNER_FAST)]

        # Liste des scanners
        for name in self.scanner_names:
            status = self.statuses.get(name, "PENDING")
            if status == "PENDING":
                continue # On n'affiche pas encore ceux qui n'ont pas commence
                
            name_padded = name + "." * max(0, 20 - len(name))
            
            if status == "RUNNING":
                color = CYAN
                status_text = f"{frame_char} RUNNING"
            elif status == "OK":
                color = GREEN
                status_text = "OK"
            elif status.startswith("SKIP"):
                color = GRAY
                status_text = status
            elif status == "ERR":
                color = DEB_RED
                status_text = "ERROR"
            else:
                color = WHITE
                status_text = status
                
            lines.append(f"  {WHITE}{name_padded}{RESET}{color}{status_text}{RESET}")

        # Effacement et redessin
        out = ""
        if self._lines_drawn > 0:
            out += f"\033[{self._lines_drawn}A" # Remonte le curseur
        
        for line in lines:
            out += f"\033[2K{line}\n" # Efface la ligne et ecrit
            
        sys.stdout.write(out)
        sys.stdout.flush()
        self._lines_drawn = len(lines)


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
