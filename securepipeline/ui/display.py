"""SecurePipeline - Affichage CLI interactif."""

import shutil
import sys

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

def rgb(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"

def bg_rgb(r: int, g: int, b: int) -> str:
    return f"\033[48;2;{r};{g};{b}m"

BACKGROUND = bg_rgb(30, 30, 30)
SURFACE    = bg_rgb(37, 37, 38)
DEB_RED    = rgb(239, 41, 41)
CYAN       = rgb(52, 226, 226)
WHITE      = rgb(230, 230, 230)
GRAY       = rgb(157, 165, 180)
YELLOW     = rgb(252, 233, 79)
BLUE       = rgb(114, 159, 207)
GREEN      = rgb(138, 226, 52)
MAGENTA    = rgb(173, 127, 168)
LOGO_COLOR = CYAN

SEV_COLORS = {
    "critical": DEB_RED,
    "high":     YELLOW,
    "medium":   BLUE,
    "low":      GRAY,
    "info":     GREEN,
}

SEV_LABELS = {
    "critical": "CRITIQUE",
    "high":     "ELEVE",
    "medium":   "MOYEN",
    "low":      "FAIBLE",
    "info":     "INFO",
}

PROJECT_LOGO = (
    "   _____                              ____  _            ___          ",
    "  / ___/___  _______  __________     / __ \\(_)___  ___  / (_)___  ___ ",
    "  \\__ \\/ _ \\/ ___/ / / / ___/ _ \\   / /_/ / / __ \\/ _ \\/ / / __ \\/ _ \\",
    " ___/ /  __/ /__/ /_/ / /  /  __/  / ____/ / /_/ /  __/ / / / / /  __/",
    "/____/\\___/\\___/\\__,_/_/   \\___/  /_/   /_/ .___/\\___/_/_/_/ /_/\\___/ ",
    "                                         /_/",
)


def term_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns

def center(text: str, width: int = 0) -> str:
    if width == 0:
        width = term_width()
    import re
    visible = re.sub(r'\033\[[^m]*m', '', text)
    pad = max(0, (width - len(visible)) // 2)
    return " " * pad + text

def clear_screen() -> None:
    sys.stdout.write(f"{RESET}\033[2J\033[3J\033[H")
    sys.stdout.flush()

def hline(char: str = "-", width: int = 0, color: str = GRAY) -> str:
    if width == 0:
        width = min(term_width() - 4, 72)
    return f"  {color}{char * width}{RESET}"


def print_home_screen() -> None:
    """Affiche l'accueil du CLI."""
    print()
    if term_width() >= 78:
        for line in PROJECT_LOGO:
            print(f"  {BOLD}{LOGO_COLOR}{line}{RESET}")
    else:
        print(f"  {BOLD}{LOGO_COLOR}SecurePipeline{RESET}")
    print(f"  {GRAY}Scanner DevSecOps multi-stack{RESET}")
    print()
    print(f"  {WHITE}Projet courant :{RESET} {GRAY}.{RESET}")
    print(f"  {WHITE}Mode           :{RESET} {GRAY}interactif{RESET}")
    print(f"  {WHITE}Rapports       :{RESET} {GRAY}.securepipeline/reports{RESET}")
    print()


def print_menu() -> None:
    """Affiche le menu interactif principal."""
    print(f"  {BLUE}Scan{RESET}")
    print(f"    {GREEN}[1]{RESET} Scanner un projet")
    print(f"    {GREEN}[2]{RESET} Afficher un exemple CI/CD")
    print()

    print(f"  {BLUE}Rapports{RESET}")
    print(f"    {GREEN}[3]{RESET} Voir le dernier rapport Markdown")
    print(f"    {GREEN}[4]{RESET} Generer un rapport HTML")
    print()

    print(f"  {BLUE}Projet{RESET}")
    print(f"    {GREEN}[5]{RESET} Configuration")
    print(f"    {GRAY}[0]{RESET} Quitter")
    print()


def get_prompt() -> str:
    """Retourne la chaine du prompt interactif principal."""
    return (
        f"{GREEN}securepipeline{RESET}:"
        f"{BLUE}~/menu{RESET}$ "
    )


def get_path_prompt(default: str = ".") -> str:
    """Retourne le prompt de saisie d'un chemin projet."""
    return (
        f"{GREEN}securepipeline{RESET}:"
        f"{BLUE}~/scan{RESET}$ "
        f"{GRAY}path [{default}]:{RESET} "
    )


def get_continue_prompt() -> str:
    """Retourne le prompt de pause."""
    return f"\n{GRAY}Appuyez sur Entree pour continuer{RESET}"


def print_section(title: str) -> None:
    print(f"\n  {CYAN}{title}{RESET}")
    print(hline(width=len(title), color=CYAN))


def print_stacks(stacks: list[str]) -> None:
    if not stacks:
        print(f"  {DEB_RED}Aucune stack technologique detectee.{RESET}")
        return
    print(f"  {WHITE}Stacks:{RESET} {GREEN}{', '.join(stacks)}{RESET}\n")


def print_scanner_start(name: str) -> None:
    print(f"  {WHITE}{name:<24}{RESET}", end="", flush=True)


def print_scanner_done(count: int) -> None:
    if count == 0:
        print(f"{GREEN}OK{RESET}")
    else:
        color = DEB_RED if count >= 5 else YELLOW
        print(f"{color}{count} finding(s){RESET}")


def print_scanner_skip(reason: str) -> None:
    print(f"{GRAY}SKIP - {reason}{RESET}")


def print_summary(stats: dict[str, int], total: int, duration: float) -> None:
    print_section("Resume du Scan")

    for sev in ["critical", "high", "medium", "low", "info"]:
        label = SEV_LABELS[sev]
        color = SEV_COLORS[sev]
        print(f"  {label:<10} {color}{stats.get(sev, 0)}{RESET}")
    
    if total == 0:
        print(f"\n  {GREEN}Aucune vulnerabilite detectee.{RESET}")
    else:
        color = DEB_RED if stats.get("critical", 0) > 0 else YELLOW
        print(f"\n  {color}Total: {total} vulnerabilite(s).{RESET}")
        
    print(f"  {GRAY}Duree: {duration:.2f}s{RESET}\n")


def print_findings_table(findings: list) -> None:
    if not findings:
        return
    print_section("Artefacts / Vulnerabilites")
    
    for f in findings:
        sev_color = SEV_COLORS.get(f.severity.value, GRAY)
        title = f.title[:50] + "..." if len(f.title) > 50 else f.title
        rule = f.rule_id
        file_path = f.file_path if f.file_path else "Global"
        
        print(f"  {sev_color}{f.severity.value.upper():<8}{RESET} {WHITE}{rule:15}{RESET} {GRAY}|{RESET} {WHITE}{title:50}{RESET} {GRAY}|{RESET} {CYAN}{file_path}{RESET}")
    print()
