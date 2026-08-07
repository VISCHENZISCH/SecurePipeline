"""SecurePipeline - Affichage CLI """

import os
import re
import shutil
import sys
import time
from datetime import datetime

# Codes ANSI / True Color 

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
ITALIC  = "\033[3m"
UNDERLINE = "\033[4m"
BLINK   = "\033[5m"
REVERSE = "\033[7m"
HIDDEN  = "\033[8m"


def rgb(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"

def bg_rgb(r: int, g: int, b: int) -> str:
    return f"\033[48;2;{r};{g};{b}m"


#Palette de couleurs 

#Couleurs principales
DEB_RED    = rgb(255, 69, 58)       # Rouge vif (critiques)
COSIT_RED  = rgb(205, 6, 25)       # Rouge vif (critiques)
ORANGE     = rgb(255, 159, 10)      # Orange (high)
YELLOW     = rgb(255, 214, 10)      # Jaune (medium)
GREEN      = rgb(48, 209, 88)       # Vert (succès, OK)
CYAN       = rgb(0, 230, 230)       # Cyan néon (accent principal)
BLUE       = rgb(100, 160, 255)     # Bleu doux (sections)
MAGENTA    = rgb(191, 90, 242)      # Magenta (accent)
WHITE      = rgb(230, 230, 230)     # Blanc doux
GRAY       = rgb(120, 120, 130)     # Gris neutre
DARK_GRAY  = rgb(72, 72, 78)       # Gris foncé (bordures)
LIGHT_CYAN = rgb(130, 230, 230)    # Cyan clair (second accent)

# Backgrounds
BG_SURFACE = bg_rgb(25, 25, 30)
BG_HEADER  = bg_rgb(30, 35, 45)
BG_CRIT    = bg_rgb(80, 20, 20)
BG_HIGH    = bg_rgb(80, 50, 10)
BG_MED     = bg_rgb(60, 55, 15)
BG_LOW     = bg_rgb(25, 35, 50)
BG_INFO    = bg_rgb(20, 40, 25)

# Couleurs de sévérité
SEV_COLORS = {
    "critical": DEB_RED,
    "high":     ORANGE,
    "medium":   YELLOW,
    "low":      BLUE,
    "info":     GREEN,
}

SEV_BG = {
    "critical": BG_CRIT,
    "high":     BG_HIGH,
    "medium":   BG_MED,
    "low":      BG_LOW,
    "info":     BG_INFO,
}

SEV_LABELS = {
    "critical": "CRITIQUE",
    "high":     "ELEVE",
    "medium":   "MOYEN",
    "low":      "FAIBLE",
    "info":     "INFO",
}

SEV_INDICATORS = {
    "critical": f"{DEB_RED}{BOLD}[!!!]{RESET}",
    "high":     f"{ORANGE}{BOLD}[!!]{RESET}",
    "medium":   f"{YELLOW}[!]{RESET}",
    "low":      f"{BLUE}[-]{RESET}",
    "info":     f"{GREEN}[i]{RESET}",
}


# display.py::Logo ASCII avec dégradé -------------------------------------------------#

PROJECT_LOGO_LINES = (
    "   _____                              ____  _            ___          ",
    "  / ___/___  _______  __________     / __ \\(_)___  ___  / (_)___  ___ ",
    "  \\__ \\/ _ \\/ ___/ / / / ___/ _ \\   / /_/ / / __ \\/ _ \\/ / / __ \\/ _ \\",
    " ___/ /  __/ /__/ /_/ / /  /  __/  / ____/ / /_/ /  __/ / / / / /  __/",
    "/____/\\___/\\___/\\__,_/_/   \\___/  /_/   /_/ .___/\\___/_/_/_/ /_/\\___/ ",
    "                                         /_/",
)

# Dégradé cyan -> vert (lignes du logo)
LOGO_GRADIENT = [
    rgb(174, 19, 35),     # Cyan pur
    rgb(143, 1, 16),
    rgb(224, 7, 29),
    rgb(255, 0, 25),
    rgb(212, 24, 43),
    rgb(205, 6, 25),     # Vert
]

SUBTITLE_TEXT = "Scanner DevSecOps multi-stack"
VERSION_LINE  = "v0.1.0"


# display.py::Utilitaires de base ---------------------------------------------------------#

def term_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns

def visible_len(text: str) -> int:
    """Longueur visible (sans les codes ANSI)."""
    return len(re.sub(r'\033\[[^m]*m', '', text))

def center(text: str, width: int = 0) -> str:
    if width == 0:
        width = term_width()
    pad = max(0, (width - visible_len(text)) // 2)
    return " " * pad + text

def clear_screen() -> None:
    sys.stdout.write(f"{RESET}\033[2J\033[3J\033[H")
    sys.stdout.flush()


# display.py::Caractères de bordure Unicode (box-drawing)---------------------------------#

BOX_TL = "\u250c"   # ┌
BOX_TR = "\u2510"   # ┐
BOX_BL = "\u2514"   # └
BOX_BR = "\u2518"   # ┘
BOX_H  = "\u2500"   # ─
BOX_V  = "\u2502"   # │
BOX_LT = "\u251c"   # ├
BOX_RT = "\u2524"   # ┤
BOX_BT = "\u2534"   # ┴
BOX_TT = "\u252c"   # ┬
BOX_CR = "\u253c"   # ┼

# Variantes doubles
DBL_H = "\u2550"   # ═
DBL_V = "\u2551"   # ║
DBL_TL = "\u2554"  # ╔
DBL_TR = "\u2557"  # ╗
DBL_BL = "\u255a"  # ╚
DBL_BR = "\u255d"  # ╝

# Blocs et barres
BLOCK_FULL  = "\u2588"  # █
BLOCK_LIGHT = "\u2591"  # ░
BLOCK_MED   = "\u2592"  # ▒
BLOCK_HEAVY = "\u2593"  # ▓
BAR_H       = "\u2501"  # ━ (heavy horizontal)
DOT         = "\u2022"  # •
ARROW_R     = "\u25b6"  # ▶
ARROW_D     = "\u25bc"  # ▼
CHECK       = "\u2714"  # ✔
CROSS       = "\u2718"  # ✘
CIRCLE_F    = "\u25cf"  # ●
CIRCLE_E    = "\u25cb"  # ○
DIAMOND     = "\u25c6"  # ◆


# display.py::Animations et effets ---------------------------------------------------------#

def typing_print(text: str, delay: float = 0.008) -> None:
    """Effet de frappe progressive."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")

def typing_line(text: str, delay: float = 0.003) -> None:
    """Comme typing_print mais plus rapide, sans newline a la fin."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)


# display.py::Composants de bordure ------------------------------------------#

def box_top(width: int, color: str = COSIT_RED) -> str:
    return f"  {color}{BOX_TL}{BOX_H * width}{BOX_TR}{RESET}"

def box_bottom(width: int, color: str = COSIT_RED) -> str:
    return f"  {color}{BOX_BL}{BOX_H * width}{BOX_BR}{RESET}"

def box_mid(width: int, color: str = DARK_GRAY) -> str:
    return f"  {color}{BOX_LT}{BOX_H * width}{BOX_RT}{RESET}"

def box_row(content: str, width: int, color: str = COSIT_RED) -> str:
    pad = width - visible_len(content)
    return f"  {color}{BOX_V}{RESET} {content}{' ' * max(0, pad - 1)}{color}{BOX_V}{RESET}"

def hline(char: str = BOX_H, width: int = 0, color: str = DARK_GRAY) -> str:
    if width == 0:
        width = min(term_width() - 4, 72)
    return f"  {color}{char * width}{RESET}"

def heavy_hline(width: int = 0, color: str = CYAN) -> str:
    if width == 0:
        width = min(term_width() - 4, 72)
    return f"  {color}{BAR_H * width}{RESET}"


# display.py::Ecran d'accueil ---------------------------------------------------------#

def print_home_screen() -> None:
    """Affiche l'ecran d'accueil avec logo en degrade et infos systeme."""
    w = min(term_width() - 4, 74)

    print()

    # display.py::Logo ASCII avec dégradé -------------------------------------------------#

    if term_width() >= 78:
        for i, line in enumerate(PROJECT_LOGO_LINES):
            color = LOGO_GRADIENT[i % len(LOGO_GRADIENT)]
            print(f"  {BOLD}{color}{line}{RESET}")
    else:
        print(f"  {BOLD}{CYAN}SecurePipeline{RESET}")

    # Sous-titre centré
    print()
    subtitle = f"{GRAY}{ITALIC}  {SUBTITLE_TEXT}{RESET}  {DARK_GRAY}{DOT}{RESET}  {DIM}{GRAY}{VERSION_LINE}{RESET}"
    print(f"  {subtitle}")

    # Ligne de séparation dégradée
    #print(heavy_hline(w, DARK_GRAY))
    print()

    # Informations système dans un cadre
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cwd = os.path.basename(os.getcwd()) or "."

    print(f"  {COSIT_RED}{CIRCLE_F}{RESET} {WHITE}Projet   {RESET} {GRAY}{BOX_V}{RESET} {CYAN}{cwd}{RESET}")
    print(f"  {COSIT_RED}{CIRCLE_F}{RESET} {WHITE}Mode     {RESET} {GRAY}{BOX_V}{RESET} {CYAN}interactif{RESET}")
    print(f"  {COSIT_RED}{CIRCLE_F}{RESET} {WHITE}Rapports {RESET} {GRAY}{BOX_V}{RESET} {CYAN}reports{RESET}")
    print(f"  {COSIT_RED}{CIRCLE_F}{RESET} {WHITE}Date     {RESET} {GRAY}{BOX_V}{RESET} {CYAN}{now}{RESET}")
    print()


# display.py::Menu principal ──────────────────────────────────────────────────────────

def print_menu() -> None:
    """Affiche le menu interactif en style arborescence."""

    # Caractères d'arborescence avec couleur
    pipe  = f"{COSIT_RED}{BOX_V}{RESET}"
    tee   = f"{COSIT_RED}{BOX_LT}{BOX_H}{BOX_H}{RESET}"
    elbow = f"{COSIT_RED}{BOX_BL}{BOX_H}{BOX_H}{RESET}"

    # Section Scan
    print(f"  {tee} {BLUE}{BOLD}Scan{RESET}")
    print(f"  {pipe}   {tee} {GREEN}[1]{RESET} {WHITE}Scanner un projet{RESET}")
    print(f"  {pipe}   {tee} {GREEN}[2]{RESET} {WHITE}Detecter les stacks d'un projet{RESET}")
    print(f"  {pipe}   {elbow} {GREEN}[3]{RESET} {WHITE}Exemple de commande CI/CD{RESET}")
    print(f"  {pipe}")

    # Section Rapports
    print(f"  {tee} {BLUE}{BOLD}Rapports{RESET}")
    print(f"  {pipe}   {tee} {GREEN}[4]{RESET} {WHITE}Voir le dernier rapport{RESET}")
    print(f"  {pipe}   {elbow} {GREEN}[5]{RESET} {WHITE}Generer un rapport HTML{RESET}")
    print(f"  {pipe}")

    # Section Outils
    print(f"  {tee} {BLUE}{BOLD}Outils{RESET}")
    print(f"  {pipe}   {tee} {GREEN}[6]{RESET} {WHITE}Verifier les prerequis{RESET}")
    print(f"  {pipe}   {elbow} {GREEN}[7]{RESET} {WHITE}Lister les modules de scan{RESET}")
    print(f"  {pipe}")

    # Section Projet
    print(f"  {elbow} {BLUE}{BOLD}Projet{RESET}")
    print(f"      {tee} {GREEN}[8]{RESET} {WHITE}Configuration{RESET}")
    print(f"      {tee} {GREEN}[9]{RESET} {WHITE}Aide / A propos{RESET}")
    print(f"      {elbow} {GREEN}[0]{RESET} {GRAY}Quitter{RESET}")

    print()


# display.py::Prompts ------------------------------------------------------------------#

def get_prompt() -> str:
    """Prompt principal style terminal cyber."""
    now = datetime.now().strftime("%H:%M:%S")
    return (
        f"{COSIT_RED}[{DARK_GRAY}{now}{COSIT_RED}]{RESET} "
        f"{GREEN}sec{RESET}{COSIT_RED}@{RESET}{CYAN}pipeline{RESET}"
        f"{COSIT_RED}:{RESET}{BLUE}~/menu{RESET}"
        f"{COSIT_RED}${RESET} "
    )


def get_path_prompt(default: str = ".") -> str:
    """Prompt de saisie d'un chemin."""
    now = datetime.now().strftime("%H:%M:%S")
    return (
        f"{COSIT_RED}[{GRAY}{now}{COSIT_RED}]{RESET} "
        f"{GREEN}sec{RESET}{COSIT_RED}@{RESET}{CYAN}pipeline{RESET}"
        f"{COSIT_RED}:{RESET}{BLUE}~/scan{RESET}"
        f"{COSIT_RED}${RESET} {GRAY}path [{default}]:{RESET} "
        
    )


def get_continue_prompt() -> str:
    """Prompt de pause."""
    return f"\n  {DARK_GRAY}{BAR_H * 3}{RESET} {GRAY}Appuyez sur Entree pour continuer{RESET} {DARK_GRAY}{BAR_H * 3}{RESET}"


# display.py::Sections et titres ------------------------------------------------#

def print_section(title: str) -> None:
    """Affiche un titre de section stylise."""
    w = max(len(title) + 4, 30)
    print()
    print(f"  {CYAN}{BOLD}{ARROW_R}{RESET} {CYAN}{BOLD}{title}{RESET}")
    print(f"  {CYAN}{BAR_H * w}{RESET}")


def print_subsection(title: str) -> None:
    """Affiche un sous-titre."""
    print(f"\n  {BLUE}{DOT}{RESET} {BLUE}{title}{RESET}")


# display.py::Affichage des stacks ------------------------------------------------#

def print_stacks(stacks: list[str]) -> None:
    """Affiche les stacks detectees avec indicateurs visuels."""
    if not stacks:
        print(f"  {DEB_RED}{CROSS} Aucune stack technologique detectee.{RESET}")
        return

    print(f"  {WHITE}Stacks detectees :{RESET}")
    for stack in stacks:
        print(f"    {GREEN}{CIRCLE_F}{RESET} {WHITE}{stack}{RESET}")
    print()


# display.py::Progression du scan ------------------------------------------------#

def print_scanner_start(name: str) -> None:
    """Affiche le debut d'un scanner avec indicateur."""
    label = f"{GRAY}{DIAMOND}{RESET} {WHITE}{name:<24}{RESET}"
    print(f"  {label}", end="", flush=True)


def print_scanner_done(count: int) -> None:
    """Affiche le resultat d'un scanner termine."""
    if count == 0:
        print(f" {GREEN}{CHECK} OK{RESET}")
    else:
        color = DEB_RED if count >= 5 else ORANGE if count >= 2 else YELLOW
        print(f" {color}{count} finding(s){RESET}")


def print_scanner_skip(reason: str) -> None:
    """Affiche un scanner ignore."""
    print(f" {DARK_GRAY}SKIP {GRAY}{BOX_H} {reason}{RESET}")


# display.py::Resume du scan ------------------------------------------------#

def _severity_bar(count: int, total: int, color: str, width: int = 20) -> str:
    """Genere une barre visuelle pour une severite."""
    if total == 0:
        filled = 0
    else:
        filled = max(0, min(width, int((count / total) * width)))
    empty = width - filled
    return f"{color}{BLOCK_FULL * filled}{DARK_GRAY}{BLOCK_LIGHT * empty}{RESET}"


def print_summary(stats: dict[str, int], total: int, duration: float) -> None:
    """Affiche le resume du scan avec barres visuelles."""
    print_section("Resume du Scan")
    print()

    bar_width = 25

    for sev in ["critical", "high", "medium", "low", "info"]:
        label = SEV_LABELS[sev]
        color = SEV_COLORS[sev]
        count = stats.get(sev, 0)
        bar = _severity_bar(count, max(total, 1), color, bar_width)
        indicator = SEV_INDICATORS[sev]
        print(f"  {indicator} {color}{label:<10}{RESET} {bar} {WHITE}{count}{RESET}")

    print()

    if total == 0:
        print(f"  {GREEN}{CHECK} Aucune vulnerabilite detectee.{RESET}")
    else:
        color = DEB_RED if stats.get("critical", 0) > 0 else ORANGE if stats.get("high", 0) > 0 else YELLOW
        print(f"  {color}{BOLD}Total: {total} vulnerabilite(s) detectee(s){RESET}")

    print(f"  {GRAY}Duree: {duration:.2f}s{RESET}\n")


# display.py::Tableau de findings ------------------------------------------------#

def print_findings_table(findings: list) -> None:
    """Affiche les findings dans un tableau avec bordures Unicode."""
    if not findings:
        return

    print_section("Detail des Vulnerabilites")
    print()

    # En-tête
    col_sev   = 10
    col_rule  = 18
    col_title = 42
    col_file  = 25
    total_w   = col_sev + col_rule + col_title + col_file + 9  # separateurs

    # Ligne d'en-tête
    header = (
        f"  {DARK_GRAY}{BOX_TL}{BOX_H * (col_sev + 2)}{BOX_TT}"
        f"{BOX_H * (col_rule + 2)}{BOX_TT}"
        f"{BOX_H * (col_title + 2)}{BOX_TT}"
        f"{BOX_H * (col_file + 2)}{BOX_TR}{RESET}"
    )
    print(header)

    header_text = (
        f"  {DARK_GRAY}{BOX_V}{RESET} {BOLD}{WHITE}{'SEVERITE':<{col_sev}}{RESET} "
        f"{DARK_GRAY}{BOX_V}{RESET} {BOLD}{WHITE}{'REGLE':<{col_rule}}{RESET} "
        f"{DARK_GRAY}{BOX_V}{RESET} {BOLD}{WHITE}{'TITRE':<{col_title}}{RESET} "
        f"{DARK_GRAY}{BOX_V}{RESET} {BOLD}{WHITE}{'FICHIER':<{col_file}}{RESET} "
        f"{DARK_GRAY}{BOX_V}{RESET}"
    )
    print(header_text)

    sep = (
        f"  {DARK_GRAY}{BOX_LT}{BOX_H * (col_sev + 2)}{BOX_CR}"
        f"{BOX_H * (col_rule + 2)}{BOX_CR}"
        f"{BOX_H * (col_title + 2)}{BOX_CR}"
        f"{BOX_H * (col_file + 2)}{BOX_RT}{RESET}"
    )
    print(sep)

    # Lignes
    for f in findings:
        sev_color = SEV_COLORS.get(f.severity.value, GRAY)
        sev_bg    = SEV_BG.get(f.severity.value, "")
        sev_text  = SEV_LABELS.get(f.severity.value, f.severity.value.upper())

        title = f.title[:col_title - 3] + "..." if len(f.title) > col_title else f.title
        rule = f.rule_id[:col_rule] if len(f.rule_id) > col_rule else f.rule_id
        file_path = f.file_path if f.file_path else "Global"
        if len(file_path) > col_file:
            file_path = "..." + file_path[-(col_file - 3):]

        row = (
            f"  {DARK_GRAY}{BOX_V}{RESET} {sev_bg}{sev_color}{BOLD}{sev_text:<{col_sev}}{RESET} "
            f"{DARK_GRAY}{BOX_V}{RESET} {WHITE}{rule:<{col_rule}}{RESET} "
            f"{DARK_GRAY}{BOX_V}{RESET} {GRAY}{title:<{col_title}}{RESET} "
            f"{DARK_GRAY}{BOX_V}{RESET} {CYAN}{file_path:<{col_file}}{RESET} "
            f"{DARK_GRAY}{BOX_V}{RESET}"
        )
        print(row)

    # display.py::footer - Ligne de fermeture---------------------------------------------#
    footer = (
        f"  {DARK_GRAY}{BOX_BL}{BOX_H * (col_sev + 2)}{BOX_BT}"
        f"{BOX_H * (col_rule + 2)}{BOX_BT}"
        f"{BOX_H * (col_title + 2)}{BOX_BT}"
        f"{BOX_H * (col_file + 2)}{BOX_BR}{RESET}"
    )
    print(footer)
    print()


# display.py::Configuration ----------------------------------------------------#

def print_config(config) -> None:
    """Affiche la configuration actuelle."""
    print_section("Configuration")
    print()
    w = 40

    print(box_top(w, DARK_GRAY))
    print(box_row(f"{WHITE}Seuil d'echec  {GRAY}{BOX_V}{RESET} {CYAN}{config.fail_on}{RESET}", w, DARK_GRAY))
    print(box_row(f"{WHITE}Format rapport {GRAY}{BOX_V}{RESET} {CYAN}{config.output_format}{RESET}", w, DARK_GRAY))
    print(box_row(f"{WHITE}Dossier output {GRAY}{BOX_V}{RESET} {CYAN}{config.report_dir}{RESET}", w, DARK_GRAY))
    print(box_row(f"{WHITE}Mode interactif{GRAY}{BOX_V}{RESET} {CYAN}{'oui' if config.interactive else 'non'}{RESET}", w, DARK_GRAY))
    print(box_bottom(w, DARK_GRAY))
    print()


# display.py::Affichage du dernier rapport ------------------------------------#

def print_last_report(report_path: str) -> None:
    """Affiche le contenu du dernier rapport Markdown."""
    print_section("Dernier rapport")
    print()
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
        # Afficher avec coloration basique des titres Markdown
        for line in content.split("\n"):
            if line.startswith("# "):
                print(f"  {CYAN}{BOLD}{line}{RESET}")
            elif line.startswith("## "):
                print(f"  {BLUE}{BOLD}{line}{RESET}")
            elif line.startswith("### "):
                print(f"  {MAGENTA}{line}{RESET}")
            elif line.startswith("|"):
                print(f"  {GRAY}{line}{RESET}")
            elif "CRITIQUE" in line or "critical" in line.lower():
                print(f"  {DEB_RED}{line}{RESET}")
            elif "ELEVE" in line or "high" in line.lower():
                print(f"  {ORANGE}{line}{RESET}")
            else:
                print(f"  {WHITE}{line}{RESET}")
    except FileNotFoundError:
        print(f"  {DEB_RED}{CROSS} Aucun rapport trouve a : {report_path}{RESET}")
    except Exception as e:
        print(f"  {DEB_RED}{CROSS} Erreur de lecture : {e}{RESET}")
    print()


# display.py::Message d'etat -------------------------------------------------#

def print_status(message: str, status: str = "info") -> None:
    """Affiche un message d'etat colore."""
    colors = {
        "info":    GREEN,
        "warning": YELLOW,
        "error":   DEB_RED,
        "success": GREEN,
    }
    indicators = {
        "info":    f"{GREEN}{CIRCLE_F}{RESET}",
        "warning": f"{YELLOW}{CIRCLE_F}{RESET}",
        "error":   f"{DEB_RED}{CROSS}{RESET}",
        "success": f"{GREEN}{CHECK}{RESET}",
    }
    color = colors.get(status, GRAY)
    indicator = indicators.get(status, f"{GRAY}{DOT}{RESET}")
    print(f"  {indicator} {color}{message}{RESET}")


def print_banner(text: str) -> None:
    """Affiche un bandeau d'information."""
    w = min(term_width() - 4, 72)
    pad = max(0, w - len(text) - 2)
    print(f"  {BG_HEADER}{CYAN} {text}{' ' * pad}{RESET}")
