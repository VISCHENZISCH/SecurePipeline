"""SecurePipeline - Affichage interactif style Hacker/Forensic."""

import os
import shutil

# ═══════════════════════════════════════════════════════════════════════
#  COULEURS ANSI
# ═══════════════════════════════════════════════════════════════════════

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

def rgb(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"

# Palette Debian / GNOME Tango Theme (Dark Mode)
DEB_RED  = rgb(239, 41, 41)    # Bright Red (Tango)
CYAN     = rgb(52, 226, 226)   # Bright Cyan (Tango)
WHITE    = rgb(211, 215, 207)  # Foreground / Text (Tango)
GRAY     = rgb(136, 138, 133)  # Dark Gray (Tango)
YELLOW   = rgb(252, 233, 79)   # Bright Yellow (Tango)
BLUE     = rgb(114, 159, 207)  # Bright Blue (Tango)
GREEN    = rgb(138, 226, 52)   # Bright Green (Tango)
MAGENTA  = rgb(173, 127, 168)  # Bright Magenta (Tango)

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
    print("\033[2J\033[H", end="")

def hline(char: str = "─", width: int = 0, color: str = GRAY) -> str:
    if width == 0:
        width = term_width() - 4
    return f"  {color}{char * width}{RESET}"


# ═══════════════════════════════════════════════════════════════════════
#  MENU INTERACTIF & BANNER
# ═══════════════════════════════════════════════════════════════════════

def print_matrix_banner() -> None:
    """Affiche le banner style Debian/DevSecOps."""
    w = term_width()
    print()
    
    # Logo minimaliste "Terminal" centré
    print(center(f"{WHITE}>_ SecurePipeline_{RESET}", w))
    print(center(f"{GRAY}------------------{GREEN}█{RESET}", w))
    print()
    
    # Pluie de code DevSecOps centrée
    print(center(f"{GRAY}[WARN] Unpinned actions   [CRIT] CVE-2021-44228   [INFO] SBOM generated{RESET}", w))
    print(center(f"{BLUE}SAST: Semgrep | Bandit    SCA: Trivy | Audit      DAST: OWASP ZAP{RESET}", w))
    print(center(f"{CYAN}k8s-audit kube-score hadolint gitleaks docker-bench-security checkov{RESET}", w))
    print()
    print()
    
    # Copyright et Liens centrés
    print(center(f"{GRAY}© 2026 Félix TOVIGNAN{RESET}", w))
    print(center(f"{CYAN}https://github.com/VISCHENZISCH/SecurePipeline.git{RESET}", w))
    print()
    
    # Usage
    print(f" {WHITE}usage CLI  : {GRAY}securepipeline --scan ./projet{RESET}")
    print(f" {WHITE}mode CI/CD : {GRAY}securepipeline --scan . --fail-on critical{RESET}")
    print()


def print_menu() -> None:
    """Affiche le menu interactif essentiel et aéré."""
    print(f"  {BLUE}=== Scans de Sécurité ==={RESET}")
    print(f"   {DEB_RED}[01]{RESET} {WHITE}Lancer un Scan Complet (Auto-détection){RESET}")
    print(f"   {DEB_RED}[02]{RESET} {WHITE}Exemple de commande CI/CD (Headless){RESET}")
    print()
    
    print(f"  {BLUE}=== Outils & Rapports ==={RESET}")
    print(f"   {DEB_RED}[88]{RESET} {WHITE}Voir le dernier rapport (Markdown){RESET}")
    print(f"   {DEB_RED}[99]{RESET} {WHITE}Générer Rapport HTML (Export){RESET}")
    print()
    
    print(f"   {GRAY}[00] Quitter{RESET}")
    print()


def get_prompt() -> str:
    """Retourne la chaine du prompt interactif style Debian."""
    return f"{GREEN}root@securepipeline{RESET}:{BLUE}~/menu{RESET}# "


# ═══════════════════════════════════════════════════════════════════════
#  AFFICHAGES D'EXECUTION DE SCAN
# ═══════════════════════════════════════════════════════════════════════

def print_section(title: str) -> None:
    print(f"\n  {CYAN}[*] {title}{RESET}")


def print_stacks(stacks: list[str]) -> None:
    if not stacks:
        print(f"  {DEB_RED}[!] Aucune stack technologique detectee.{RESET}")
        return
    print(f"  {GREEN}[+] Stacks detectees: {WHITE}{', '.join(stacks)}{RESET}\n")


def print_scanner_start(name: str) -> None:
    print(f"  {GRAY}└─{RESET} {WHITE}Lancement de {CYAN}{name}{RESET} ... ", end="", flush=True)


def print_scanner_done(count: int) -> None:
    if count == 0:
        print(f"{GREEN}OK{RESET}")
    else:
        color = DEB_RED if count >= 5 else YELLOW
        print(f"{color}FAIL ({count} findings){RESET}")


def print_scanner_skip(reason: str) -> None:
    print(f"{GRAY}SKIP ({reason}){RESET}")


def print_summary(stats: dict[str, int], total: int, duration: float) -> None:
    print_section("Resume du Scan")
    
    parts = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = stats.get(sev, 0)
        color = SEV_COLORS[sev]
        parts.append(f"{color}[{SEV_LABELS[sev]}: {count}]{RESET}")
        
    print(f"  {' '.join(parts)}")
    
    if total == 0:
        print(f"  {GREEN}[+] Systeme propre. Aucune vulnerabilite.{RESET}")
    else:
        color = DEB_RED if stats.get("critical", 0) > 0 else YELLOW
        print(f"  {color}[!] Total: {total} vulnerabilites.{RESET}")
        
    print(f"  {GRAY}Temps d'execution: {duration:.2f}s{RESET}\n")


def print_findings_table(findings: list) -> None:
    if not findings:
        return
    print_section("Artefacts / Vulnerabilites")
    
    for f in findings:
        sev_color = SEV_COLORS.get(f.severity.value, GRAY)
        title = f.title[:50] + "..." if len(f.title) > 50 else f.title
        rule = f.rule_id
        file_path = f.file_path if f.file_path else "Global"
        
        print(f"  {sev_color}► [{f.severity.value.upper():^8}]{RESET} {WHITE}{rule:15}{RESET} {GRAY}|{RESET} {WHITE}{title:50}{RESET} {GRAY}|{RESET} {CYAN}{file_path}{RESET}")
    print()
