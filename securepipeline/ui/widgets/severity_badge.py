"""SecurePipeline - Widget de badges de severite."""

from securepipeline.ui.display import (
    RESET, BOLD,
    SEV_COLORS, SEV_BG, SEV_LABELS, SEV_INDICATORS,
    WHITE, GRAY, DARK_GRAY, BOX_H,
)


def severity_badge(severity: str) -> str:
    """Retourne un badge de severite colore (fond + texte).

    Args:
        severity: Niveau de severite ("critical", "high", "medium", "low", "info").

    Returns:
        Chaine avec codes ANSI pour afficher un badge colore.
    """
    color = SEV_COLORS.get(severity, GRAY)
    bg = SEV_BG.get(severity, "")
    label = SEV_LABELS.get(severity, severity.upper())
    return f"{bg}{color}{BOLD} {label:<8} {RESET}"


def severity_inline(severity: str) -> str:
    """Retourne le label de severite colore sans fond.

    Args:
        severity: Niveau de severite.

    Returns:
        Chaine avec couleur foreground uniquement.
    """
    color = SEV_COLORS.get(severity, GRAY)
    label = SEV_LABELS.get(severity, severity.upper())
    return f"{color}{BOLD}{label}{RESET}"


def severity_indicator(severity: str) -> str:
    """Retourne l'indicateur compact de severite.

    Args:
        severity: Niveau de severite.

    Returns:
        Chaine avec indicateur [!!!], [!!], [!], [-], ou [i].
    """
    return SEV_INDICATORS.get(severity, f"{GRAY}[?]{RESET}")


def print_severity_legend() -> None:
    """Affiche la legende des niveaux de severite."""
    print(f"\n  {WHITE}{BOLD}Legende des severites{RESET}")
    print(f"  {DARK_GRAY}{BOX_H * 35}{RESET}")

    descriptions = {
        "critical": "Vulnerabilite exploitable, impact majeur",
        "high":     "Risque eleve, correction prioritaire",
        "medium":   "Risque modere, a planifier",
        "low":      "Risque faible, bonne pratique",
        "info":     "Information, pas de risque direct",
    }

    for sev in ["critical", "high", "medium", "low", "info"]:
        badge = severity_badge(sev)
        desc = descriptions.get(sev, "")
        print(f"  {badge} {GRAY}{desc}{RESET}")

    print()


def severity_summary_line(stats: dict[str, int]) -> str:
    """Retourne une ligne resumee des severites.

    Args:
        stats: Dict {severity: count}.

    Returns:
        Ligne formatee ex: "3 CRITIQUE | 5 ELEVE | 2 MOYEN"
    """
    parts = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = stats.get(sev, 0)
        if count > 0:
            color = SEV_COLORS.get(sev, GRAY)
            label = SEV_LABELS.get(sev, sev.upper())
            parts.append(f"{color}{count} {label}{RESET}")

    if not parts:
        return f"{GRAY}Aucun finding{RESET}"

    return f" {DARK_GRAY}|{RESET} ".join(parts)
