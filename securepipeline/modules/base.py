"""SecurePipeline - Scanner de base abstrait."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from securepipeline.core.models import Finding
from securepipeline.utils.logger import log
from securepipeline.utils.subprocess_runner import check_tool


@dataclass
class ScannerInfo:
    """Métadonnées d'un scanner."""
    name: str
    description: str
    tools_required: list[str] = field(default_factory=list)
    stack: str = ""


class BaseScanner(ABC):
    """Classe abstraite pour tous les scanners de sécurité.

    Chaque scanner doit implémenter :
    - info() : retourne les métadonnées du scanner
    - scan() : exécute le scan et retourne les findings
    """

    @abstractmethod
    def info(self) -> ScannerInfo:
        """Retourne les métadonnées du scanner."""
        ...

    @abstractmethod
    def scan(self, path: str) -> list[Finding]:
        """Exécute le scan sur le chemin donné.

        Args:
            path: Chemin du projet à scanner.

        Returns:
            Liste des findings détectés.
        """
        ...

    def check_prerequisites(self) -> tuple[bool, list[str]]:
        """Vérifie que les outils requis sont installés.

        Returns:
            Tuple (tous_ok, liste_manquants).
        """
        scanner_info = self.info()
        missing = []
        for tool in scanner_info.tools_required:
            if not check_tool(tool):
                missing.append(tool)

        if missing:
            log.warning(
                f"[{scanner_info.name}] : "
                f"outils manquants : {', '.join(missing)}"
            )
        return len(missing) == 0, missing
