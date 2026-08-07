"""SecurePipeline - Exécution sécurisée de sous-processus."""

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from securepipeline.utils.logger import log


@dataclass
class CommandResult:
    """Résultat d'une commande exécutée."""
    command: list[str]
    return_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.return_code == 0

    def json(self) -> dict | list | None:
        """Parse stdout comme JSON si possible."""
        try:
            return json.loads(self.stdout)
        except (json.JSONDecodeError, ValueError):
            return None


def check_tool(tool_name: str) -> bool:
    """Vérifie si un outil est installé et accessible.

    Args:
        tool_name: Nom de l'exécutable.

    Returns:
        True si l'outil est trouvé dans le PATH.
    """
    return shutil.which(tool_name) is not None


def run_command(
    command: list[str],
    cwd: str | Path | None = None,
    timeout: int = 300,
    capture_output: bool = True,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Exécute une commande shell de manière sécurisée.

    Args:
        command: Liste des arguments de la commande.
        cwd: Répertoire de travail.
        timeout: Timeout en secondes (défaut: 300s).
        capture_output: Capture stdout/stderr.
        env: Variables d'environnement additionnelles.

    Returns:
        CommandResult avec les résultats.
    """
    cmd_str = " ".join(command)
    log.debug(f"Exécution : {cmd_str}")

    try:
        result = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            env=env,
        )
        return CommandResult(
            command=command,
            return_code=result.returncode,
            stdout=result.stdout or "",
            stderr=result.stderr or "",
        )
    except subprocess.TimeoutExpired:
        log.warning(f"Timeout ({timeout}s) pour : {cmd_str}")
        return CommandResult(
            command=command,
            return_code=-1,
            stderr=f"Timeout après {timeout}s",
            timed_out=True,
        )
    except FileNotFoundError:
        log.error(f"Commande introuvable : {command[0]}")
        return CommandResult(
            command=command,
            return_code=-1,
            stderr=f"Commande introuvable : {command[0]}",
        )
    except Exception as e:
        log.error(f"Erreur inattendue : {e}")
        return CommandResult(
            command=command,
            return_code=-1,
            stderr=str(e),
        )
