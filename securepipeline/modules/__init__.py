"""SecurePipeline - Registre des modules de scan."""

from securepipeline.modules.base import BaseScanner
from securepipeline.modules.python_scanner import PythonScanner
from securepipeline.modules.node_scanner import NodeScanner
from securepipeline.modules.php_scanner import PhpScanner
from securepipeline.modules.flutter_scanner import FlutterScanner
from securepipeline.modules.docker_scanner import DockerScanner
from securepipeline.modules.k8s_scanner import K8sScanner
from securepipeline.modules.secrets_scanner import SecretsScanner

# Registre stack vers scanners
# Chaque stack peut avoir plusieurs scanners.
# Le SecretsScanner (Gitleaks) est toujours exécuté.

STACK_SCANNERS: dict[str, list[type[BaseScanner]]] = {
    "python":  [PythonScanner],
    "node":    [NodeScanner],
    "php":     [PhpScanner],
    "flutter": [FlutterScanner],
    "docker":  [DockerScanner],
    "k8s":     [K8sScanner],
}

# Scanner global (exécuté indépendamment de la stack)
GLOBAL_SCANNERS: list[type[BaseScanner]] = [SecretsScanner]


def get_scanners_for_stacks(stacks: list[str]) -> list[BaseScanner]:
    """Retourne les instances de scanners pour les stacks données.

    Args:
        stacks: Liste des noms de stacks détectées.

    Returns:
        Liste d'instances de scanners à exécuter.
    """
    scanners: list[BaseScanner] = []
    seen: set[type] = set()

    # Scanners spécifiques aux stacks
    for stack in stacks:
        for scanner_cls in STACK_SCANNERS.get(stack, []):
            if scanner_cls not in seen:
                scanners.append(scanner_cls())
                seen.add(scanner_cls)

    # Scanners globaux
    for scanner_cls in GLOBAL_SCANNERS:
        if scanner_cls not in seen:
            scanners.append(scanner_cls())
            seen.add(scanner_cls)

    return scanners


__all__ = [
    "BaseScanner",
    "STACK_SCANNERS",
    "GLOBAL_SCANNERS",
    "get_scanners_for_stacks",
]
