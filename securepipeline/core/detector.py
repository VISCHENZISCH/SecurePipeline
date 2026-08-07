"""SecurePipeline - Détecteur de stacks technologiques."""

from pathlib import Path

# Signatures de détection

STACK_SIGNATURES: dict[str, list[str]] = {
    "python":  ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "poetry.lock"],
    "node":    ["package.json", "yarn.lock", "pnpm-lock.yaml"],
    "php":     ["composer.json", "composer.lock"],
    "docker":  ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    "k8s":     ["k8s/", "kubernetes/", "helm/"],
    "flutter": ["pubspec.yaml", "pubspec.lock"],
}


def detect_stacks(path: str) -> list[str]:
    """Détecte les stacks technologiques présentes dans le projet.

    Args:
        path: Chemin du projet à analyser.

    Returns:
        Liste des noms de stacks détectées.
    """
    project_path = Path(path).resolve()
    detected: list[str] = []

    if not project_path.exists():
        return detected

    for stack_name, signatures in STACK_SIGNATURES.items():
        for sig in signatures:
            target = project_path / sig
            if target.exists():
                detected.append(stack_name)
                break

    return sorted(detected)
