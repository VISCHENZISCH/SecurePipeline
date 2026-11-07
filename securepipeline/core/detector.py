"""Technology stack detection."""

from pathlib import Path

STACK_SIGNATURES: dict[str, list[str]] = {
    "python":  ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "poetry.lock"],
    "node":    ["package.json", "yarn.lock", "pnpm-lock.yaml"],
    "php":     ["composer.json", "composer.lock"],
    "docker":  ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    "k8s":     ["k8s/", "kubernetes/", "helm/"],
    "flutter": ["pubspec.yaml", "pubspec.lock"],
}


def detect_stacks(path: str | Path) -> list[str]:
    """Return the sorted names of the stacks found at the project root."""
    root = Path(path).resolve()
    return sorted(
        stack
        for stack, signatures in STACK_SIGNATURES.items()
        if any((root / signature).exists() for signature in signatures)
    )
