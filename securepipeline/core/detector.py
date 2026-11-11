"""Technology stack detection.

Like GitHub's dependency graph, it looks for manifests at any depth of the
repository (a frontend/ folder, a services/api/ folder...), among the files that
git tracks or does not ignore. Dependencies and build outputs are skipped.
"""

from pathlib import Path, PurePath

from securepipeline.utils.files import list_project_files

K8S_DIRS = ("k8s", "kubernetes", "helm")

# A name ending with "/" is a directory that may appear anywhere in the path.
STACK_SIGNATURES: dict[str, list[str]] = {
    "python":  ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "poetry.lock"],
    "node":    ["package.json", "yarn.lock", "pnpm-lock.yaml"],
    "php":     ["composer.json", "composer.lock"],
    "rust":    ["Cargo.toml", "Cargo.lock"],
    "docker":  ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"],
    "k8s":     [f"{name}/" for name in K8S_DIRS],
    "flutter": ["pubspec.yaml", "pubspec.lock"],
}


def detect_stacks(path: str | Path) -> list[str]:
    """Return the sorted names of the stacks found anywhere in the project."""
    root = Path(path).resolve()
    if not root.is_dir():
        return []

    found = {
        stack
        for file in list_project_files(root)
        for stack, signatures in STACK_SIGNATURES.items()
        if _matches(file.relative_to(root), signatures)
    }
    # An empty k8s/ folder at the root still announces Kubernetes manifests.
    if any((root / name).is_dir() for name in K8S_DIRS):
        found.add("k8s")
    return sorted(found)


def _matches(relative: PurePath, signatures: list[str]) -> bool:
    folders = {part.lower() for part in relative.parts[:-1]}
    for signature in signatures:
        if signature.endswith("/"):
            if signature[:-1] in folders:
                return True
        elif relative.name == signature or _is_dockerfile_variant(relative.name, signature):
            return True
    return False


def _is_dockerfile_variant(name: str, signature: str) -> bool:
    """Dockerfile.worker and worker.Dockerfile are Dockerfiles too."""
    return signature == "Dockerfile" and (name.startswith("Dockerfile.") or name.endswith(".Dockerfile"))
