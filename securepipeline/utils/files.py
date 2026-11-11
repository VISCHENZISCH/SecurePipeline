"""Project file inventory, built the way code hosts see a repository."""

import os
from collections.abc import Callable, Collection, Iterator
from pathlib import Path

from securepipeline.utils.process import run_command

# Dependencies, build outputs, environments and caches are not the project's own code.
# GitHub Linguist calls them "vendored" and leaves them out of the language stats.
EXCLUDED_DIRS = frozenset({
    ".dart_tool",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".securepipeline",
    ".tox",
    ".venv",
    "__pycache__",
    "bower_components",
    "env",
    "node_modules",
    "site-packages",
    "target",
    "vendor",
    "venv",
})


def iter_project_files(root: Path, accept: Callable[[str], bool]) -> Iterator[Path]:
    """Yield the files whose name passes `accept`, skipping excluded directories."""
    for directory, subdirs, filenames in os.walk(root):
        subdirs[:] = [d for d in subdirs if d not in EXCLUDED_DIRS]
        for name in filenames:
            if accept(name):
                yield Path(directory) / name


def list_project_files(root: Path) -> list[Path]:
    """Return the files that make up the project, at any depth.

    In a git repository, these are the tracked files and the new files that
    .gitignore does not exclude: what a push would publish, and so what GitHub's
    dependency graph and Dependabot see. Outside git, every file outside the
    excluded directories.
    """
    files = _git_files(root) or list(iter_project_files(root, lambda _name: True))
    return sorted(
        path for path in files
        if not EXCLUDED_DIRS.intersection(path.relative_to(root).parts[:-1])
    )


def _git_files(root: Path) -> list[Path] | None:
    command = ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"]
    result = run_command(command, timeout=60)
    if result.return_code != 0:
        return None
    # A file deleted but not yet committed is still in the index.
    return [root / name for name in result.stdout.split("\0") if name and (root / name).is_file()]


def manifest_dirs(root: Path, manifests: Collection[str], lockfiles: Collection[str] = ()) -> list[Path]:
    """Return the directories that hold one of `manifests`, at any depth.

    A directory without its own lockfile is left out when a parent directory has
    one: it belongs to a workspace (npm, Cargo) audited from the workspace root.
    """
    dirs = sorted({path.parent for path in list_project_files(root) if path.name in manifests})
    if not lockfiles:
        return dirs

    def has_lockfile(directory: Path) -> bool:
        return any((directory / name).is_file() for name in lockfiles)

    def covered_by_parent(directory: Path) -> bool:
        parents = directory.relative_to(root).parents
        return any(has_lockfile(root / parent) for parent in parents)

    return [d for d in dirs if has_lockfile(d) or not covered_by_parent(d)]


def display_path(directory: Path, root: Path) -> str:
    """Name a directory relative to the project, "." for the project itself."""
    return directory.relative_to(root).as_posix()
