"""Fast traversal of project files."""

import os
from collections.abc import Callable, Iterator
from pathlib import Path

# Dependencies, environments and caches are not the project's own code.
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
    "env",
    "node_modules",
    "site-packages",
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
