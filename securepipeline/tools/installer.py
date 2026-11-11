"""Installs the security tools; every download is verified against its pinned SHA-256."""

import hashlib
import io
import os
import platform
import subprocess  # nosec B404 - runs pip with a fixed argument list
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from securepipeline.tools.catalog import (
    BINARIES_BY_NAME,
    PIP_TOOLS,
    BinaryTool,
    tool_descriptions,
)
from securepipeline.utils.process import check_tool

DOWNLOAD_TIMEOUT = 120
PIP_TIMEOUT = 900
INSTALL_WORKERS = 6


def get_missing_tools() -> list[str]:
    """Return the tools that are absent but could be installed on this platform."""
    return [
        name for name in tool_descriptions()
        if not check_tool(name) and is_available(name)
    ]


def is_available(name: str) -> bool:
    """False for a binary tool that publishes no build for this platform (kubesec on Windows)."""
    tool = BINARIES_BY_NAME.get(name)
    return tool is None or current_platform() in tool.assets


def current_platform() -> str:
    """Return the catalog key of this platform, such as "linux-amd64"."""
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    machine = platform.machine().lower()
    return f"{platform.system().lower()}-{arch.get(machine, machine)}"


def default_bin_dir() -> Path:
    """Return the active venv's bin directory, otherwise ~/.local/bin."""
    if sys.prefix != sys.base_prefix:
        return Path(sys.executable).parent
    return Path.home() / ".local" / "bin"


def _download(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT) as response:  # nosec B310 - https catalog URL
        return response.read()


def _extract_binary(payload: bytes, filename: str, binary: str) -> bytes:
    """Read the binary from memory, so archive paths never reach the disk."""
    if filename.endswith(".tar.gz"):
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            for member in archive.getmembers():
                if member.isfile() and os.path.basename(member.name) == binary:
                    return archive.extractfile(member).read()
    elif filename.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for name in archive.namelist():
                if os.path.basename(name) == binary:
                    return archive.read(name)
    else:
        return payload
    raise ValueError(f"{binary} not found in {filename}")


def _write_executable(content: bytes, destination: Path) -> None:
    """Write atomically: an interruption must not leave a truncated binary."""
    fd, temp_name = tempfile.mkstemp(dir=destination.parent, prefix=f".{destination.name}.")
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
        temp_path.chmod(0o755)
        temp_path.replace(destination)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def _install_binary(tool: BinaryTool, bin_dir: Path, plat: str) -> None:
    asset = tool.assets.get(plat)
    if asset is None:
        raise ValueError(f"no binary for {plat}")

    payload = _download(f"{tool.base_url}/{asset.filename}")
    if hashlib.sha256(payload).hexdigest() != asset.sha256:
        raise ValueError("invalid SHA-256 checksum, file rejected")

    exe = ".exe" if plat.startswith("windows") else ""
    content = _extract_binary(payload, asset.filename, f"{tool.name}{exe}")
    _write_executable(content, bin_dir / f"{tool.name}{exe}")


def _install_pip(packages: list[str]) -> None:
    result = subprocess.run(  # nosec B603 - fixed pip command, no shell
        [sys.executable, "-m", "pip", "install", "-q", "--disable-pip-version-check", *packages],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=PIP_TIMEOUT,
        check=False,
    )
    if result.returncode != 0:
        lines = (result.stderr or result.stdout or "pip error").strip().splitlines()
        raise ValueError(lines[-1])


def install_tools(
    names: list[str],
    bin_dir: Path | None = None,
    on_start: Callable[[str], None] | None = None,
    on_done: Callable[[str, bool, str], None] | None = None,
) -> dict[str, bool]:
    """Install tools in parallel and return {tool: success}.

    pip packages are grouped into one call: pip resolves shared dependencies better
    and does not compete with itself for the environment.
    """
    destination = bin_dir or default_bin_dir()
    destination.mkdir(parents=True, exist_ok=True)
    plat = current_platform()
    results: dict[str, bool] = {}

    def report(tool_names: list[str], error: str) -> None:
        for name in tool_names:
            results[name] = not error
            if on_done:
                on_done(name, not error, error)

    def run_group(tool_names: list[str], install: Callable[[], None]) -> None:
        for name in tool_names:
            if on_start:
                on_start(name)
        try:
            install()
        except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as e:
            report(tool_names, str(e)[:120])
        else:
            report(tool_names, "")

    pip_names = [name for name in names if name in PIP_TOOLS]
    binary_names = [name for name in names if name in BINARIES_BY_NAME]
    report([name for name in names if name not in PIP_TOOLS and name not in BINARIES_BY_NAME], "unknown tool")

    with ThreadPoolExecutor(max_workers=INSTALL_WORKERS) as pool:
        if pip_names:
            packages = [PIP_TOOLS[name][0] for name in pip_names]
            pool.submit(run_group, pip_names, lambda: _install_pip(packages))
        for name in binary_names:
            tool = BINARIES_BY_NAME[name]
            pool.submit(run_group, [name], lambda t=tool: _install_binary(t, destination, plat))

    return results
