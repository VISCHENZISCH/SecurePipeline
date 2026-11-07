"""Installer tests: only a verified binary may reach the disk."""

import hashlib
import io
import os
import re
import tarfile
import zipfile

import pytest

from securepipeline.tools import catalog, installer
from securepipeline.tools.catalog import Asset, BinaryTool


def tar_gz(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def tool_for(payload: bytes, filename: str, plat: str = "linux-amd64") -> BinaryTool:
    asset = Asset(filename, hashlib.sha256(payload).hexdigest())
    return BinaryTool("tool", "desc", "https://example.invalid", {plat: asset})


def serve(monkeypatch, payload: bytes) -> None:
    monkeypatch.setattr(installer, "_download", lambda _url: payload)


def test_catalog_is_consistent():
    for tool in catalog.BINARY_TOOLS:
        assert tool.base_url.startswith("https://github.com/")
        assert "linux-amd64" in tool.assets
        for asset in tool.assets.values():
            assert re.fullmatch(r"[0-9a-f]{64}", asset.sha256), asset.filename


def test_rejects_wrong_checksum(monkeypatch, tmp_path):
    tool = tool_for(b"expected", "tool")
    serve(monkeypatch, b"tampered content")
    with pytest.raises(ValueError, match="SHA-256"):
        installer._install_binary(tool, tmp_path, "linux-amd64")
    assert not list(tmp_path.iterdir())


def test_installs_direct_binary_as_executable(monkeypatch, tmp_path):
    tool = tool_for(b"binary", "tool")
    serve(monkeypatch, b"binary")
    installer._install_binary(tool, tmp_path, "linux-amd64")
    assert (tmp_path / "tool").read_bytes() == b"binary"
    assert os.access(tmp_path / "tool", os.X_OK)
    assert list(tmp_path.iterdir()) == [tmp_path / "tool"]


def test_tar_extraction_ignores_paths_in_archive(monkeypatch, tmp_path):
    payload = tar_gz({"../../evil": b"evil", "folder/tool": b"binary"})
    serve(monkeypatch, payload)
    target = tmp_path / "bin"
    target.mkdir()
    installer._install_binary(tool_for(payload, "tool.tar.gz"), target, "linux-amd64")
    assert (target / "tool").read_bytes() == b"binary"
    assert sorted(p.name for p in tmp_path.rglob("*")) == ["bin", "tool"]


def test_zip_extraction_adds_exe_on_windows(monkeypatch, tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("tool.exe", b"binary")
    payload = buffer.getvalue()
    serve(monkeypatch, payload)
    tool = tool_for(payload, "tool.zip", "windows-amd64")
    installer._install_binary(tool, tmp_path, "windows-amd64")
    assert (tmp_path / "tool.exe").read_bytes() == b"binary"


def test_archive_without_binary_is_rejected(monkeypatch, tmp_path):
    payload = tar_gz({"LICENSE": b"text"})
    serve(monkeypatch, payload)
    with pytest.raises(ValueError, match="not found"):
        installer._install_binary(tool_for(payload, "tool.tar.gz"), tmp_path, "linux-amd64")


def test_unsupported_platform_is_reported(tmp_path):
    with pytest.raises(ValueError, match="no binary"):
        installer._install_binary(tool_for(b"x", "tool"), tmp_path, "plan9-mips")


def test_failed_write_leaves_no_temp_file(tmp_path, monkeypatch):
    def refuse(_self, _target):
        raise OSError("disk full")

    monkeypatch.setattr(installer.Path, "replace", refuse)
    with pytest.raises(OSError, match="disk full"):
        installer._write_executable(b"x", tmp_path / "tool")
    assert not list(tmp_path.iterdir())


def test_install_tools_groups_pip_and_reports_each_tool(monkeypatch, tmp_path):
    pip_calls = []
    monkeypatch.setattr(installer, "_install_pip", pip_calls.append)

    def fail_binary(tool, _bin_dir, _plat):
        raise ValueError(f"failed {tool.name}")

    monkeypatch.setattr(installer, "_install_binary", fail_binary)
    done = {}
    results = installer.install_tools(
        ["bandit", "semgrep", "trivy", "unknown"],
        bin_dir=tmp_path,
        on_done=lambda name, ok, error: done.__setitem__(name, (ok, error)),
    )
    assert len(pip_calls) == 1
    assert len(pip_calls[0]) == 2
    assert results == {"bandit": True, "semgrep": True, "trivy": False, "unknown": False}
    assert done["trivy"] == (False, "failed trivy")
    assert done["unknown"] == (False, "unknown tool")


@pytest.mark.parametrize(("system", "machine", "expected"), [
    ("Linux", "x86_64", "linux-amd64"),
    ("Linux", "aarch64", "linux-arm64"),
    ("Darwin", "arm64", "darwin-arm64"),
    ("Windows", "AMD64", "windows-amd64"),
])
def test_current_platform(monkeypatch, system, machine, expected):
    monkeypatch.setattr(installer.platform, "system", lambda: system)
    monkeypatch.setattr(installer.platform, "machine", lambda: machine)
    assert installer.current_platform() == expected
