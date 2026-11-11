"""Stack detection tests."""

import shutil
import subprocess  # nosec B404 - builds a throwaway git repository

import pytest

from securepipeline.core.detector import STACK_SIGNATURES, detect_stacks
from securepipeline.utils.files import manifest_dirs


class TestDetectStacks:

    def test_empty_directory(self, tmp_path):
        assert detect_stacks(str(tmp_path)) == []

    def test_nonexistent_path(self):
        assert detect_stacks("/no/such/path") == []

    def test_detect_python(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname='test'")
        result = detect_stacks(str(tmp_path))
        assert "python" in result

    def test_detect_python_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("click>=8.0\n")
        result = detect_stacks(str(tmp_path))
        assert "python" in result

    def test_detect_node(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "test"}')
        result = detect_stacks(str(tmp_path))
        assert "node" in result

    def test_detect_php(self, tmp_path):
        (tmp_path / "composer.json").write_text('{"name": "test/test"}')
        result = detect_stacks(str(tmp_path))
        assert "php" in result

    def test_detect_docker(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM python:3.11")
        result = detect_stacks(str(tmp_path))
        assert "docker" in result

    def test_detect_flutter(self, tmp_path):
        (tmp_path / "pubspec.yaml").write_text("name: test_app")
        result = detect_stacks(str(tmp_path))
        assert "flutter" in result

    def test_detect_k8s(self, tmp_path):
        (tmp_path / "k8s").mkdir()
        result = detect_stacks(str(tmp_path))
        assert "k8s" in result

    def test_detect_multiple_stacks(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask\n")
        (tmp_path / "Dockerfile").write_text("FROM python:3.11")
        (tmp_path / "package.json").write_text('{"name": "front"}')
        result = detect_stacks(str(tmp_path))
        assert "python" in result
        assert "docker" in result
        assert "node" in result

    def test_results_are_sorted(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask\n")
        (tmp_path / "Dockerfile").write_text("FROM python:3.11")
        (tmp_path / "package.json").write_text('{"name": "front"}')
        result = detect_stacks(str(tmp_path))
        assert result == sorted(result)

    def test_all_signatures_covered(self):
        expected_stacks = {"python", "node", "php", "rust", "docker", "k8s", "flutter"}
        assert set(STACK_SIGNATURES.keys()) == expected_stacks


class TestDetectionAtAnyDepth:
    """Like GitHub's dependency graph: manifests count wherever they are."""

    def test_finds_stacks_in_subfolders(self, tmp_path):
        (tmp_path / "frontend").mkdir()
        (tmp_path / "frontend" / "package.json").write_text("{}")
        (tmp_path / "crates" / "core").mkdir(parents=True)
        (tmp_path / "crates" / "core" / "Cargo.toml").write_text("[package]\nname='core'")
        assert detect_stacks(tmp_path) == ["node", "rust"]

    def test_dockerfile_variants(self, tmp_path):
        (tmp_path / "deploy").mkdir()
        (tmp_path / "deploy" / "worker.Dockerfile").write_text("FROM debian")
        assert detect_stacks(tmp_path) == ["docker"]

    def test_k8s_manifests_in_a_nested_folder(self, tmp_path):
        (tmp_path / "deploy" / "kubernetes").mkdir(parents=True)
        (tmp_path / "deploy" / "kubernetes" / "job.yaml").write_text("kind: Job")
        assert detect_stacks(tmp_path) == ["k8s"]

    def test_dependencies_and_build_outputs_are_ignored(self, tmp_path):
        for folder in ("node_modules/lib", "target/debug", ".venv/lib"):
            (tmp_path / folder).mkdir(parents=True)
        (tmp_path / "node_modules" / "lib" / "package.json").write_text("{}")
        (tmp_path / "target" / "debug" / "Cargo.toml").write_text("")
        (tmp_path / ".venv" / "lib" / "setup.py").write_text("")
        assert detect_stacks(tmp_path) == []

    @pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
    def test_gitignored_files_are_ignored_like_on_a_code_host(self, tmp_path):
        git = ["git", "-C", str(tmp_path)]
        subprocess.run([*git, "init", "-q"], check=True)  # nosec B603 B607 - test repository
        (tmp_path / ".gitignore").write_text("generated/\n")
        (tmp_path / "generated").mkdir()
        (tmp_path / "generated" / "package.json").write_text("{}")
        (tmp_path / "requirements.txt").write_text("flask\n")
        assert detect_stacks(tmp_path) == ["python"]


class TestManifestDirs:

    def test_workspace_members_share_the_root_lockfile(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text("[workspace]")
        (tmp_path / "Cargo.lock").write_text("")
        (tmp_path / "crates" / "web").mkdir(parents=True)
        (tmp_path / "crates" / "web" / "Cargo.toml").write_text("")
        assert manifest_dirs(tmp_path, {"Cargo.toml"}, {"Cargo.lock"}) == [tmp_path]

    def test_a_project_without_lockfile_is_kept(self, tmp_path):
        (tmp_path / "frontend").mkdir()
        (tmp_path / "frontend" / "package.json").write_text("{}")
        dirs = manifest_dirs(tmp_path, {"package.json"}, {"package-lock.json"})
        assert dirs == [tmp_path / "frontend"]
