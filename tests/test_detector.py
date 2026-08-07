"""Tests pour le détecteur de stacks technologiques."""

import os
import tempfile

import pytest

from securepipeline.core.detector import detect_stacks, STACK_SIGNATURES


class TestDetectStacks:
    """Tests pour detect_stacks()."""

    def test_empty_directory(self, tmp_path):
        """Un dossier vide ne doit retourner aucune stack."""
        assert detect_stacks(str(tmp_path)) == []

    def test_nonexistent_path(self):
        """Un chemin inexistant doit retourner une liste vide."""
        assert detect_stacks("/chemin/totalement/inexistant") == []

    def test_detect_python(self, tmp_path):
        """Détecte un projet Python via pyproject.toml."""
        (tmp_path / "pyproject.toml").write_text("[project]\nname='test'")
        result = detect_stacks(str(tmp_path))
        assert "python" in result

    def test_detect_python_requirements(self, tmp_path):
        """Détecte un projet Python via requirements.txt."""
        (tmp_path / "requirements.txt").write_text("click>=8.0\n")
        result = detect_stacks(str(tmp_path))
        assert "python" in result

    def test_detect_node(self, tmp_path):
        """Détecte un projet Node.js via package.json."""
        (tmp_path / "package.json").write_text('{"name": "test"}')
        result = detect_stacks(str(tmp_path))
        assert "node" in result

    def test_detect_php(self, tmp_path):
        """Détecte un projet PHP via composer.json."""
        (tmp_path / "composer.json").write_text('{"name": "test/test"}')
        result = detect_stacks(str(tmp_path))
        assert "php" in result

    def test_detect_docker(self, tmp_path):
        """Détecte Docker via Dockerfile."""
        (tmp_path / "Dockerfile").write_text("FROM python:3.11")
        result = detect_stacks(str(tmp_path))
        assert "docker" in result

    def test_detect_flutter(self, tmp_path):
        """Détecte Flutter via pubspec.yaml."""
        (tmp_path / "pubspec.yaml").write_text("name: test_app")
        result = detect_stacks(str(tmp_path))
        assert "flutter" in result

    def test_detect_k8s(self, tmp_path):
        """Détecte Kubernetes via le dossier k8s/."""
        (tmp_path / "k8s").mkdir()
        result = detect_stacks(str(tmp_path))
        assert "k8s" in result

    def test_detect_multiple_stacks(self, tmp_path):
        """Détecte plusieurs stacks simultanément."""
        (tmp_path / "requirements.txt").write_text("flask\n")
        (tmp_path / "Dockerfile").write_text("FROM python:3.11")
        (tmp_path / "package.json").write_text('{"name": "front"}')
        result = detect_stacks(str(tmp_path))
        assert "python" in result
        assert "docker" in result
        assert "node" in result

    def test_results_are_sorted(self, tmp_path):
        """Les résultats doivent être triés alphabétiquement."""
        (tmp_path / "requirements.txt").write_text("flask\n")
        (tmp_path / "Dockerfile").write_text("FROM python:3.11")
        (tmp_path / "package.json").write_text('{"name": "front"}')
        result = detect_stacks(str(tmp_path))
        assert result == sorted(result)

    def test_all_signatures_covered(self):
        """Vérifie que toutes les stacks déclarées ont des signatures."""
        expected_stacks = {"python", "node", "php", "docker", "k8s", "flutter"}
        assert set(STACK_SIGNATURES.keys()) == expected_stacks
