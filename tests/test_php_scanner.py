"""Tests pour le scanner PHP."""

import json

import pytest

from securepipeline.modules.php_scanner import PhpScanner
from securepipeline.modules.base import ScannerInfo


class TestPhpScannerInfo:
    """Tests pour les métadonnées du PhpScanner."""

    def test_info_returns_scanner_info(self):
        """info() doit retourner un ScannerInfo."""
        scanner = PhpScanner()
        info = scanner.info()
        assert isinstance(info, ScannerInfo)

    def test_info_name(self):
        """Le scanner doit avoir un nom."""
        scanner = PhpScanner()
        info = scanner.info()
        assert info.name
        assert len(info.name) > 0

    def test_info_has_tools(self):
        """Le scanner doit déclarer ses outils requis."""
        scanner = PhpScanner()
        info = scanner.info()
        assert isinstance(info.tools_required, list)

    def test_info_stack_is_php(self):
        """Le scanner doit être associé à la stack PHP."""
        scanner = PhpScanner()
        info = scanner.info()
        assert info.stack == "php"


class TestPhpScannerPrerequisites:
    """Tests pour la vérification des prérequis."""

    def test_check_prerequisites_returns_tuple(self):
        """check_prerequisites doit retourner un tuple (bool, list)."""
        scanner = PhpScanner()
        result = scanner.check_prerequisites()
        assert isinstance(result, tuple)
        assert len(result) == 2
        ok, missing = result
        assert isinstance(ok, bool)
        assert isinstance(missing, list)


class TestPhpScannerScan:
    """Tests pour le scan PHP."""

    def test_scan_empty_project(self, tmp_path):
        """Le scan d'un dossier vide ne doit pas planter."""
        scanner = PhpScanner()
        # Le scan peut retourner une liste vide si les outils ne sont pas installés
        findings = scanner.scan(str(tmp_path))
        assert isinstance(findings, list)

    def test_scan_returns_findings_list(self, tmp_path):
        """Le résultat du scan doit toujours être une liste."""
        (tmp_path / "composer.json").write_text('{"name": "test/test"}')
        scanner = PhpScanner()
        result = scanner.scan(str(tmp_path))
        assert isinstance(result, list)
