import pytest
from securepipeline.modules.docker_scanner import DockerScanner
from securepipeline.modules.base import ScannerInfo

class TestDockerScannerInfo:
    def test_info_returns_scanner_info(self):
        scanner = DockerScanner()
        info = scanner.info()
        assert isinstance(info, ScannerInfo)
        assert info.name == "Docker Scanner"
        assert info.stack == "docker"
        assert "trivy" in info.tools_required
        assert "hadolint" in info.tools_required

class TestDockerScannerScan:
    def test_scan_empty_project(self, tmp_path):
        scanner = DockerScanner()
        findings = scanner.scan(str(tmp_path))
        assert isinstance(findings, list)
