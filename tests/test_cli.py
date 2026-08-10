import pytest
from click.testing import CliRunner
from securepipeline.cli import cli

def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Scanner de securite multi-stack" in result.output

def test_scan_missing_path():
    runner = CliRunner()
    # Missing required path argument
    result = runner.invoke(cli, ["scan"])
    assert result.exit_code != 0
    assert "Missing argument" in result.output
