"""Secret detection with Gitleaks."""

import json
import tempfile
from pathlib import Path

from securepipeline.core.models import Finding, Severity
from securepipeline.scanners.base import BaseScanner, Check, ScannerInfo, ToolError
from securepipeline.utils.process import run_command

# Gitleaks also returns 1 on errors: a dedicated code removes the ambiguity.
LEAKS_EXIT_CODE = 42


class SecretsScanner(BaseScanner):
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Secrets",
            description="Exposed secret detection with Gitleaks",
            stack="global",
        )

    def checks(self) -> list[Check]:
        return [Check("gitleaks", self._run)]

    def _run(self, root: Path) -> list[Finding]:
        # The report lives outside the project, which may be mounted read-only.
        with tempfile.TemporaryDirectory(prefix="securepipeline-") as tmp:
            report = Path(tmp) / "gitleaks.json"
            command = [
                "gitleaks", "detect",
                "--source", str(root),
                "--report-path", str(report),
                "--report-format", "json",
                "--exit-code", str(LEAKS_EXIT_CODE),
                "--redact",
                "--no-banner",
            ]
            if not (root / ".git").exists():
                command.append("--no-git")

            result = run_command(command, cwd=root, timeout=600)
            if result.return_code not in (0, LEAKS_EXIT_CODE):
                reason = result.stderr.strip().splitlines()[-1:] or [f"return code {result.return_code}"]
                raise ToolError(reason[0][:160])

            try:
                leaks = json.loads(report.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                raise ToolError(f"unreadable Gitleaks report: {e}") from e

        return [parse_leak(leak) for leak in leaks]


def parse_leak(leak: dict) -> Finding:
    """Build a finding that never keeps the secret itself."""
    commit = leak.get("Commit", "")
    return Finding(
        rule_id=leak.get("RuleID", "LEAK"),
        title=f"Secret found: {leak.get('Description', 'secret')}",
        severity=Severity.CRITICAL,
        file_path=leak.get("File", ""),
        line=leak.get("StartLine", 0),
        description=f"Commit {commit[:8]}" if commit else "",
        remediation="Revoke this secret, then remove it from the code and the Git history.",
        scanner="gitleaks",
    )
