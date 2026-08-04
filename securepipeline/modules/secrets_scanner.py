"""SecurePipeline - Scanner de secrets (Gitleaks)."""

import json
from pathlib import Path
from securepipeline.core.models import Finding, Severity
from securepipeline.modules.base import BaseScanner, ScannerInfo
from securepipeline.utils.logger import log
from securepipeline.utils.subprocess_runner import run_command, check_tool


class SecretsScanner(BaseScanner):
    """Scanner de secrets (Gitleaks) - toujours exécuté."""

    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Secrets Scanner",
            description="Détection de secrets exposés avec Gitleaks",
            tools_required=["gitleaks"],
            stack="global",
        )

    def scan(self, path: str) -> list[Finding]:
        if not check_tool("gitleaks"):
            log.warning("gitleaks non installé, module ignoré")
            return []

        log.info("[Secrets] → gitleaks")
        report_path = Path(path) / ".gitleaks-report.json"
        
        cmd = ["gitleaks", "detect", "--source", path, "--report-path", str(report_path), "--report-format", "json"]
        # gitleaks retourne 1 s'il trouve des leaks, ce n'est pas une erreur système
        run_command(cmd, cwd=path, timeout=120)

        findings = []
        if report_path.exists():
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for leak in data:
                        findings.append(Finding(
                            rule_id=leak.get("RuleID", "LEAK"),
                            title=f"Secret trouvé : {leak.get('Description', 'Secret')}",
                            severity=Severity.CRITICAL,  # Un secret est toujours critique
                            file_path=leak.get("File", ""),
                            line=leak.get("StartLine", 0),
                            description=f"Match: {leak.get('Match', '')[:50]}...",
                            scanner="gitleaks",
                        ))
            except json.JSONDecodeError:
                log.warning("Erreur parsing rapport gitleaks")
            finally:
                report_path.unlink(missing_ok=True)
                
        return findings
