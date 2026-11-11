"""Semgrep static analysis, shared by all stacks."""

from importlib import resources
from pathlib import Path

from securepipeline.core.models import Finding, Severity
from securepipeline.scanners.base import BaseScanner, Check, NothingToScan, ScannerInfo, load_json
from securepipeline.utils.files import EXCLUDED_DIRS
from securepipeline.utils.process import run_command

# The Semgrep registry has no Dart ruleset, so Flutter gets no static analysis.
REGISTRY_RULESETS = {
    "python": ["p/python"],
    "node": ["p/javascript", "p/typescript"],
    "php": ["p/php"],
    "rust": ["p/rust"],
}
LOCAL_RULES = {
    "node": "js.yml",
    "php": "php.yml",
}
SEVERITIES = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


class SemgrepScanner(BaseScanner):
    """Groups the rules of all detected stacks into one Semgrep run.

    Semgrep shares file parsing across rules, which is much faster than one run per stack.
    """

    def __init__(self, stacks: list[str] | None = None):
        self.stacks = stacks if stacks is not None else list(REGISTRY_RULESETS)

    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Semgrep SAST",
            description="Static analysis for Python, JS/TS, PHP and Rust (registry and bundled rules)",
            stack="sast",
        )

    def checks(self) -> list[Check]:
        return [Check("semgrep", self._run)]

    def _configs(self) -> list[str]:
        rules_dir = resources.files("securepipeline.rules").joinpath("semgrep")
        configs: list[str] = []
        for stack in self.stacks:
            configs.extend(REGISTRY_RULESETS.get(stack, []))
            if stack in LOCAL_RULES:
                configs.append(str(rules_dir.joinpath(LOCAL_RULES[stack])))
        return configs

    def _run(self, root: Path) -> list[Finding]:
        configs = self._configs()
        if not configs:
            raise NothingToScan("no rules for these stacks")

        command = ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check"]
        for config in configs:
            command.extend(["--config", config])
        for excluded in sorted(EXCLUDED_DIRS):
            command.extend(["--exclude", excluded])
        command.append(str(root))

        # Without --error, Semgrep returns 0 even when it has results.
        return parse_semgrep(load_json(run_command(command, cwd=root, timeout=600), ok_codes=(0,)))


def parse_semgrep(data: dict) -> list[Finding]:
    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        findings.append(Finding(
            rule_id=result.get("check_id", "semgrep.unknown").rsplit(".", 1)[-1],
            title=" ".join(extra.get("message", "Semgrep finding").split())[:200],
            severity=SEVERITIES.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM),
            file_path=result.get("path", ""),
            line=result.get("start", {}).get("line", 0),
            description=extra.get("metadata", {}).get("shortlink", ""),
            scanner="semgrep",
        ))
    return findings
