"""Rust dependency audit: known vulnerabilities (OSV-Scanner) and project policy (cargo-deny)."""

import json
import shutil
from pathlib import Path

from securepipeline.core.models import Finding, Severity
from securepipeline.scanners.base import (
    BaseScanner,
    Check,
    CheckSkipped,
    NothingToScan,
    ScannerInfo,
    ToolError,
    audit_dirs,
    load_json,
)
from securepipeline.utils.files import manifest_dirs
from securepipeline.utils.process import run_command

DENY_CONFIGS = ("deny.toml", ".deny.toml", ".cargo/deny.toml")
# Advisories are left to OSV-Scanner, so that each vulnerability is reported once.
DENY_CHECKS = ("bans", "licenses", "sources")
DENY_LEVELS = {
    "error": Severity.HIGH,
    "warning": Severity.LOW,
    "note": Severity.INFO,
    "help": Severity.INFO,
}


class RustScanner(BaseScanner):
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="Rust",
            description="Known vulnerabilities (OSV-Scanner) and deny.toml policy (cargo-deny)",
            stack="rust",
        )

    def checks(self) -> list[Check]:
        return [Check("osv-scanner", self._run_osv_scanner), Check("cargo-deny", self._run_cargo_deny)]

    def _crate_dirs(self, root: Path) -> list[Path]:
        dirs = manifest_dirs(root, {"Cargo.toml"}, {"Cargo.lock"})
        if not dirs:
            raise NothingToScan("no Cargo.toml")
        return dirs

    def _run_osv_scanner(self, root: Path) -> list[Finding]:
        return audit_dirs(root, self._crate_dirs(root), _osv_scan)

    def _run_cargo_deny(self, root: Path) -> list[Finding]:
        configured = [d for d in self._crate_dirs(root) if _deny_config(d)]
        if not configured:
            raise NothingToScan("no deny.toml, OSV-Scanner covers the known vulnerabilities")
        if shutil.which("cargo") is None:
            raise CheckSkipped("cargo is required by cargo-deny (install Rust: https://rustup.rs)")
        return audit_dirs(root, configured, _cargo_deny)


def _deny_config(directory: Path) -> Path | None:
    return next((directory / name for name in DENY_CONFIGS if (directory / name).is_file()), None)


def _osv_scan(directory: Path) -> list[Finding]:
    lockfile = directory / "Cargo.lock"
    if not lockfile.exists():
        raise CheckSkipped("Cargo.lock missing (create it with cargo generate-lockfile)")
    command = [
        "osv-scanner", "scan", "source",
        "--format", "json",
        "--verbosity", "error",
        "--lockfile", str(lockfile),
    ]
    # OSV-Scanner returns 1 when it finds vulnerabilities.
    return parse_osv_scanner(load_json(run_command(command, cwd=directory, timeout=300)))


def _cargo_deny(directory: Path) -> list[Finding]:
    config = _deny_config(directory)
    command = [
        "cargo-deny", "--format", "json", "--color", "never",
        "--manifest-path", str(directory / "Cargo.toml"),
        "--config", str(config),
        # --locked: never rewrite the project's Cargo.lock.
        "--locked",
        "check", *DENY_CHECKS,
    ]
    result = run_command(command, cwd=directory, timeout=600)
    # cargo-deny writes one JSON object per line on stderr, and returns 1 on errors.
    if result.return_code not in (0, 1):
        raise ToolError(_deny_error(result.stderr, result.return_code))
    return parse_cargo_deny(result.stderr)


def _deny_error(stderr: str, code: int) -> str:
    """Prefer the "error: ..." line over the usage hints that follow it."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip() and not line.startswith("{")]
    errors = [line for line in lines if line.lower().startswith("error")]
    return (errors or lines or [f"return code {code}"])[0][:160]


def _cvss_severity(score: str) -> Severity | None:
    try:
        value = float(score)
    except ValueError:
        return None
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW if value > 0 else None


def _fixed_versions(vuln: dict) -> list[str]:
    return [
        event["fixed"]
        for affected in vuln.get("affected") or []
        for version_range in affected.get("ranges") or []
        for event in version_range.get("events") or []
        if "fixed" in event
    ]


def parse_osv_scanner(data: dict) -> list[Finding]:
    """One finding per vulnerability and package, rated with the CVSS score OSV provides."""
    findings = []
    for result in data.get("results") or []:
        for package in result.get("packages") or []:
            info = package.get("package", {})
            name, version = info.get("name", "?"), info.get("version", "?")
            scores = {
                vuln_id: group.get("max_severity", "")
                for group in package.get("groups") or []
                for vuln_id in group.get("ids") or []
            }
            for vuln in package.get("vulnerabilities") or []:
                vuln_id = vuln.get("id", "OSV-UNKNOWN")
                informational = next(
                    (
                        (affected.get("database_specific") or {}).get("informational")
                        for affected in vuln.get("affected") or []
                        if (affected.get("database_specific") or {}).get("informational")
                    ),
                    None,
                )
                if informational:
                    # Unmaintained or unsound crates: a warning, not an exploitable flaw.
                    severity, note = Severity.LOW, f"[{informational}] "
                else:
                    severity = _cvss_severity(scores.get(vuln_id, ""))
                    note = "" if severity else "[Unknown severity, defaulted to MEDIUM] "
                    severity = severity or Severity.MEDIUM
                fixes = _fixed_versions(vuln)
                aliases = ", ".join(vuln.get("aliases") or [])
                findings.append(Finding(
                    rule_id=vuln_id,
                    title=f"{name} {version}: {vuln.get('summary') or 'vulnerability'}",
                    severity=severity,
                    file_path="Cargo.lock",
                    description=(note + (vuln.get("details") or "")[:400] + (f" | Aliases: {aliases}" if aliases else "")),
                    remediation=f"Upgrade {name} to {', '.join(fixes)}" if fixes else "No fixed version yet",
                    scanner="osv-scanner",
                ))
    return findings


def parse_cargo_deny(output: str) -> list[Finding]:
    findings = []
    for line in output.splitlines():
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get("type") != "diagnostic":
            continue
        fields = entry.get("fields") or {}
        labels = fields.get("labels") or [{}]
        findings.append(Finding(
            rule_id=f"cargo-deny/{fields.get('code') or 'diagnostic'}",
            title=fields.get("message", "cargo-deny diagnostic"),
            severity=DENY_LEVELS.get(fields.get("severity", "warning"), Severity.MEDIUM),
            file_path="Cargo.lock",
            line=labels[0].get("line", 0) or 0,
            description=(labels[0].get("span") or "")[:300],
            remediation="See the [bans], [licenses] and [sources] sections of deny.toml",
            scanner="cargo-deny",
        ))
    return findings
