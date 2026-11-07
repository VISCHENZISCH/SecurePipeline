"""Scan data models."""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

TOOL_NOT_INSTALLED = "not installed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_label(cls, label: object, default: "Severity | None" = None) -> "Severity":
        """Convert a tool label ("HIGH", "moderate"...) to a severity."""
        normalized = str(label).strip().lower()
        if normalized == "moderate":
            return cls.MEDIUM
        try:
            return cls(normalized)
        except ValueError:
            return default if default is not None else cls.MEDIUM

    @property
    def label(self) -> str:
        return self.value.upper()


SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class CheckStatus(str, Enum):
    """Outcome of a tool run. SKIPPED and ERROR make the scan incomplete."""
    OK = "ok"
    NOTHING = "nothing"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    file_path: str = ""
    line: int = 0
    description: str = ""
    remediation: str = ""
    scanner: str = ""

    def __post_init__(self) -> None:
        self.severity = Severity(self.severity)

    @property
    def location(self) -> str:
        if self.file_path and self.line:
            return f"{self.file_path}:{self.line}"
        return self.file_path


@dataclass
class CheckResult:
    tool: str
    module: str
    status: CheckStatus
    detail: str = ""
    findings: int = 0
    duration: float = 0.0

    def __post_init__(self) -> None:
        self.status = CheckStatus(self.status)

    @property
    def is_incomplete(self) -> bool:
        return self.status in (CheckStatus.SKIPPED, CheckStatus.ERROR)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    stacks_scanned: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def incomplete_checks(self) -> list[CheckResult]:
        return [c for c in self.checks if c.is_incomplete]

    @property
    def is_complete(self) -> bool:
        return not self.incomplete_checks

    def severity_counts(self) -> dict[Severity, int]:
        counts = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def blocking_findings(self, fail_on: str = "critical") -> list[Finding]:
        threshold = SEVERITY_RANK[Severity(fail_on)]
        return [f for f in self.findings if SEVERITY_RANK[f.severity] >= threshold]

    def exit_code(self, fail_on: str = "critical", allow_incomplete: bool = False) -> int:
        """Return 1 for blocking findings, 2 for an incomplete scan, otherwise 0.

        An incomplete scan must never pass for a clean one.
        """
        if self.blocking_findings(fail_on):
            return 1
        if not self.is_complete and not allow_incomplete:
            return 2
        return 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        return cls(
            findings=[Finding(**f) for f in data.get("findings", [])],
            stacks_scanned=list(data.get("stacks_scanned", [])),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            checks=[CheckResult(**c) for c in data.get("checks", [])],
        )
