"""SecurePipeline - Modèles de données."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """models.py::Niveaux de sévérité des findings------------------------------------#"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    """Un résultat de scan individuel."""
    rule_id: str
    title: str
    severity: Severity
    file_path: str = ""
    line: int = 0
    description: str = ""
    remediation: str = ""
    scanner: str = ""


@dataclass
class ScanResult:
    """Résultat agrégé d'un scan complet."""
    findings: list[Finding] = field(default_factory=list)
    stacks_scanned: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def exit_code(self, fail_on: str = "critical") -> int:
        """Retourne un code de sortie basé sur le seuil de sévérité.

        Args:
            fail_on: Seuil minimum pour échouer ("critical", "high", "medium", "low").

        Returns:
            0 si OK, 1 si des findings dépassent le seuil.
        """
        threshold = SEVERITY_RANK.get(Severity(fail_on), 4)
        for finding in self.findings:
            if SEVERITY_RANK.get(finding.severity, 0) >= threshold:
                return 1
        return 0
