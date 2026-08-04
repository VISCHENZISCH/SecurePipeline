"""SecurePipeline - Configuration globale."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    """Configuration de SecurePipeline."""
    project_path: str = "."
    output_format: str = "md"
    fail_on: str = "critical"
    interactive: bool = True
    report_dir: str = ".securepipeline/reports"

    @property
    def report_path(self) -> Path:
        return Path(self.project_path) / self.report_dir
