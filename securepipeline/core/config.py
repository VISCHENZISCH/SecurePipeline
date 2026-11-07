"""Scan configuration."""

import os
from dataclasses import dataclass
from pathlib import Path

FAIL_ON_CHOICES = ("critical", "high", "medium", "low")
FORMAT_CHOICES = ("md", "html", "both")
FORMAT_ALIASES = {"markdown": "md"}
DEFAULT_REPORT_DIR = ".securepipeline/reports"
MAX_DEFAULT_JOBS = 8


def default_jobs() -> int:
    """Cap parallelism: the external tools are heavy."""
    return min(MAX_DEFAULT_JOBS, os.cpu_count() or 4)


@dataclass
class Config:
    project_path: str = "."
    output_format: str = "md"
    fail_on: str = "critical"
    report_dir: str = DEFAULT_REPORT_DIR
    jobs: int = 0

    def __post_init__(self) -> None:
        self.jobs = self.jobs or default_jobs()
        self.output_format = FORMAT_ALIASES.get(self.output_format, self.output_format)

    @classmethod
    def from_env(cls) -> "Config":
        fail_on = os.environ.get("SECUREPIPELINE_FAIL_ON", "critical").lower()
        output_format = os.environ.get("SECUREPIPELINE_FORMAT", "md").lower()
        output_format = FORMAT_ALIASES.get(output_format, output_format)
        return cls(
            output_format=output_format if output_format in FORMAT_CHOICES else "md",
            fail_on=fail_on if fail_on in FAIL_ON_CHOICES else "critical",
            report_dir=os.environ.get("SECUREPIPELINE_REPORT_DIR", DEFAULT_REPORT_DIR),
        )

    @property
    def project_root(self) -> Path:
        return Path(self.project_path).resolve()

    @property
    def report_path(self) -> Path:
        """Report directory; a relative path starts at the scanned project."""
        return self.project_root / self.report_dir
