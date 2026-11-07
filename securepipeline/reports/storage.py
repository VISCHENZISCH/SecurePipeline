"""Report files on disk."""

import json
import time
from pathlib import Path

from securepipeline.core.models import ScanResult

JSON_REPORT = "securepipeline-report.json"
MARKDOWN_REPORT = "securepipeline-report.md"
HTML_REPORT = "securepipeline-report.html"


def save_report(content: str, out_dir: str | Path, filename: str) -> Path:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    report = directory / filename
    report.write_text(content, encoding="utf-8")
    return report


def save_json_report(result: ScanResult, out_dir: str | Path) -> Path:
    """Keep the raw result, which the menu reads back without running a new scan."""
    return save_report(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), out_dir, JSON_REPORT)


def load_json_report(out_dir: str | Path) -> ScanResult | None:
    """Return the last result, or None if it is missing or unreadable."""
    try:
        data = json.loads((Path(out_dir) / JSON_REPORT).read_text(encoding="utf-8"))
        return ScanResult.from_dict(data)
    except (OSError, ValueError, TypeError, KeyError):
        return None


def report_age_seconds(out_dir: str | Path) -> float | None:
    try:
        return time.time() - (Path(out_dir) / JSON_REPORT).stat().st_mtime
    except OSError:
        return None
