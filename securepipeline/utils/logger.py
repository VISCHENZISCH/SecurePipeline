"""Internal logger, silent by default: user-facing output goes through the UI."""

import logging
import os
import sys


def get_logger(name: str = "securepipeline", level: int | None = None) -> logging.Logger:
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("  [%(levelname)s] %(message)s"))
        logger.addHandler(handler)

    if level is None:
        requested = os.environ.get("SECUREPIPELINE_LOG_LEVEL", "WARNING").upper()
        level = logging.getLevelNamesMapping().get(requested, logging.WARNING)

    logger.setLevel(level)
    return logger


log = get_logger()
