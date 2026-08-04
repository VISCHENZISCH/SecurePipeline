"""SecurePipeline - Logging minimal (pas de Rich)."""

import logging
import sys

def get_logger(name: str = "securepipeline", level: int = logging.WARNING) -> logging.Logger:
    """Cree un logger basique sans Rich.

    Args:
        name: Nom du logger.
        level: Niveau de log (WARNING par defaut pour ne pas polluer la sortie CLI).

    Returns:
        Logger configure.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(handler)

    logger.setLevel(level)
    return logger

# Logger global (silencieux par defaut, les messages passent par display.py)
log = get_logger()
