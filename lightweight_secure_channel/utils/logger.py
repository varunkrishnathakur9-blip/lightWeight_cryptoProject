"""Shared logger configuration."""

from __future__ import annotations

import logging


def configure_logger(name: str = "lscp", level: int = logging.INFO) -> logging.Logger:
    """Create or return a configured logger instance."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(name)s | %(levelname)s | %(message)s")
        )
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger

