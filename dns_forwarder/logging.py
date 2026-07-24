from __future__ import annotations

import logging
from collections.abc import Collection

LOGGER_NAME = "dns_forwarder"
_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
_VALID_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}


def configure_logging(level: str) -> logging.Logger:
    normalized = level.upper()
    if normalized not in _VALID_LEVELS:
        raise ValueError(f"未知 log_level: {level}")

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, normalized))
    logger.propagate = False

    handler = next(
        (item for item in logger.handlers if getattr(item, "_dns_forwarder_handler", False)),
        None,
    )
    if handler is None:
        handler = logging.StreamHandler()
        setattr(handler, "_dns_forwarder_handler", True)
        logger.addHandler(handler)

    handler.setLevel(getattr(logging, normalized))
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    if not name or name == LOGGER_NAME:
        return logging.getLogger(LOGGER_NAME)
    if name.startswith(f"{LOGGER_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def format_tags(tags: Collection[str] | None) -> str:
    if not tags:
        return "[]"
    return "[" + ",".join(sorted(tags)) + "]"
