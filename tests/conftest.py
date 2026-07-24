from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dns_forwarder.logging import configure_logging


@pytest.fixture
def capture_dns_logs(caplog: pytest.LogCaptureFixture):
    attached_loggers = []

    def attach(level: str = "DEBUG") -> None:
        logger = configure_logging(level)
        caplog.set_level(getattr(logging, level.upper()), logger="dns_forwarder")
        logger.addHandler(caplog.handler)
        attached_loggers.append(logger)

    yield attach

    for logger in attached_loggers:
        if caplog.handler in logger.handlers:
            logger.removeHandler(caplog.handler)
