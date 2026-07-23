from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dns_forwarder.logging import attach_caplog, configure_logging, detach_caplog


@pytest.fixture
def capture_dns_logs(caplog: pytest.LogCaptureFixture):
    """将 loguru 日志转发到 pytest caplog，便于断言日志文本。

    调用 ``capture_dns_logs("DEBUG")`` 即按级别捕获 ``dns_forwarder`` 的日志。
    """
    sink_ids: list[int] = []

    def attach(level: str = "DEBUG") -> None:
        configure_logging(level)
        caplog.set_level(getattr(logging, level.upper()), logger="dns_forwarder")
        sink_ids.append(attach_caplog(caplog.handler, level))

    yield attach

    for sink_id in sink_ids:
        detach_caplog(sink_id)
