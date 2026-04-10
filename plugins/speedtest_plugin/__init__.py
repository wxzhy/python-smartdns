from .models import IpRttResult, SPEEDTEST_CONTEXT_KEY, SPEEDTEST_SERVICE_KEY, SpeedTestContext
from .plugin import (
    SpeedTestFallbackRuleConfig,
    SpeedTestPlugin,
    SpeedTestPluginConfig,
    get_speedtest_context,
    plugin,
)
from .service import SpeedTestService

__all__ = [
    "IpRttResult",
    "SPEEDTEST_CONTEXT_KEY",
    "SPEEDTEST_SERVICE_KEY",
    "SpeedTestContext",
    "SpeedTestFallbackRuleConfig",
    "SpeedTestPlugin",
    "SpeedTestPluginConfig",
    "SpeedTestService",
    "get_speedtest_context",
    "plugin",
]
