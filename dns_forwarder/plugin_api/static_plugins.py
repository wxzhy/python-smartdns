from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import ModuleType

STATIC_PLUGIN_MODULE_NAMES = (
    "block_plugin",
    "cache_plugin",
    "cloudflare_ech_plugin",
    "https_plugin",
    "ip_filter_plugin",
    "ip_replace_plugin",
    "query_log_plugin",
    "redirect_plugin",
    "sample_plugin",
    "speedtest_plugin",
    "tag_plugin",
)


def iter_static_plugin_module_names() -> tuple[str, ...]:
    return STATIC_PLUGIN_MODULE_NAMES


@cache
def _load_all_static_plugin_modules() -> dict[str, ModuleType]:
    # Keep the built-in plugin list explicit, but delay the imports until runtime
    # so plugin_api can finish initializing before plugins import it back.
    from plugins import (  # noqa: PLC0415 - lazy to break circular import with plugins
        block_plugin,
        cache_plugin,
        cloudflare_ech_plugin,
        https_plugin,
        ip_filter_plugin,
        ip_replace_plugin,
        query_log_plugin,
        redirect_plugin,
        sample_plugin,
        speedtest_plugin,
        tag_plugin,
    )

    return {
        "block_plugin": block_plugin,
        "cache_plugin": cache_plugin,
        "cloudflare_ech_plugin": cloudflare_ech_plugin,
        "https_plugin": https_plugin,
        "ip_filter_plugin": ip_filter_plugin,
        "ip_replace_plugin": ip_replace_plugin,
        "query_log_plugin": query_log_plugin,
        "redirect_plugin": redirect_plugin,
        "sample_plugin": sample_plugin,
        "speedtest_plugin": speedtest_plugin,
        "tag_plugin": tag_plugin,
    }


def load_static_plugin_module(module_name: str) -> ModuleType:
    try:
        return _load_all_static_plugin_modules()[module_name]
    except KeyError as exc:
        raise FileNotFoundError(f"未找到插件模块: {module_name}") from exc
