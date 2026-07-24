from __future__ import annotations

import queue
from typing import Any

import dns.resolver

from dns_forwarder.config import AppConfig
from dns_forwarder.pipeline import NestedResolveRecursionError

MSG_QUERY = "query"
MSG_QUERY_RESPONSE = "query_response"
MSG_QUERY_LOG = "query_log"
MSG_RESOLVE_REQUEST = "resolve_request"
MSG_RESOLVE_RESPONSE = "resolve_response"
MSG_STOP = "stop"
MSG_STOP_READER = "stop_reader"
MSG_WORKER_READY = "worker_ready"


def put_nowait(target_queue: Any, message: dict[str, Any]) -> None:
    try:
        target_queue.put_nowait(message)
    except (OSError, ValueError, queue.Full):
        pass


def close_queue(target_queue: Any) -> None:
    try:
        target_queue.close()
    except (OSError, ValueError):
        pass
    try:
        target_queue.join_thread()
    except (OSError, ValueError):
        pass


def is_query_log_plugin_enabled(config: AppConfig) -> bool:
    return any(
        plugin.enabled and plugin.module == "query_log_plugin"
        for plugin in config.plugins
    )


def query_log_max_entries(config: AppConfig) -> int:
    for plugin in config.plugins:
        if plugin.enabled and plugin.module == "query_log_plugin":
            value = plugin.config.get("max_entries", 500)
            return int(value)
    return 500


def serialize_resolve_error_type(exc: Exception) -> str:
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return "NXDOMAIN"
    if isinstance(exc, NestedResolveRecursionError):
        return "NestedResolveRecursionError"
    return type(exc).__name__


def deserialize_resolve_error(error_type: str, message: str) -> Exception:
    if error_type == "NXDOMAIN":
        return dns.resolver.NXDOMAIN()
    if error_type == "NestedResolveRecursionError":
        return NestedResolveRecursionError(message)
    return RuntimeError(message or error_type)
