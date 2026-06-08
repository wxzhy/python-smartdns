from __future__ import annotations

from collections.abc import Iterable
from logging import Logger
from typing import Any

from dns_forwarder.config import ListenerConfig, ListenerProtocol
from dns_forwarder.server import TcpDnsServer, UdpDnsServer

DnsServer = UdpDnsServer | TcpDnsServer
ListenerStatus = dict[str, str | None]


def build_listener_status(
    services: Iterable[DnsServer],
    configured_listeners: Iterable[ListenerConfig],
) -> list[ListenerStatus]:
    listeners: list[ListenerStatus] = []
    for service in services:
        address = service.bound_address()
        listeners.append(
            {
                "name": service.listener.name,
                "protocol": service.listener.protocol.value,
                "address": f"{address[0]}:{address[1]}" if address else None,
            }
        )
    if listeners:
        return listeners

    return [
        {
            "name": listener.name,
            "protocol": listener.protocol.value,
            "address": None,
        }
        for listener in configured_listeners
    ]


async def start_dns_listeners(
    listeners: Iterable[ListenerConfig],
    runtime_manager: Any,
    *,
    logger: Logger,
    log_prefix: str,
) -> list[DnsServer]:
    services: list[DnsServer] = []
    for listener in listeners:
        if not listener.enabled:
            continue
        service = _build_dns_server(listener, runtime_manager)
        await service.start()
        services.append(service)
        bound_address = service.bound_address()
        logger.info(
            "%s name=%s protocol=%s address=%s:%s",
            log_prefix,
            listener.name,
            listener.protocol.value,
            bound_address[0] if bound_address else listener.host,
            bound_address[1] if bound_address else listener.port,
        )
    return services


async def stop_dns_listeners(services: list[DnsServer]) -> None:
    for service in services:
        await service.stop()
    services.clear()


def _build_dns_server(listener: ListenerConfig, runtime_manager: Any) -> DnsServer:
    if listener.protocol is ListenerProtocol.UDP:
        return UdpDnsServer(listener, runtime_manager)
    return TcpDnsServer(listener, runtime_manager)
