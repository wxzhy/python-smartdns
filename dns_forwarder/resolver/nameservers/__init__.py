from __future__ import annotations

from collections.abc import Iterable

import dns.nameserver

from dns_forwarder.config import (
    Do53CustomNameserverConfig,
    Do53NameserverConfig,
    DoHCustomNameserverConfig,
    DoHNameserverConfig,
    DoQNameserverConfig,
    DoTNameserverConfig,
    NameserverConfig,
)

from .do53 import build_nameserver as build_do53_nameserver
from .do53_custom import build_nameserver as build_do53_custom_nameserver
from .doh import build_nameserver as build_doh_nameserver
from .doh_custom import build_nameserver as build_doh_custom_nameserver
from .doq import build_nameserver as build_doq_nameserver
from .dot import build_nameserver as build_dot_nameserver


def build_nameserver(config: NameserverConfig) -> dns.nameserver.Nameserver:
    if isinstance(config, Do53NameserverConfig):
        return build_do53_nameserver(config)
    if isinstance(config, Do53CustomNameserverConfig):
        return build_do53_custom_nameserver(config)
    if isinstance(config, DoHNameserverConfig):
        return build_doh_nameserver(config)
    if isinstance(config, DoHCustomNameserverConfig):
        return build_doh_custom_nameserver(config)
    if isinstance(config, DoTNameserverConfig):
        return build_dot_nameserver(config)
    if isinstance(config, DoQNameserverConfig):
        return build_doq_nameserver(config)
    raise TypeError(f"不支持的 nameserver 配置类型: {type(config).__name__}")


def build_nameserver_map(
    configs: Iterable[NameserverConfig],
) -> dict[str, dns.nameserver.Nameserver]:
    return {config.name: build_nameserver(config) for config in configs}


__all__ = [
    "build_nameserver",
    "build_nameserver_map",
]
