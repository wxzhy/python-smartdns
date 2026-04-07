from __future__ import annotations

import dns.nameserver

from dns_forwarder.config import DoQNameserverConfig


def build_nameserver(config: DoQNameserverConfig) -> dns.nameserver.DoQNameserver:
    return dns.nameserver.DoQNameserver(
        config.address,
        port=config.port,
        verify=config.verify,
        server_hostname=config.server_hostname,
    )
