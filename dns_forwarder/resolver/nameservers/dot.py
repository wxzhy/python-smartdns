from __future__ import annotations

import dns.nameserver

from dns_forwarder.config import DoTNameserverConfig


def build_nameserver(config: DoTNameserverConfig) -> dns.nameserver.DoTNameserver:
    return dns.nameserver.DoTNameserver(
        config.address,
        port=config.port,
        hostname=config.hostname,
        verify=config.verify,
    )
