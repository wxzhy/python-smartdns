from __future__ import annotations

import dns.nameserver

from dns_forwarder.config import Do53NameserverConfig


def build_nameserver(config: Do53NameserverConfig) -> dns.nameserver.Do53Nameserver:
    return dns.nameserver.Do53Nameserver(config.address, config.port)
