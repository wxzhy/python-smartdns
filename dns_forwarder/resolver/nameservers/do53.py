from __future__ import annotations

from typing import TYPE_CHECKING

import dns.nameserver

if TYPE_CHECKING:
    from dns_forwarder.config import Do53NameserverConfig


def build_nameserver(config: Do53NameserverConfig) -> dns.nameserver.Do53Nameserver:
    return dns.nameserver.Do53Nameserver(config.address, config.port)
