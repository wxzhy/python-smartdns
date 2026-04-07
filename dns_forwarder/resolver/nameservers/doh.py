from __future__ import annotations

import dns.nameserver
import dns.query

from dns_forwarder.config import DoHNameserverConfig, HTTPVersionType


HTTP_VERSION_MAP: dict[HTTPVersionType, dns.query.HTTPVersion] = {
    HTTPVersionType.DEFAULT: dns.query.HTTPVersion.DEFAULT,
    HTTPVersionType.H1: dns.query.HTTPVersion.H1,
    HTTPVersionType.H2: dns.query.HTTPVersion.H2,
    HTTPVersionType.H3: dns.query.HTTPVersion.H3,
}


def build_nameserver(config: DoHNameserverConfig) -> dns.nameserver.DoHNameserver:
    return dns.nameserver.DoHNameserver(
        config.url,
        bootstrap_address=config.bootstrap_address,
        verify=config.verify,
        want_get=config.want_get,
        http_version=HTTP_VERSION_MAP[config.http_version],
    )
