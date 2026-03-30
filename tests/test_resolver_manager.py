from __future__ import annotations

from unittest.mock import patch

import dns.edns

from dns_forwarder.config import EDNSClientSubnetConfig, EDNSConfig, UpstreamConfig
from dns_forwarder.resolver.manager import UpstreamResolver


def test_upstream_resolver_configures_ecs_option() -> None:
    config = UpstreamConfig(
        name="local",
        host="127.0.0.1",
        port=53,
        edns=EDNSConfig(
            enabled=True,
            payload=1400,
            client_subnet=EDNSClientSubnetConfig(
                address="203.0.113.10",
                source_prefix=24,
                scope_prefix=0,
            ),
        ),
    )

    with patch("dns.asyncresolver.Resolver.use_edns") as use_edns:
        UpstreamResolver(config)

    use_edns.assert_called_once()
    kwargs = use_edns.call_args.kwargs
    assert kwargs["edns"] == 0
    assert kwargs["payload"] == 1400
    assert len(kwargs["options"]) == 1
    assert isinstance(kwargs["options"][0], dns.edns.ECSOption)


def test_upstream_resolver_skips_edns_when_not_configured() -> None:
    config = UpstreamConfig(name="local", host="127.0.0.1", port=53)

    with patch("dns.asyncresolver.Resolver.use_edns") as use_edns:
        UpstreamResolver(config)

    use_edns.assert_not_called()
