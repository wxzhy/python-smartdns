from __future__ import annotations

from unittest.mock import AsyncMock, patch

import dns.message
import dns.edns
import dns.nameserver
import dns.query
import dns.rrset

from dns_forwarder.config import (
    Do53NameserverConfig,
    DoHNameserverConfig,
    DoQNameserverConfig,
    DoTNameserverConfig,
    ECSConfig,
    HTTPVersionType,
    UpstreamConfig,
)
from dns_forwarder.pipeline import RequestContext, build_answer_from_response
from dns_forwarder.resolver.manager import UpstreamResolver
from dns_forwarder.resolver.nameservers import build_nameserver, build_nameserver_map


def test_build_nameserver_supports_do53() -> None:
    nameserver = build_nameserver(
        Do53NameserverConfig(name="local", address="127.0.0.1", port=5301)
    )

    assert isinstance(nameserver, dns.nameserver.Do53Nameserver)
    assert nameserver.address == "127.0.0.1"
    assert nameserver.port == 5301


def test_build_nameserver_supports_doh() -> None:
    nameserver = build_nameserver(
        DoHNameserverConfig(
            name="cloudflare",
            url="https://cloudflare-dns.com/dns-query",
            bootstrap_address="1.1.1.1",
            want_get=True,
            http_version=HTTPVersionType.H2,
        )
    )

    assert isinstance(nameserver, dns.nameserver.DoHNameserver)
    assert nameserver.url == "https://cloudflare-dns.com/dns-query"
    assert nameserver.bootstrap_address == "1.1.1.1"
    assert nameserver.want_get is True
    assert nameserver.http_version is dns.query.HTTPVersion.H2


def test_build_nameserver_supports_dot() -> None:
    nameserver = build_nameserver(
        DoTNameserverConfig(
            name="quad9",
            address="9.9.9.9",
            port=853,
            hostname="dns.quad9.net",
            verify=True,
        )
    )

    assert isinstance(nameserver, dns.nameserver.DoTNameserver)
    assert nameserver.address == "9.9.9.9"
    assert nameserver.hostname == "dns.quad9.net"


def test_build_nameserver_supports_doq() -> None:
    nameserver = build_nameserver(
        DoQNameserverConfig(
            name="adguard",
            address="94.140.14.14",
            port=853,
            server_hostname="unfiltered.adguard-dns.com",
            verify=True,
        )
    )

    assert isinstance(nameserver, dns.nameserver.DoQNameserver)
    assert nameserver.address == "94.140.14.14"
    assert nameserver.server_hostname == "unfiltered.adguard-dns.com"


def test_build_nameserver_map_returns_named_instances() -> None:
    nameservers = build_nameserver_map(
        [
            Do53NameserverConfig(name="primary", address="127.0.0.1", port=5301),
            Do53NameserverConfig(name="backup", address="127.0.0.2", port=5302),
        ]
    )

    assert set(nameservers) == {"primary", "backup"}
    assert all(isinstance(item, dns.nameserver.Do53Nameserver) for item in nameservers.values())


def test_upstream_resolver_configures_ecs_option() -> None:
    config = UpstreamConfig(
        name="local",
        nameservers=["primary"],
        ecs=ECSConfig("203.0.113.10/24"),
    )

    with patch("dns.asyncresolver.Resolver.use_edns") as use_edns:
        UpstreamResolver(
            config,
            [dns.nameserver.Do53Nameserver("127.0.0.1", 53)],
        )

    use_edns.assert_called_once()
    kwargs = use_edns.call_args.kwargs
    assert len(kwargs["options"]) == 1
    assert isinstance(kwargs["options"][0], dns.edns.ECSOption)
    assert "payload" not in kwargs


def test_upstream_resolver_enables_rotate_for_multiple_nameservers() -> None:
    config = UpstreamConfig(name="local", nameservers=["primary", "backup"])
    resolver = UpstreamResolver(
        config,
        [
            dns.nameserver.Do53Nameserver("127.0.0.1", 53),
            dns.nameserver.Do53Nameserver("127.0.0.2", 53),
        ],
    )

    assert len(resolver.resolver.nameservers) == 2
    assert resolver.resolver.rotate is True


def test_upstream_resolver_skips_ecs_when_not_configured() -> None:
    config = UpstreamConfig(name="local", nameservers=["primary"])

    with patch("dns.asyncresolver.Resolver.use_edns") as use_edns:
        UpstreamResolver(config, [dns.nameserver.Do53Nameserver("127.0.0.1", 53)])

    use_edns.assert_not_called()


async def test_upstream_resolver_emits_debug_logs(capture_dns_logs, caplog) -> None:
    capture_dns_logs("DEBUG")
    config = UpstreamConfig(name="local", nameservers=["primary"], use_tcp=True)
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(dns.rrset.from_text("example.test.", 30, "IN", "A", "198.51.100.10"))
    answer = build_answer_from_response(request, response)
    resolver = UpstreamResolver(config, [dns.nameserver.Do53Nameserver("127.0.0.1", 53)])
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"domain-tag"},
    )

    with patch.object(resolver.resolver, "resolve", AsyncMock(return_value=answer)) as resolve_mock:
        result = await resolver.resolve(context)

    assert result.answer is answer
    resolve_mock.assert_awaited_once()
    assert resolve_mock.await_args.kwargs["tcp"] is True
    assert "发起上游查询" in caplog.text
    assert "上游查询成功" in caplog.text
    assert "tags=[domain-tag]" in caplog.text
