from __future__ import annotations

from unittest.mock import AsyncMock, patch

import dns.edns
import dns.message
import dns.nameserver
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from dns_forwarder.config import (
    DNSCryptNameserverConfig,
    Do53CustomNameserverConfig,
    Do53NameserverConfig,
    DoHAiohttpNameserverConfig,
    DoHCurlCffiNameserverConfig,
    DoHCustomNameserverConfig,
    DoHHttpxNameserverConfig,
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


def test_build_nameserver_supports_do53_custom() -> None:
    nameserver = build_nameserver(
        Do53CustomNameserverConfig(name="local-custom", address="127.0.0.1", port=5302)
    )

    assert nameserver.__class__.__name__ == "Do53CustomNameserver"
    assert nameserver.address == "127.0.0.1"
    assert nameserver.port == 5302


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


def test_build_nameserver_supports_doh_custom() -> None:
    nameserver = build_nameserver(
        DoHCustomNameserverConfig(
            name="cloudflare-custom",
            url="https://cloudflare-dns.com/dns-query",
            want_get=True,
            http_version=HTTPVersionType.H2,
        )
    )

    assert nameserver.__class__.__name__ == "DoHCustomNameserver"
    assert nameserver.url == "https://cloudflare-dns.com/dns-query"
    assert nameserver.want_get is True
    assert nameserver.http_version is dns.query.HTTPVersion.H2


def test_build_nameserver_supports_doh_httpx() -> None:
    with patch("dns_forwarder.resolver.nameservers.doh_httpx._get_shared_client") as client:
        nameserver = build_nameserver(
            DoHHttpxNameserverConfig(
                name="cloudflare-httpx",
                url="https://1.1.1.1/dns-query",
                want_get=True,
                http_version=HTTPVersionType.H2,
                http_host="cloudflare-dns.com",
                server_hostname="cloudflare-dns.com",
            )
        )

    assert nameserver.__class__.__name__ == "DoHHttpxNameserver"
    assert nameserver.url == "https://1.1.1.1/dns-query"
    assert nameserver.effective_url == "https://cloudflare-dns.com/dns-query"
    assert nameserver.http_host == "cloudflare-dns.com"
    client.assert_called_once_with(True, True)


def test_build_nameserver_supports_doh_aiohttp() -> None:
    nameserver = build_nameserver(
        DoHAiohttpNameserverConfig(
            name="cloudflare-aiohttp",
            url="https://1.1.1.1/dns-query",
            http_version=HTTPVersionType.H1,
            http_host="cloudflare-dns.com",
            server_hostname="cloudflare-dns.com",
        ),
        bootstrap_resolver=["1.1.1.1", "8.8.8.8"],
    )

    assert nameserver.__class__.__name__ == "DoHAiohttpNameserver"
    assert nameserver.url == "https://1.1.1.1/dns-query"
    assert nameserver.bootstrap_resolver == ("1.1.1.1", "8.8.8.8")
    assert nameserver.server_hostname == "cloudflare-dns.com"


def test_build_nameserver_supports_doh_curl_cffi() -> None:
    with patch("dns_forwarder.resolver.nameservers.doh_curl_cffi._get_shared_session") as session:
        nameserver = build_nameserver(
            DoHCurlCffiNameserverConfig(
                name="cloudflare-curl",
                url="https://1.1.1.1/dns-query",
                want_get=True,
                http_version=HTTPVersionType.H3,
                http_host="cloudflare-dns.com",
                server_hostname="cloudflare-dns.com",
            ),
            bootstrap_resolver=["1.1.1.1", "8.8.8.8"],
        )

    assert nameserver.__class__.__name__ == "DoHCurlCffiNameserver"
    assert nameserver.effective_url == "https://cloudflare-dns.com/dns-query"
    assert nameserver.resolve_entries == ("cloudflare-dns.com:443:1.1.1.1",)
    session.assert_called_once()
    assert session.call_args.kwargs["bootstrap_resolver"] == ("1.1.1.1", "8.8.8.8")


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


def test_build_nameserver_supports_dnscrypt() -> None:
    with patch("dns_forwarder.resolver.nameservers.dnscrypt.DNSCryptResolver") as resolver_cls:
        nameserver = build_nameserver(
            DNSCryptNameserverConfig(
                name="opendns-dnscrypt",
                address="208.67.220.220",
                port=443,
                provider_name="2.dnscrypt-cert.opendns.com",
                provider_pk=(
                    "B735:1140:206F:225D:3E2B:D822:D7FD:691E:"
                    "A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79"
                ),
            )
        )

    assert nameserver.__class__.__name__ == "DNSCryptNameserver"
    assert nameserver.address == "208.67.220.220"
    assert nameserver.port == 443
    resolver_cls.assert_called_once()


def test_build_nameserver_map_returns_named_instances() -> None:
    nameservers = build_nameserver_map(
        [
            Do53NameserverConfig(name="primary", address="127.0.0.1", port=5301),
            Do53CustomNameserverConfig(name="backup", address="127.0.0.2", port=5302),
        ]
    )

    assert set(nameservers) == {"primary", "backup"}
    assert isinstance(nameservers["primary"], dns.nameserver.Do53Nameserver)
    assert nameservers["backup"].__class__.__name__ == "Do53CustomNameserver"


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


@pytest.mark.parametrize(
    ("field_name", "field_value", "message"),
    [
        ("qname", dns.name.from_text("other.test."), "qname 不匹配"),
        ("rdtype", dns.rdatatype.AAAA, "rdtype 不匹配"),
        ("rdclass", dns.rdataclass.CH, "class 非 IN"),
    ],
)
async def test_upstream_resolver_rejects_invalid_answer_shape(
    field_name,
    field_value,
    message: str,
) -> None:
    config = UpstreamConfig(name="local", nameservers=["primary"], use_tcp=True)
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(dns.rrset.from_text("example.test.", 30, "IN", "A", "198.51.100.10"))
    answer = build_answer_from_response(request, response)
    setattr(answer, field_name, field_value)
    resolver = UpstreamResolver(config, [dns.nameserver.Do53Nameserver("127.0.0.1", 53)])
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"domain-tag"},
    )

    with patch.object(resolver.resolver, "resolve", AsyncMock(return_value=answer)):
        result = await resolver.resolve(context)

    assert result.answer is None
    assert isinstance(result.error, ValueError)
    assert message in str(result.error)
