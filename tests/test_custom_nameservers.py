from __future__ import annotations

from unittest.mock import AsyncMock, patch

import dns.message
import dns.query

from dns_forwarder.resolver.nameservers._trick_sockets import (
    TrickyDatagramSocket,
    TrickyStreamSocket,
)
from dns_forwarder.resolver.nameservers.do53_custom import Do53CustomNameserver
from dns_forwarder.resolver.nameservers.doh_custom import DoHCustomNameserver, _get_shared_client


async def test_do53_custom_async_query_uses_tricky_udp_socket() -> None:
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    backend = object()
    nameserver = Do53CustomNameserver("127.0.0.1", 53)

    with patch("dns.asyncquery.udp", AsyncMock(return_value=response)) as udp_mock:
        result = await nameserver.async_query(
            request,
            timeout=1.0,
            source=None,
            source_port=0,
            max_size=False,
            backend=backend,
        )

    assert result is response
    udp_mock.assert_awaited_once()
    kwargs = udp_mock.await_args.kwargs
    assert isinstance(kwargs["sock"], TrickyDatagramSocket)
    assert kwargs["sock"].closed is True
    assert kwargs["raise_on_truncation"] is True
    assert kwargs["ignore_errors"] is True
    assert kwargs["ignore_unexpected"] is True


async def test_do53_custom_async_query_uses_tricky_tcp_socket() -> None:
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    backend = object()
    nameserver = Do53CustomNameserver("127.0.0.1", 53)

    with patch(
        "dns_forwarder.resolver.nameservers.do53_custom.TrickyStreamSocket.connect",
        AsyncMock(return_value=None),
    ) as connect_mock:
        with patch("dns.asyncquery.tcp", AsyncMock(return_value=response)) as tcp_mock:
            result = await nameserver.async_query(
                request,
                timeout=1.0,
                source=None,
                source_port=0,
                max_size=True,
                backend=backend,
            )

    assert result is response
    connect_mock.assert_awaited_once()
    tcp_mock.assert_awaited_once()
    kwargs = tcp_mock.await_args.kwargs
    assert isinstance(kwargs["sock"], TrickyStreamSocket)
    assert kwargs["sock"].closed is True


async def test_doh_custom_async_query_uses_shared_client_for_standard_settings() -> None:
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    nameserver = DoHCustomNameserver(
        "https://dns.example/dns-query",
        verify=True,
        want_get=True,
        http_version=dns.query.HTTPVersion.H2,
    )

    with patch("dns.asyncquery.https", AsyncMock(return_value=response)) as https_mock:
        result = await nameserver.async_query(
            request,
            timeout=1.0,
            source=None,
            source_port=0,
            max_size=False,
            backend=object(),
        )

    assert result is response
    https_mock.assert_awaited_once()
    kwargs = https_mock.await_args.kwargs
    assert kwargs["client"] is _get_shared_client()
    assert kwargs["post"] is False
    assert kwargs["http_version"] is dns.query.HTTPVersion.H2


@patch("dns.asyncquery.https", new_callable=AsyncMock)
async def test_doh_custom_async_query_falls_back_for_h3(https_mock: AsyncMock) -> None:
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    https_mock.return_value = response
    nameserver = DoHCustomNameserver(
        "https://dns.example/dns-query",
        verify=True,
        http_version=dns.query.HTTPVersion.H3,
    )

    result = await nameserver.async_query(
        request,
        timeout=1.0,
        source=None,
        source_port=0,
        max_size=False,
        backend=object(),
    )

    assert result is response
    assert "client" not in https_mock.await_args.kwargs


@patch("dns.asyncquery.https", new_callable=AsyncMock)
async def test_doh_custom_async_query_falls_back_for_bootstrap_address(
    https_mock: AsyncMock,
) -> None:
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    https_mock.return_value = response
    nameserver = DoHCustomNameserver(
        "https://dns.example/dns-query",
        bootstrap_address="1.1.1.1",
        verify=True,
        http_version=dns.query.HTTPVersion.H2,
    )

    result = await nameserver.async_query(
        request,
        timeout=1.0,
        source=None,
        source_port=0,
        max_size=False,
        backend=object(),
    )

    assert result is response
    assert "client" not in https_mock.await_args.kwargs


@patch("dns.asyncquery.https", new_callable=AsyncMock)
async def test_doh_custom_async_query_falls_back_for_custom_verify(https_mock: AsyncMock) -> None:
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    https_mock.return_value = response
    nameserver = DoHCustomNameserver(
        "https://dns.example/dns-query",
        verify="/tmp/cert.pem",
        http_version=dns.query.HTTPVersion.H2,
    )

    result = await nameserver.async_query(
        request,
        timeout=1.0,
        source=None,
        source_port=0,
        max_size=False,
        backend=object(),
    )

    assert result is response
    assert "client" not in https_mock.await_args.kwargs
