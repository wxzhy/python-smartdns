from __future__ import annotations

from unittest.mock import AsyncMock, patch

import dns.message
import dns.query

from dns_forwarder.config import HTTPVersionType
from dns_forwarder.resolver.nameservers import doh_aiohttp, doh_curl_cffi
from dns_forwarder.resolver.nameservers._trick_sockets import (
    TrickyDatagramSocket,
    TrickyStreamSocket,
)
from dns_forwarder.resolver.nameservers.do53_custom import Do53CustomNameserver
from dns_forwarder.resolver.nameservers.doh_aiohttp import (
    DoHAiohttpNameserver,
)
from dns_forwarder.resolver.nameservers.doh_aiohttp import (
    _get_shared_session as get_aiohttp_shared_session,
)
from dns_forwarder.resolver.nameservers.doh_curl_cffi import (
    DoHCurlCffiNameserver,
)
from dns_forwarder.resolver.nameservers.doh_curl_cffi import (
    _get_shared_session as get_curl_shared_session,
)
from dns_forwarder.resolver.nameservers.doh_custom import DoHCustomNameserver, _get_shared_client
from dns_forwarder.resolver.nameservers.doh_httpx import DoHHttpxNameserver


class FakeResponse:
    def __init__(self, content: bytes) -> None:
        self.content = content

    def raise_for_status(self) -> None:
        return None


class FakeAiohttpResponse:
    def __init__(self, content: bytes) -> None:
        self._content = content

    async def __aenter__(self) -> "FakeAiohttpResponse":
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None

    def raise_for_status(self) -> None:
        return None

    async def read(self) -> bytes:
        return self._content


def _doh_response_wire(request: dns.message.QueryMessage) -> bytes:
    response = dns.message.make_response(request)
    return response.to_wire()


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


async def test_doh_httpx_get_query_uses_dns_param_and_host_header() -> None:
    request = dns.message.make_query("example.test", "A")
    fake_client = AsyncMock()
    fake_client.request.return_value = FakeResponse(_doh_response_wire(request))

    with patch(
        "dns_forwarder.resolver.nameservers.doh_httpx._get_shared_client",
        return_value=fake_client,
    ):
        nameserver = DoHHttpxNameserver(
            "https://1.1.1.1/dns-query",
            verify=True,
            want_get=True,
            http_version=HTTPVersionType.H2,
            http_host="cloudflare-dns.com",
            server_hostname="cloudflare-dns.com",
        )
        result = await nameserver.async_query(
            request,
            timeout=1.0,
            source=None,
            source_port=0,
            max_size=False,
            backend=object(),
        )

    assert result.question == request.question
    fake_client.request.assert_awaited_once()
    args = fake_client.request.await_args.args
    kwargs = fake_client.request.await_args.kwargs
    assert args[0] == "GET"
    assert args[1].startswith("https://1.1.1.1/dns-query?dns=")
    assert kwargs["headers"]["Host"] == "cloudflare-dns.com"
    assert kwargs["content"] is None
    assert kwargs["extensions"] == {"sni_hostname": "cloudflare-dns.com"}


async def test_doh_aiohttp_post_query_passes_tls_hostname_and_body() -> None:
    request = dns.message.make_query("example.test", "A")

    class FakeSession:
        def __init__(self) -> None:
            self.call_kwargs = {}

        def request(self, *args, **kwargs) -> FakeAiohttpResponse:
            self.call_args = args
            self.call_kwargs = kwargs
            return FakeAiohttpResponse(_doh_response_wire(request))

    fake_session = FakeSession()
    nameserver = DoHAiohttpNameserver(
        "https://1.1.1.1/dns-query",
        verify=True,
        want_get=False,
        http_version=HTTPVersionType.H1,
        http_host="cloudflare-dns.com",
        server_hostname="cloudflare-dns.com",
        bootstrap_resolver=["1.1.1.1"],
    )

    with patch(
        "dns_forwarder.resolver.nameservers.doh_aiohttp._get_shared_session",
        return_value=fake_session,
    ):
        result = await nameserver.async_query(
            request,
            timeout=1.0,
            source=None,
            source_port=0,
            max_size=False,
            backend=object(),
        )

    assert result.question == request.question
    assert fake_session.call_args == ("POST", "https://1.1.1.1/dns-query")
    assert fake_session.call_kwargs["headers"]["Host"] == "cloudflare-dns.com"
    assert fake_session.call_kwargs["headers"]["Content-Type"] == "application/dns-message"
    assert fake_session.call_kwargs["data"] == request.to_wire()
    assert fake_session.call_kwargs["server_hostname"] == "cloudflare-dns.com"


async def test_doh_curl_cffi_get_query_uses_request_options_and_host_header() -> None:
    request = dns.message.make_query("example.test", "A")
    fake_session = AsyncMock()
    fake_session.request.return_value = FakeResponse(_doh_response_wire(request))

    with patch(
        "dns_forwarder.resolver.nameservers.doh_curl_cffi._get_shared_session",
        return_value=fake_session,
    ):
        nameserver = DoHCurlCffiNameserver(
            "https://1.1.1.1/dns-query",
            verify=True,
            want_get=True,
            http_version=HTTPVersionType.H3,
            http_host="cloudflare-dns.com",
            fingerprint="chrome",
            bootstrap_resolver=["1.1.1.1"],
        )
        result = await nameserver.async_query(
            request,
            timeout=1.0,
            source=None,
            source_port=0,
            max_size=False,
            backend=object(),
        )

    assert result.question == request.question
    fake_session.request.assert_awaited_once()
    args = fake_session.request.await_args.args
    kwargs = fake_session.request.await_args.kwargs
    assert args[0] == "GET"
    assert args[1].startswith("https://1.1.1.1/dns-query?dns=")
    assert kwargs["headers"]["Host"] == "cloudflare-dns.com"
    assert kwargs["data"] is None
    assert kwargs["verify"] is True
    assert kwargs["http_version"] is not None
    assert kwargs["impersonate"] == "chrome"
    assert "ja3" not in kwargs
    assert "akamai" not in kwargs
    assert "extra_fp" not in kwargs


async def test_doh_aiohttp_shared_session_uses_bootstrap_resolver() -> None:
    doh_aiohttp._SHARED_SESSION = None
    doh_aiohttp._SHARED_BOOTSTRAP_RESOLVER = None

    with (
        patch("dns_forwarder.resolver.nameservers.doh_aiohttp.AsyncResolver") as resolver,
        patch("dns_forwarder.resolver.nameservers.doh_aiohttp.aiohttp.TCPConnector") as connector,
        patch("dns_forwarder.resolver.nameservers.doh_aiohttp.aiohttp.ClientSession") as session,
    ):
        result = get_aiohttp_shared_session(("1.1.1.1", "8.8.8.8"))

    assert result is session.return_value
    resolver.assert_called_once_with(nameservers=["1.1.1.1", "8.8.8.8"])
    connector.assert_called_once_with(resolver=resolver.return_value, limit=500)
    session.assert_called_once_with(connector=connector.return_value)
    doh_aiohttp._SHARED_SESSION = None
    doh_aiohttp._SHARED_BOOTSTRAP_RESOLVER = None


def test_doh_curl_cffi_shared_session_uses_single_session() -> None:
    doh_curl_cffi._SHARED_SESSION = None

    with patch("dns_forwarder.resolver.nameservers.doh_curl_cffi.AsyncSession") as session:
        result = get_curl_shared_session()

    assert result is session.return_value
    kwargs = session.call_args.kwargs
    assert kwargs == {"max_clients": 500}
    doh_curl_cffi._SHARED_SESSION = None
