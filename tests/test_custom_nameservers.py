from __future__ import annotations

import socket
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch, sentinel

import dns.message
import dns.query
import dns.rcode
import dns.rdtypes.svcbbase
import pycares
from aiodns import error as aiodns_error

import dns_forwarder.resolver.nameservers.aiodns as aiodns_nameserver
from dns_forwarder.config import HTTPVersionType
from dns_forwarder.resolver.nameservers import doh_aiohttp, doh_curl_cffi
from dns_forwarder.resolver.nameservers._trick_tcp import (
    TrickyStreamSocket,
    _tcp_socket_factory,
)
from dns_forwarder.resolver.nameservers._trick_udp import TrickyDatagramSocket
from dns_forwarder.resolver.nameservers.aiodns import AiodnsDNSResolver, AiodnsNameserver
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


class FakeSocket:
    def __init__(self, family: int = socket.AF_INET) -> None:
        self.family = family
        self.options = []
        self.sent = []
        self.closed = False

    def setsockopt(self, level: int, option: int, value: int) -> None:
        self.options.append((level, option, value))

    def sendall(self, data: bytes, flags: int = 0) -> None:
        self.sent.append((data, flags))

    def close(self) -> None:
        self.closed = True

    def getpeername(self) -> tuple[str, int]:
        return ("192.0.2.10", 53)

    def getsockname(self) -> tuple[str, int]:
        return ("127.0.0.1", 5300)


def _doh_response_wire(request: dns.message.QueryMessage) -> bytes:
    response = dns.message.make_response(request)
    return response.to_wire()


def test_aiodns_dns_resolver_query_dns_supports_https() -> None:
    resolver = object.__new__(AiodnsDNSResolver)
    resolver._closed = True
    resolver._get_future_callback = Mock(return_value=(sentinel.future, sentinel.callback))
    resolver._channel = Mock()

    result = resolver.query_dns("example.test", "HTTPS", "IN")

    assert result is sentinel.future
    resolver._channel.query.assert_called_once_with(
        "example.test",
        pycares.QUERY_TYPE_HTTPS,
        query_class=pycares.QUERY_CLASS_IN,
        callback=sentinel.callback,
    )


def test_aiodns_dns_resolver_query_dns_delegates_non_https() -> None:
    resolver = object.__new__(AiodnsDNSResolver)
    resolver._closed = True

    with patch.object(
        aiodns_nameserver.aiodns.DNSResolver,
        "query_dns",
        return_value=sentinel.result,
    ) as query_dns:
        result = resolver.query_dns("example.test", "A", "IN")

    assert result is sentinel.result
    query_dns.assert_called_once_with("example.test", "A", "IN")


async def test_aiodns_get_resolver_configures_pycares_channel() -> None:
    aiodns_nameserver._RESOLVERS.clear()
    try:
        with patch(
            "dns_forwarder.resolver.nameservers.aiodns.AiodnsDNSResolver"
        ) as resolver_cls:
            result = aiodns_nameserver._get_resolver(
                ("1.1.1.1", "1.0.0.1"),
                5301,
                2.5,
                True,
            )

        assert result is resolver_cls.return_value
        kwargs = resolver_cls.call_args.kwargs
        assert kwargs["nameservers"] == ["1.1.1.1", "1.0.0.1"]
        assert kwargs["flags"] == pycares.ARES_FLAG_USEVC
        assert kwargs["timeout"] == 2.5
        assert kwargs["tcp_port"] == 5301
        assert kwargs["udp_port"] == 5301
        assert kwargs["rotate"] is True
    finally:
        aiodns_nameserver._RESOLVERS.clear()


async def test_aiodns_nameserver_async_query_fills_response_sections() -> None:
    request = dns.message.make_query("example.test", "HTTPS")
    result = pycares.DNSResult(
        answer=[
            pycares.DNSRecord(
                name="example.test",
                type=pycares.QUERY_TYPE_HTTPS,
                record_class=pycares.QUERY_CLASS_IN,
                ttl=60,
                data=pycares.HTTPSRecordData(
                    priority=1,
                    target="svc.example.test",
                    params=[(3, b"\x01\xbb")],
                ),
            )
        ],
        authority=[
            pycares.DNSRecord(
                name="example.test",
                type=pycares.QUERY_TYPE_NS,
                record_class=pycares.QUERY_CLASS_IN,
                ttl=300,
                data=pycares.NSRecordData(nsdname="ns.example.test"),
            )
        ],
        additional=[
            pycares.DNSRecord(
                name="ns.example.test",
                type=pycares.QUERY_TYPE_A,
                record_class=pycares.QUERY_CLASS_IN,
                ttl=300,
                data=pycares.ARecordData(addr="192.0.2.53"),
            )
        ],
    )
    fake_resolver = Mock()
    fake_resolver.query_dns = AsyncMock(return_value=result)
    nameserver = AiodnsNameserver(["1.1.1.1", "1.0.0.1"], port=5301, timeout=2.0)

    with patch(
        "dns_forwarder.resolver.nameservers.aiodns._get_resolver",
        return_value=fake_resolver,
    ) as get_resolver:
        response = await nameserver.async_query(
            request,
            timeout=1.0,
            source=None,
            source_port=0,
            max_size=False,
            backend=object(),
        )

    get_resolver.assert_called_once_with(nameserver.servers, 5301, 2.0, False)
    fake_resolver.query_dns.assert_awaited_once_with("example.test", "HTTPS", "IN")
    assert response.question == request.question
    assert response.answer[0].ttl == 60
    assert response.answer[0][0].priority == 1
    assert response.answer[0][0].target.to_text() == "svc.example.test."
    assert response.answer[0][0].params[dns.rdtypes.svcbbase.ParamKey.PORT].port == 443
    assert response.authority[0].to_text().startswith("example.test. 300 IN NS")
    assert response.additional[0].to_text().startswith("ns.example.test. 300 IN A")


async def test_aiodns_nameserver_async_query_supports_one_rr_per_rrset() -> None:
    request = dns.message.make_query("example.test", "A")
    result = pycares.DNSResult(
        answer=[
            pycares.DNSRecord(
                name="example.test",
                type=pycares.QUERY_TYPE_A,
                record_class=pycares.QUERY_CLASS_IN,
                ttl=60,
                data=pycares.ARecordData(addr="192.0.2.1"),
            ),
            pycares.DNSRecord(
                name="example.test",
                type=pycares.QUERY_TYPE_A,
                record_class=pycares.QUERY_CLASS_IN,
                ttl=60,
                data=pycares.ARecordData(addr="192.0.2.2"),
            ),
        ],
        authority=[],
        additional=[],
    )
    fake_resolver = Mock()
    fake_resolver.query_dns = AsyncMock(return_value=result)

    with patch(
        "dns_forwarder.resolver.nameservers.aiodns._get_resolver",
        return_value=fake_resolver,
    ):
        response = await AiodnsNameserver(["1.1.1.1"]).async_query(
            request,
            timeout=1.0,
            source=None,
            source_port=0,
            max_size=False,
            backend=object(),
            one_rr_per_rrset=True,
        )

    assert len(response.answer) == 2
    assert [rrset[0].address for rrset in response.answer] == ["192.0.2.1", "192.0.2.2"]


async def test_aiodns_nameserver_async_query_uses_tcp_for_max_size_and_maps_errors() -> None:
    request = dns.message.make_query("missing.test", "A")
    fake_resolver = Mock()
    fake_resolver.query_dns = AsyncMock(
        side_effect=aiodns_error.DNSError(aiodns_error.ARES_ENOTFOUND, "not found")
    )
    nameserver = AiodnsNameserver(["1.1.1.1"], port=5301, timeout=2.0)

    with patch(
        "dns_forwarder.resolver.nameservers.aiodns._get_resolver",
        return_value=fake_resolver,
    ) as get_resolver:
        response = await nameserver.async_query(
            request,
            timeout=1.0,
            source=None,
            source_port=0,
            max_size=True,
            backend=object(),
        )

    get_resolver.assert_called_once_with(nameserver.servers, 5301, 2.0, True)
    assert response.rcode() == dns.rcode.NXDOMAIN


async def test_aiodns_close_shared_sessions_closes_cached_resolvers() -> None:
    resolver = AsyncMock()
    key = aiodns_nameserver._ResolverKey(1, ("1.1.1.1",), 53, 1.0, False)
    aiodns_nameserver._RESOLVERS[key] = resolver

    await aiodns_nameserver.close_shared_sessions()

    resolver.close.assert_awaited_once()
    assert aiodns_nameserver._RESOLVERS == {}


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
    assert kwargs["sock"].use_tricks is True
    assert kwargs["sock"].closed is True


async def test_do53_custom_async_query_can_disable_udp_tricks() -> None:
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    nameserver = Do53CustomNameserver("127.0.0.1", 53, use_tricks=False)

    with patch("dns.asyncquery.udp", AsyncMock(return_value=response)) as udp_mock:
        result = await nameserver.async_query(
            request,
            timeout=1.0,
            source=None,
            source_port=0,
            max_size=False,
            backend=object(),
        )

    assert result is response
    udp_mock.assert_awaited_once()
    assert "sock" not in udp_mock.await_args.kwargs


async def test_do53_custom_async_query_keeps_custom_tcp_without_tricks() -> None:
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    nameserver = Do53CustomNameserver(
        "dns.example",
        53,
        use_tricks=False,
        hosts={"dns.example": ["192.0.2.10"]},
    )

    with patch(
        "dns_forwarder.resolver.nameservers.do53_custom.TrickyStreamSocket.connect",
        AsyncMock(return_value=None),
    ):
        with patch("dns.asyncquery.tcp", AsyncMock(return_value=response)) as tcp_mock:
            result = await nameserver.async_query(
                request,
                timeout=1.0,
                source=None,
                source_port=0,
                max_size=True,
                backend=object(),
            )

    assert result is response
    tcp_mock.assert_awaited_once()
    kwargs = tcp_mock.await_args.kwargs
    assert isinstance(kwargs["sock"], TrickyStreamSocket)
    assert kwargs["sock"].hosts == (("dns.example", ("192.0.2.10",)),)
    assert kwargs["sock"].use_tricks is False


async def test_tricky_tcp_connect_uses_hosts_with_happy_eyeballs() -> None:
    fake_socket = FakeSocket(socket.AF_INET)
    hosts = (("dns.example", ("192.0.2.10", "2001:db8::10")),)
    expected_addr_infos = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "DNS.EXAMPLE.",
            ("192.0.2.10", 53),
        ),
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "DNS.EXAMPLE.",
            ("2001:db8::10", 53, 0, 0),
        ),
    ]
    tricky_sock = TrickyStreamSocket(socket.AF_UNSPEC, socket.SOCK_STREAM, hosts=hosts)

    with (
        patch(
            "dns_forwarder.resolver.nameservers._trick_tcp.asyncio.get_running_loop"
        ) as get_running_loop,
        patch(
            "dns_forwarder.resolver.nameservers._trick_tcp.aiohappyeyeballs.start_connection",
            AsyncMock(return_value=fake_socket),
        ) as start_connection,
    ):
        await tricky_sock.connect(("DNS.EXAMPLE.", 53), timeout=1.0)

    get_running_loop.assert_not_called()
    start_connection.assert_awaited_once()
    assert start_connection.await_args.args == (expected_addr_infos,)
    assert start_connection.await_args.kwargs["local_addr_infos"] is None
    assert start_connection.await_args.kwargs["happy_eyeballs_delay"] == 0.25
    assert start_connection.await_args.kwargs["socket_factory"] is _tcp_socket_factory
    assert tricky_sock.family == socket.AF_INET


async def test_tricky_tcp_connect_falls_back_to_getaddrinfo() -> None:
    fake_socket = FakeSocket(socket.AF_INET)
    addr_infos = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("198.51.100.10", 53),
        )
    ]
    fake_loop = SimpleNamespace(getaddrinfo=AsyncMock(return_value=addr_infos))
    tricky_sock = TrickyStreamSocket(
        socket.AF_UNSPEC,
        socket.SOCK_STREAM,
        hosts=(),
        source="127.0.0.1",
        source_port=0,
    )

    with (
        patch(
            "dns_forwarder.resolver.nameservers._trick_tcp.asyncio.get_running_loop",
            return_value=fake_loop,
        ),
        patch(
            "dns_forwarder.resolver.nameservers._trick_tcp.aiohappyeyeballs.start_connection",
            AsyncMock(return_value=fake_socket),
        ) as start_connection,
    ):
        await tricky_sock.connect(("dns.example", 53), timeout=1.0)

    fake_loop.getaddrinfo.assert_awaited_once_with(
        "dns.example",
        53,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    start_connection.assert_awaited_once()
    assert start_connection.await_args.args == (addr_infos,)
    assert start_connection.await_args.kwargs["local_addr_infos"] == [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("127.0.0.1", 0),
        )
    ]


def test_tricky_tcp_socket_factory_sets_tcp_nodelay() -> None:
    fake_socket = FakeSocket(socket.AF_INET)
    addr_info = (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        ("192.0.2.10", 53),
    )

    with patch(
        "dns_forwarder.resolver.nameservers._trick_tcp.socket.socket",
        return_value=fake_socket,
    ) as socket_cls:
        result = _tcp_socket_factory(addr_info)

    assert result is fake_socket
    socket_cls.assert_called_once_with(
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    assert fake_socket.options == [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]


async def test_tricky_tcp_sendall_can_skip_oob_trick() -> None:
    fake_socket = FakeSocket(socket.AF_INET)
    fake_loop = SimpleNamespace(sock_sendall=AsyncMock(return_value=None))
    data = b"x" * 64
    tricky_sock = TrickyStreamSocket(
        socket.AF_UNSPEC,
        socket.SOCK_STREAM,
        use_tricks=False,
    )
    tricky_sock._socket = fake_socket

    with patch(
        "dns_forwarder.resolver.nameservers._trick_tcp.asyncio.get_running_loop",
        return_value=fake_loop,
    ):
        await tricky_sock.sendall(data, timeout=1.0)

    assert fake_socket.sent == []
    fake_loop.sock_sendall.assert_awaited_once_with(fake_socket, data)


async def test_tricky_tcp_sendall_uses_oob_trick_by_default() -> None:
    fake_socket = FakeSocket(socket.AF_INET)
    fake_loop = SimpleNamespace(sock_sendall=AsyncMock(return_value=None))
    data = b"x" * 64
    tricky_sock = TrickyStreamSocket(socket.AF_UNSPEC, socket.SOCK_STREAM)
    tricky_sock._socket = fake_socket

    with patch(
        "dns_forwarder.resolver.nameservers._trick_tcp.asyncio.get_running_loop",
        return_value=fake_loop,
    ):
        await tricky_sock.sendall(data, timeout=1.0)

    assert fake_socket.sent == [(data[:16] + b"\x00", socket.MSG_OOB)]
    fake_loop.sock_sendall.assert_awaited_once_with(fake_socket, data[16:])


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
        hosts={},
    )

    with patch(
        "dns_forwarder.resolver.nameservers.doh_aiohttp._get_shared_session",
        return_value=fake_session,
    ) as get_session:
        result = await nameserver.async_query(
            request,
            timeout=1.0,
            source=None,
            source_port=0,
            max_size=False,
            backend=object(),
        )

    assert result.question == request.question
    get_session.assert_called_once_with(("1.1.1.1",), ())
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
    ) as get_session:
        nameserver = DoHCurlCffiNameserver(
            "https://1.1.1.1/dns-query",
            verify=True,
            want_get=True,
            http_version=HTTPVersionType.H3,
            http_host="cloudflare-dns.com",
            fingerprint="chrome",
            bootstrap_resolver=["1.1.1.1"],
            hosts={
                "cloudflare-dns.com": [
                    "1.1.1.1",
                    "1.0.0.1",
                    "2606:4700:4700::1111",
                ]
            },
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
    expected_resolve_entries = (
        "cloudflare-dns.com:443:1.1.1.1,1.0.0.1,[2606:4700:4700::1111]",
    )
    assert get_session.call_args.args == (expected_resolve_entries,)
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
    doh_aiohttp._SHARED_HOSTS = None

    with (
        patch("dns_forwarder.resolver.nameservers.doh_aiohttp.AsyncResolver") as resolver,
        patch("dns_forwarder.resolver.nameservers.doh_aiohttp.aiohttp.TCPConnector") as connector,
        patch("dns_forwarder.resolver.nameservers.doh_aiohttp.aiohttp.ClientSession") as session,
    ):
        result = get_aiohttp_shared_session(("1.1.1.1", "8.8.8.8"), ())

    assert result is session.return_value
    resolver.assert_called_once_with(nameservers=["1.1.1.1", "8.8.8.8"])
    connector.assert_called_once_with(
        resolver=resolver.return_value,
        limit=500,
        keepalive_timeout=30,
    )
    session.assert_called_once_with(connector=connector.return_value)
    doh_aiohttp._SHARED_SESSION = None
    doh_aiohttp._SHARED_BOOTSTRAP_RESOLVER = None
    doh_aiohttp._SHARED_HOSTS = None


async def test_doh_aiohttp_hosts_resolver_returns_static_hosts() -> None:
    resolver = doh_aiohttp.HostsAsyncResolver(
        (("dns.example", ("192.0.2.10", "2001:db8::10")),)
    )
    try:
        result = await resolver.resolve("DNS.EXAMPLE.", 443, socket.AF_UNSPEC)
    finally:
        await resolver.close()

    assert result == [
        {
            "hostname": "DNS.EXAMPLE.",
            "host": "192.0.2.10",
            "port": 443,
            "family": socket.AF_INET,
            "proto": 0,
            "flags": socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
        },
        {
            "hostname": "DNS.EXAMPLE.",
            "host": "2001:db8::10",
            "port": 443,
            "family": socket.AF_INET6,
            "proto": 0,
            "flags": socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
        },
    ]


async def test_doh_aiohttp_shared_session_uses_hosts_resolver() -> None:
    doh_aiohttp._SHARED_SESSION = None
    doh_aiohttp._SHARED_BOOTSTRAP_RESOLVER = None
    doh_aiohttp._SHARED_HOSTS = None
    hosts = (("cloudflare-dns.com", ("1.1.1.1", "1.0.0.1")),)

    with (
        patch("dns_forwarder.resolver.nameservers.doh_aiohttp.HostsAsyncResolver") as resolver,
        patch("dns_forwarder.resolver.nameservers.doh_aiohttp.aiohttp.TCPConnector") as connector,
        patch("dns_forwarder.resolver.nameservers.doh_aiohttp.aiohttp.ClientSession") as session,
    ):
        result = get_aiohttp_shared_session(("8.8.8.8",), hosts)

    assert result is session.return_value
    resolver.assert_called_once_with(hosts, nameservers=["8.8.8.8"])
    connector.assert_called_once_with(
        resolver=resolver.return_value,
        limit=500,
        keepalive_timeout=30,
    )
    session.assert_called_once_with(connector=connector.return_value)
    doh_aiohttp._SHARED_SESSION = None
    doh_aiohttp._SHARED_BOOTSTRAP_RESOLVER = None
    doh_aiohttp._SHARED_HOSTS = None


def test_doh_curl_cffi_shared_session_uses_single_session() -> None:
    doh_curl_cffi._SHARED_SESSIONS = {}

    with patch("dns_forwarder.resolver.nameservers.doh_curl_cffi.AsyncSession") as session:
        result = get_curl_shared_session()

    assert result is session.return_value
    kwargs = session.call_args.kwargs
    assert kwargs == {"max_clients": 500}
    doh_curl_cffi._SHARED_SESSIONS = {}


def test_doh_curl_cffi_shared_session_uses_curl_resolve_entries() -> None:
    doh_curl_cffi._SHARED_SESSIONS = {}
    resolve_entries = ("cloudflare-dns.com:443:1.1.1.1,1.0.0.1",)

    with patch("dns_forwarder.resolver.nameservers.doh_curl_cffi.AsyncSession") as session:
        result = get_curl_shared_session(resolve_entries)

    assert result is session.return_value
    kwargs = session.call_args.kwargs
    assert kwargs == {
        "max_clients": 500,
        "curl_options": {doh_curl_cffi.CurlOpt.RESOLVE: list(resolve_entries)},
    }
    doh_curl_cffi._SHARED_SESSIONS = {}
