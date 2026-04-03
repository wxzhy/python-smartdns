from __future__ import annotations

from unittest.mock import AsyncMock, patch

import dns.message
import dns.edns
import dns.rrset

from dns_forwarder.config import EDNSClientSubnetConfig, EDNSConfig, UpstreamConfig
from dns_forwarder.pipeline import RequestContext, build_answer_from_response
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


async def test_upstream_resolver_emits_debug_logs(capture_dns_logs, caplog) -> None:
    capture_dns_logs("DEBUG")
    config = UpstreamConfig(name="local", host="127.0.0.1", port=53)
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(dns.rrset.from_text("example.test.", 30, "IN", "A", "198.51.100.10"))
    answer = build_answer_from_response(request, response)
    resolver = UpstreamResolver(config)
    context = RequestContext(request=request, clientaddr=("127.0.0.1", 5300), listener_name="udp")

    with patch.object(resolver.resolver, "resolve", AsyncMock(return_value=answer)):
        result = await resolver.resolve(context)

    assert result.answer is answer
    assert "发起上游查询" in caplog.text
    assert "上游查询成功" in caplog.text
