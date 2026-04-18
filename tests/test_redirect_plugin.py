from __future__ import annotations

import dns.message
import dns.rdatatype
import dns.resolver
import dns.rrset

from dns_forwarder.pipeline import RequestContext, build_answer_from_response
from dns_forwarder.plugin_api import PluginRegistry
from plugins.redirect_plugin import RedirectPlugin, RedirectPluginConfig


def make_answer(qname: str, qtype: str, *items: str):
    request = dns.message.make_query(qname, qtype)
    response = dns.message.make_response(request)
    if items:
        response.answer.append(
            dns.rrset.from_text(
                request.question[0].name.to_text(),
                120,
                "IN",
                qtype,
                *items,
            )
        )
    return build_answer_from_response(request, response)


def test_redirect_plugin_config_normalizes_redirect_map() -> None:
    config = RedirectPluginConfig(
        redirects={
            " Example.COM. ": " Target.Example. ",
            "api.example.com": "Alias.Example.COM.",
        }
    )

    assert config.redirects == {
        "example.com": "target.example",
        "api.example.com": "alias.example.com",
    }


async def test_redirect_plugin_builds_cname_plus_subquery_answer() -> None:
    plugin = RedirectPlugin()
    plugin.bind(
        RedirectPluginConfig(redirects={"example.com": "target.example"}),
        plugin.variables_model(),
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    request = dns.message.make_query("example.com", "A")

    async def resolve_handler(context: RequestContext, qname: str, qtype: str):
        assert context.request.question[0].name.to_text().rstrip(".") == "example.com"
        assert qname == "target.example"
        assert qtype == "A"
        return make_answer(qname, qtype, "203.0.113.10")

    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        _resolve_handler=resolve_handler,
    )

    await plugin.on_request(context)

    assert context.final_answer is not None
    assert context.stop_processing is False
    assert context.metadata["redirect_target"] == "target.example"
    assert context.final_answer.canonical_name.to_text().rstrip(".") == "target.example"
    assert context.final_answer.rrset is not None
    assert context.final_answer.rrset.rdtype == dns.rdatatype.A
    assert [item.address for item in context.final_answer.rrset] == ["203.0.113.10"]
    assert len(context.final_answer.response.answer) == 2
    assert context.final_answer.response.answer[0].rdtype == dns.rdatatype.CNAME
    assert context.final_answer.response.answer[0][0].target.to_text().rstrip(".") == (
        "target.example"
    )
    assert context.final_answer.response.answer[1].rdtype == dns.rdatatype.A
    assert context.final_answer.response.answer[1][0].address == "203.0.113.10"


async def test_redirect_plugin_skips_when_subquery_returns_no_rrset() -> None:
    plugin = RedirectPlugin()
    plugin.bind(
        RedirectPluginConfig(redirects={"example.com": "target.example"}),
        plugin.variables_model(),
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    request = dns.message.make_query("example.com", "TXT")

    async def resolve_handler(context: RequestContext, qname: str, qtype: str):
        assert qname == "target.example"
        assert qtype == "TXT"
        return make_answer(qname, qtype)

    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        _resolve_handler=resolve_handler,
    )

    await plugin.on_request(context)

    assert context.final_answer is None
    assert context.final_response is None


async def test_redirect_plugin_skips_when_subquery_raises_nxdomain() -> None:
    plugin = RedirectPlugin()
    plugin.bind(
        RedirectPluginConfig(redirects={"example.com": "target.example"}),
        plugin.variables_model(),
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    request = dns.message.make_query("example.com", "A")

    async def resolve_handler(context: RequestContext, qname: str, qtype: str):
        raise dns.resolver.NXDOMAIN()

    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        _resolve_handler=resolve_handler,
    )

    await plugin.on_request(context)

    assert context.final_answer is None
    assert context.final_response is None
