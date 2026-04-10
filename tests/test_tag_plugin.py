from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from dns_forwarder.core import DOMAINSET_CONTEXT_KEY, IPSET_CONTEXT_KEY, DomainSet, IPSet
from dns_forwarder.pipeline import RequestContext, UpstreamResult, build_answer_from_response
from dns_forwarder.plugin_api import PluginManager, PluginRegistry
from plugins.tag_plugin import TagPlugin, get_domainset, get_ipset


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_domainset_merges_same_tag_files_and_domain_suffix_matches(tmp_path: Path) -> None:
    domain_dir = tmp_path / "domains"
    domain_dir.mkdir()
    _write_lines(domain_dir / "proxy.txt", ["example.org", "another.example.org", "# comment", "example.org"])
    _write_lines(domain_dir / "domestic.txt", ["www.example.org"])
    _write_lines(domain_dir / "deep.txt", ["b.c.com"])
    _write_lines(domain_dir / "suffix.txt", ["c.com"])

    domainset = DomainSet(str(domain_dir))

    assert domainset.lookup("www.example.org") == {"proxy", "domestic"}
    assert domainset.lookup("api.another.example.org") == {"proxy"}
    assert domainset.lookup("a.b.c.com") == {"deep", "suffix"}
    assert domainset.lookup("example.net") == set()


def test_ipset_unions_covering_ip_prefix_tags(tmp_path: Path) -> None:
    ip_dir = tmp_path / "ips"
    ip_dir.mkdir()
    _write_lines(ip_dir / "proxy.txt", ["203.0.112.0/20", "203.0.113.0/24", "203.0.113.8/32"])
    _write_lines(ip_dir / "domestic.txt", ["203.0.113.0/25"])

    ipset = IPSet(str(ip_dir))

    assert ipset.lookup("203.0.113.8") == {"proxy", "domestic"}
    assert ipset.lookup("203.0.113.200") == {"proxy"}
    assert ipset.lookup("198.51.100.8") == set()


def test_domainset_rejects_same_domain_in_multiple_tags(tmp_path: Path) -> None:
    domain_dir = tmp_path / "domains"
    domain_dir.mkdir()
    _write_lines(domain_dir / "proxy.txt", ["example.org"])
    _write_lines(domain_dir / "domestic.txt", ["example.org"])

    try:
        DomainSet(str(domain_dir))
    except ValueError as exc:
        assert "domain 重复归属多个 tag" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_ipset_rejects_same_network_in_multiple_tags(tmp_path: Path) -> None:
    ip_dir = tmp_path / "ips"
    ip_dir.mkdir()
    _write_lines(ip_dir / "proxy.txt", ["203.0.113.0/24"])
    _write_lines(ip_dir / "domestic.txt", ["203.0.113.0/24"])

    try:
        IPSet(str(ip_dir))
    except ValueError as exc:
        assert "network 重复归属多个 tag" in str(exc)
    else:
        raise AssertionError("expected ValueError")


async def test_tag_plugin_uses_shared_domainset_and_ipset(tmp_path: Path) -> None:
    domain_dir = tmp_path / "domains"
    ip_dir = tmp_path / "ips"
    domain_dir.mkdir()
    ip_dir.mkdir()
    _write_lines(domain_dir / "proxy.txt", ["example.org"])

    domainset = DomainSet(str(domain_dir))
    ipset = IPSet(str(ip_dir))
    plugin = TagPlugin()
    plugin.bind(plugin.config_model(), plugin.variables_model())
    registry = PluginRegistry()
    registry.register_context(DOMAINSET_CONTEXT_KEY, domainset)
    registry.register_context(IPSET_CONTEXT_KEY, ipset)

    await plugin.setup(registry)

    manager = PluginManager([], registry)
    extensions = manager.build_context_extensions()

    assert extensions[DOMAINSET_CONTEXT_KEY] is domainset
    assert extensions[IPSET_CONTEXT_KEY] is ipset


async def test_tag_plugin_adds_request_tags_from_domain_files(tmp_path: Path) -> None:
    domain_dir = tmp_path / "domains"
    ip_dir = tmp_path / "ips"
    domain_dir.mkdir()
    ip_dir.mkdir()
    _write_lines(domain_dir / "proxy.txt", ["example.org"])
    _write_lines(domain_dir / "domestic.txt", ["www.example.org"])

    plugin = TagPlugin()
    plugin.bind(plugin.config_model(), plugin.variables_model())
    registry = PluginRegistry()
    domainset = DomainSet(str(domain_dir))
    ipset = IPSet(str(ip_dir))
    registry.register_context(DOMAINSET_CONTEXT_KEY, domainset)
    registry.register_context(IPSET_CONTEXT_KEY, ipset)
    await plugin.setup(registry)
    manager = PluginManager([], registry)

    context = RequestContext(
        request=dns.message.make_query("www.example.org", "A"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions=manager.build_context_extensions(),
    )

    await plugin.on_request(context)

    assert context.tags == {"proxy", "domestic"}
    assert get_domainset(context) is context.extensions[DOMAINSET_CONTEXT_KEY]
    assert get_ipset(context) is context.extensions[IPSET_CONTEXT_KEY]


async def test_tag_plugin_adds_unique_answer_ip_tags_to_upstream_result(tmp_path: Path) -> None:
    domain_dir = tmp_path / "domains"
    ip_dir = tmp_path / "ips"
    domain_dir.mkdir()
    ip_dir.mkdir()
    _write_lines(domain_dir / "proxy.txt", ["example.org"])
    _write_lines(ip_dir / "cn.txt", ["203.0.113.0/24"])
    _write_lines(ip_dir / "direct.txt", ["203.0.113.10"])

    plugin = TagPlugin()
    plugin.bind(plugin.config_model(), plugin.variables_model())
    registry = PluginRegistry()
    registry.register_context(DOMAINSET_CONTEXT_KEY, DomainSet(str(domain_dir)))
    registry.register_context(IPSET_CONTEXT_KEY, IPSet(str(ip_dir)))
    await plugin.setup(registry)
    manager = PluginManager([], registry)

    context = RequestContext(
        request=dns.message.make_query("www.example.org", "A"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"proxy"},
        extensions=manager.build_context_extensions(),
    )
    response = dns.message.make_response(context.request)
    response.answer.append(
        dns.rrset.from_text(
            "www.example.org.",
            60,
            "IN",
            "A",
            "203.0.113.10",
            "203.0.113.10",
            "203.0.113.11",
        )
    )
    answer = build_answer_from_response(context.request, response)
    result = UpstreamResult(upstream_name="default", duration_ms=1.0, answer=answer, tags=context.tags.copy())

    await plugin.on_upstream_response(context, result)

    assert result.tags == {"proxy", "cn", "direct"}


async def test_tag_plugin_adds_cname_chain_domain_tags_to_upstream_result(tmp_path: Path) -> None:
    domain_dir = tmp_path / "domains"
    ip_dir = tmp_path / "ips"
    domain_dir.mkdir()
    ip_dir.mkdir()
    _write_lines(domain_dir / "request-tag.txt", ["example.org"])
    _write_lines(domain_dir / "mid-tag.txt", ["edge.example.net"])
    _write_lines(domain_dir / "final-tag.txt", ["target.cdn.net"])
    _write_lines(ip_dir / "cn.txt", ["203.0.113.0/24"])

    plugin = TagPlugin()
    plugin.bind(plugin.config_model(), plugin.variables_model())
    registry = PluginRegistry()
    registry.register_context(DOMAINSET_CONTEXT_KEY, DomainSet(str(domain_dir)))
    registry.register_context(IPSET_CONTEXT_KEY, IPSet(str(ip_dir)))
    await plugin.setup(registry)
    manager = PluginManager([], registry)

    context = RequestContext(
        request=dns.message.make_query("www.example.org", "A"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"request-tag"},
        extensions=manager.build_context_extensions(),
    )
    response = dns.message.make_response(context.request)
    response.answer.append(
        dns.rrset.from_text(
            "www.example.org.",
            60,
            "IN",
            "CNAME",
            "edge.example.net.",
        )
    )
    response.answer.append(
        dns.rrset.from_text(
            "edge.example.net.",
            60,
            "IN",
            "CNAME",
            "target.cdn.net.",
        )
    )
    response.answer.append(
        dns.rrset.from_text(
            "target.cdn.net.",
            60,
            "IN",
            "A",
            "203.0.113.10",
        )
    )
    answer = build_answer_from_response(context.request, response)
    result = UpstreamResult(upstream_name="default", duration_ms=1.0, answer=answer, tags=context.tags.copy())

    await plugin.on_upstream_response(context, result)

    assert result.tags == {"request-tag", "mid-tag", "final-tag", "cn"}


async def test_tag_plugin_adds_https_hint_ip_tags_to_upstream_result(tmp_path: Path) -> None:
    domain_dir = tmp_path / "domains"
    ip_dir = tmp_path / "ips"
    domain_dir.mkdir()
    ip_dir.mkdir()
    _write_lines(domain_dir / "request-tag.txt", ["example.org"])
    _write_lines(ip_dir / "v4-tag.txt", ["203.0.113.0/24"])
    _write_lines(ip_dir / "v6-tag.txt", ["2001:db8::/32"])

    plugin = TagPlugin()
    plugin.bind(plugin.config_model(), plugin.variables_model())
    registry = PluginRegistry()
    registry.register_context(DOMAINSET_CONTEXT_KEY, DomainSet(str(domain_dir)))
    registry.register_context(IPSET_CONTEXT_KEY, IPSet(str(ip_dir)))
    await plugin.setup(registry)
    manager = PluginManager([], registry)

    context = RequestContext(
        request=dns.message.make_query("www.example.org", "HTTPS"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"request-tag"},
        extensions=manager.build_context_extensions(),
    )
    response = dns.message.make_response(context.request)
    response.answer.append(
        dns.rrset.from_text(
            "www.example.org.",
            60,
            "IN",
            "HTTPS",
            '1 . ipv4hint="203.0.113.10" ipv6hint="2001:db8::10"',
        )
    )
    answer = build_answer_from_response(context.request, response)
    result = UpstreamResult(upstream_name="default", duration_ms=1.0, answer=answer, tags=context.tags.copy())

    await plugin.on_upstream_response(context, result)

    assert result.tags == {"request-tag", "v4-tag", "v6-tag"}


async def test_tag_plugin_adds_https_cname_and_hint_tags_to_upstream_result(tmp_path: Path) -> None:
    domain_dir = tmp_path / "domains"
    ip_dir = tmp_path / "ips"
    domain_dir.mkdir()
    ip_dir.mkdir()
    _write_lines(domain_dir / "request-tag.txt", ["example.org"])
    _write_lines(domain_dir / "mid-tag.txt", ["edge.example.net"])
    _write_lines(domain_dir / "final-tag.txt", ["svc.example.net"])
    _write_lines(ip_dir / "v4-tag.txt", ["203.0.113.0/24"])
    _write_lines(ip_dir / "v6-tag.txt", ["2001:db8::/32"])

    plugin = TagPlugin()
    plugin.bind(plugin.config_model(), plugin.variables_model())
    registry = PluginRegistry()
    registry.register_context(DOMAINSET_CONTEXT_KEY, DomainSet(str(domain_dir)))
    registry.register_context(IPSET_CONTEXT_KEY, IPSet(str(ip_dir)))
    await plugin.setup(registry)
    manager = PluginManager([], registry)

    context = RequestContext(
        request=dns.message.make_query("www.example.org", "HTTPS"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"request-tag"},
        extensions=manager.build_context_extensions(),
    )
    response = dns.message.make_response(context.request)
    response.answer.append(
        dns.rrset.from_text(
            "www.example.org.",
            60,
            "IN",
            "CNAME",
            "edge.example.net.",
        )
    )
    response.answer.append(
        dns.rrset.from_text(
            "edge.example.net.",
            60,
            "IN",
            "CNAME",
            "svc.example.net.",
        )
    )
    response.answer.append(
        dns.rrset.from_text(
            "svc.example.net.",
            60,
            "IN",
            "HTTPS",
            '1 . ipv4hint="203.0.113.10" ipv6hint="2001:db8::10"',
        )
    )
    answer = build_answer_from_response(context.request, response)
    result = UpstreamResult(upstream_name="default", duration_ms=1.0, answer=answer, tags=context.tags.copy())

    await plugin.on_upstream_response(context, result)

    assert result.tags == {"request-tag", "mid-tag", "final-tag", "v4-tag", "v6-tag"}


async def test_tag_plugin_skips_https_answers_without_hints(tmp_path: Path) -> None:
    domain_dir = tmp_path / "domains"
    ip_dir = tmp_path / "ips"
    domain_dir.mkdir()
    ip_dir.mkdir()
    _write_lines(ip_dir / "v4-tag.txt", ["203.0.113.0/24"])

    plugin = TagPlugin()
    plugin.bind(plugin.config_model(), plugin.variables_model())
    registry = PluginRegistry()
    registry.register_context(DOMAINSET_CONTEXT_KEY, DomainSet(str(domain_dir)))
    registry.register_context(IPSET_CONTEXT_KEY, IPSet(str(ip_dir)))
    await plugin.setup(registry)
    manager = PluginManager([], registry)

    context = RequestContext(
        request=dns.message.make_query("example.org", "HTTPS"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions=manager.build_context_extensions(),
    )
    response = dns.message.make_response(context.request)
    response.answer.append(
        dns.rrset.from_text(
            "example.org.",
            60,
            "IN",
            "HTTPS",
            '1 . alpn="h2"',
        )
    )
    answer = build_answer_from_response(context.request, response)
    result = UpstreamResult(upstream_name="default", duration_ms=1.0, answer=answer, tags={"proxy"})

    await plugin.on_upstream_response(context, result)

    assert result.tags == {"proxy"}


def test_tag_plugin_extract_https_hint_ips_does_not_deduplicate_addresses() -> None:
    request = dns.message.make_query("example.org", "HTTPS")
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            "example.org.",
            60,
            "IN",
            "HTTPS",
            '1 . ipv4hint="203.0.113.10,203.0.113.10" ipv6hint="2001:db8::10,2001:db8::10"',
        )
    )
    answer = build_answer_from_response(request, response)

    assert TagPlugin._extract_answer_ips(answer) == [
        "203.0.113.10",
        "203.0.113.10",
        "2001:db8::10",
        "2001:db8::10",
    ]


def test_tag_plugin_extract_answer_ips_does_not_deduplicate_addresses() -> None:
    answer = SimpleNamespace(
        rrset=[
            SimpleNamespace(address="203.0.113.10"),
            SimpleNamespace(address="203.0.113.10"),
            SimpleNamespace(address="203.0.113.11"),
        ],
        rdtype=dns.rdatatype.A,
        rdclass=dns.rdataclass.IN,
    )

    assert TagPlugin._extract_answer_ips(answer) == [
        "203.0.113.10",
        "203.0.113.10",
        "203.0.113.11",
    ]


async def test_tag_plugin_skips_non_address_answers(tmp_path: Path) -> None:
    domain_dir = tmp_path / "domains"
    ip_dir = tmp_path / "ips"
    domain_dir.mkdir()
    ip_dir.mkdir()
    _write_lines(ip_dir / "cn.txt", ["203.0.113.0/24"])

    plugin = TagPlugin()
    plugin.bind(plugin.config_model(), plugin.variables_model())
    registry = PluginRegistry()
    registry.register_context(DOMAINSET_CONTEXT_KEY, DomainSet(str(domain_dir)))
    registry.register_context(IPSET_CONTEXT_KEY, IPSet(str(ip_dir)))
    await plugin.setup(registry)
    manager = PluginManager([], registry)

    context = RequestContext(
        request=dns.message.make_query("example.org", "A"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions=manager.build_context_extensions(),
    )
    response = dns.message.make_response(context.request)
    response.answer.append(
        dns.rrset.from_text(
            "example.org.",
            60,
            "IN",
            "TXT",
            "\"hello\"",
        )
    )
    answer = build_answer_from_response(context.request, response)
    result = UpstreamResult(upstream_name="default", duration_ms=1.0, answer=answer, tags={"proxy"})

    await plugin.on_upstream_response(context, result)

    assert result.tags == {"proxy"}
