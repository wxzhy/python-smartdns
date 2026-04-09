from __future__ import annotations

import dns.rdataclass
import dns.rdatatype
import dns.resolver

from dns_forwarder.core import DOMAINSET_CONTEXT_KEY, IPSET_CONTEXT_KEY, DomainSet, IPSet
from dns_forwarder.pipeline import RequestContext, UpstreamResult
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry


def get_domainset(context: RequestContext) -> DomainSet:
    domainset = context.extensions[DOMAINSET_CONTEXT_KEY]
    if not isinstance(domainset, DomainSet):
        raise TypeError("core.domainset 类型不正确")
    return domainset


def get_ipset(context: RequestContext) -> IPSet:
    ipset = context.extensions[IPSET_CONTEXT_KEY]
    if not isinstance(ipset, IPSet):
        raise TypeError("core.ipset 类型不正确")
    return ipset


class TagPlugin(Plugin):
    name = "tag-plugin"
    config_model = EmptyModel
    variables_model = EmptyModel
    request_order = -100
    ui_meta = {
        "title": "Tag Plugin",
        "description": "基于域名和应答 IP 命中 tag 文件，为请求和上游结果追加标签。",
    }

    async def setup(self, registry: PluginRegistry) -> None:
        return None

    async def on_request(self, context: RequestContext) -> None:
        qname = context.request.question[0].name.to_text().rstrip(".")
        context.tags.update(get_domainset(context).lookup(qname))

    async def on_upstream_response(self, context: RequestContext, result: UpstreamResult) -> None:
        result.tags.update(context.tags)
        for ip in self._extract_unique_ips(result.answer):
            result.tags.update(get_ipset(context).lookup(ip))

    @staticmethod
    def _extract_unique_ips(answer: dns.resolver.Answer | None) -> list[str]:
        if answer is None or answer.rrset is None:
            return []
        if answer.rdtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            return []
        if answer.rdclass != dns.rdataclass.IN:
            return []

        seen: set[str] = set()
        addresses: list[str] = []
        for record in answer.rrset:
            address = getattr(record, "address", None)
            if address is None or address in seen:
                continue
            seen.add(address)
            addresses.append(address)
        return addresses


plugin = TagPlugin()
