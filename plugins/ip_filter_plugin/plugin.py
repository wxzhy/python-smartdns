from __future__ import annotations

import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.resolver

from dns_forwarder.core import IPSET_CONTEXT_KEY, IPSet
from dns_forwarder.pipeline import RequestContext, UpstreamResult
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry

from .models import IpFilterPluginConfig


ADDRESS_TYPES = {dns.rdatatype.A, dns.rdatatype.AAAA}


def get_ipset(context: RequestContext) -> IPSet:
    ipset = context.extensions[IPSET_CONTEXT_KEY]
    if not isinstance(ipset, IPSet):
        raise TypeError("core.ipset 类型不正确")
    return ipset


class IpFilterPlugin(Plugin):
    name = "ip-filter-plugin"
    config_model = IpFilterPluginConfig
    variables_model = EmptyModel
    upstream_response_order = 50
    ui_meta = {
        "title": "IP Filter Plugin",
        "description": "按请求 tags 与 IPSet tags 过滤 A/AAAA 响应中的地址。",
    }

    async def setup(self, registry: PluginRegistry) -> None:
        if not self.runtime_config.whitelist_tags and not self.runtime_config.blacklist_tags:
            raise ValueError("ip_filter_plugin 至少需要 whitelist_tags 或 blacklist_tags")
        return None

    async def on_upstream_response(self, context: RequestContext, result: UpstreamResult) -> None:
        if not self._matches_request(context.tags):
            return
        answer = result.answer
        if not self._is_filterable_answer(answer):
            return
        self._filter_answer(answer, get_ipset(context))

    def _matches_request(self, tags: set[str]) -> bool:
        if self._has_any_tag(tags, self.runtime_config.exclude_tags):
            return False
        if self.runtime_config.match_tags and not self._has_any_tag(tags, self.runtime_config.match_tags):
            return False
        return True

    @staticmethod
    def _is_filterable_answer(answer: dns.resolver.Answer | None) -> bool:
        if answer is None or answer.rrset is None:
            return False
        if answer.response.rcode() != dns.rcode.NOERROR:
            return False
        return answer.rdtype in ADDRESS_TYPES and answer.rrset.rdtype == answer.rdtype

    def _filter_answer(self, answer: dns.resolver.Answer, ipset: IPSet) -> None:
        rrset = answer.rrset
        if rrset is None:
            return

        kept_records = [
            record for record in rrset if self._should_keep_ip_tags(ipset.lookup(record.address))
        ]
        if len(kept_records) == len(rrset):
            return
        if not kept_records:
            answer.rrset = None
            return
        answer.rrset = dns.rrset.from_rdata_list(rrset.name, rrset.ttl, kept_records)

    def _should_keep_ip_tags(self, ip_tags: set[str]) -> bool:
        if self.runtime_config.whitelist_tags and not self._has_any_tag(ip_tags, self.runtime_config.whitelist_tags):
            return False
        if self._has_any_tag(ip_tags, self.runtime_config.blacklist_tags):
            return False
        return True

    @staticmethod
    def _has_any_tag(current_tags: set[str], configured_tags: list[str]) -> bool:
        return bool(current_tags.intersection(configured_tags))


plugin = IpFilterPlugin()
