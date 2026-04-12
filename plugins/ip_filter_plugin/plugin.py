from __future__ import annotations

import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.resolver

from dns_forwarder.core import IPSET_CONTEXT_KEY, IPSet
from dns_forwarder.logging import format_tags, get_logger
from dns_forwarder.pipeline import RequestContext, UpstreamResult
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry

from .models import IpFilterPluginConfig

logger = get_logger("plugins.ip_filter")


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
        if context.request.question[0].rdtype not in ADDRESS_TYPES:
            return
        matches_request, reason = self._matches_request(context.tags)
        if not matches_request:
            logger.debug(
                "IP 过滤跳过 request_id=%s upstream=%s reason=%s request_tags=%s",
                context.request_id,
                result.upstream_name,
                reason,
                format_tags(context.tags),
            )
            return
        answer = result.answer
        if not self._is_filterable_answer(answer):
            return
        original_count, kept_count = self._filter_answer(answer, get_ipset(context))
        if original_count != kept_count:
            logger.debug(
                "IP 过滤已应用 request_id=%s upstream=%s qtype=%s original_count=%s kept_count=%s request_tags=%s",
                context.request_id,
                result.upstream_name,
                dns.rdatatype.to_text(answer.rdtype),
                original_count,
                kept_count,
                format_tags(context.tags),
            )

    def _matches_request(self, tags: set[str]) -> tuple[bool, str]:
        if self._has_any_tag(tags, self.runtime_config.exclude_tags):
            return False, "exclude_tags"
        if self.runtime_config.match_tags and not self._has_any_tag(tags, self.runtime_config.match_tags):
            return False, "match_tags_miss"
        return True, "matched"

    @staticmethod
    def _is_filterable_answer(answer: dns.resolver.Answer | None) -> bool:
        if answer is None or answer.rrset is None:
            return False
        if answer.response.rcode() != dns.rcode.NOERROR:
            return False
        return answer.rdtype in ADDRESS_TYPES and answer.rrset.rdtype == answer.rdtype

    def _filter_answer(self, answer: dns.resolver.Answer, ipset: IPSet) -> tuple[int, int]:
        rrset = answer.rrset
        if rrset is None:
            return 0, 0

        original_count = len(rrset)
        kept_records = [
            record for record in rrset if self._should_keep_ip_tags(ipset.lookup(record.address))
        ]
        if len(kept_records) == original_count:
            return original_count, original_count
        if not kept_records:
            answer.rrset = None
            return original_count, 0
        answer.rrset = dns.rrset.from_rdata_list(rrset.name, rrset.ttl, kept_records)
        return original_count, len(kept_records)

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
