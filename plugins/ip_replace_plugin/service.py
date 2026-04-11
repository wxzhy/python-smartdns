from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.resolver

from dns_forwarder.logging import format_tags, get_logger

from .models import IpReplaceRuleConfig

logger = get_logger("plugins.ip_replace")


@dataclass(frozen=True, slots=True)
class CompiledIpReplaceRule:
    name: str
    match_tags: frozenset[str]
    exclude_tags: frozenset[str]
    ipv4_targets: tuple[IPv4Network, ...]
    ipv6_targets: tuple[IPv6Network, ...]


class IpReplaceService:
    def __init__(self, rules: list[IpReplaceRuleConfig], skip_tags: list[str] | None = None) -> None:
        self._rules = tuple(self._compile_rule(rule) for rule in rules)
        self._skip_tags = frozenset(skip_tags or [])

    def replace_answer(self, answer: dns.resolver.Answer | None, tags: set[str], *, stage: str = "unknown") -> bool:
        if not tags:
            return False
        if self._skip_tags.intersection(tags):
            logger.debug("IP 替换跳过 stage=%s reason=skip_tags tags=%s", stage, format_tags(tags))
            return False
        if not self._is_normal_address_answer(answer):
            return False

        original_addresses = self._extract_addresses(answer)
        if not original_addresses:
            return False

        rule = self._match_rule(tags, version=4 if answer.rdtype == dns.rdatatype.A else 6)
        if rule is None:
            logger.debug(
                "IP 替换未命中规则 stage=%s qname=%s qtype=%s tags=%s",
                stage,
                answer.qname.to_text().rstrip("."),
                dns.rdatatype.to_text(answer.rdtype),
                format_tags(tags),
            )
            return False

        targets = rule.ipv4_targets if answer.rdtype == dns.rdatatype.A else rule.ipv6_targets
        replaced_addresses = self._expand_addresses(original_addresses, targets)
        if replaced_addresses == original_addresses:
            logger.debug(
                "IP 替换结果未变化 stage=%s qname=%s qtype=%s rule=%s",
                stage,
                answer.qname.to_text().rstrip("."),
                dns.rdatatype.to_text(answer.rdtype),
                rule.name,
            )
            return False

        answer.rrset = dns.rrset.from_text_list(
            answer.rrset.name,
            answer.rrset.ttl,
            answer.rdclass,
            answer.rdtype,
            replaced_addresses,
        )
        logger.debug(
            "IP 替换完成 stage=%s qname=%s qtype=%s rule=%s original_count=%s replaced_count=%s tags=%s",
            stage,
            answer.qname.to_text().rstrip("."),
            dns.rdatatype.to_text(answer.rdtype),
            rule.name,
            len(original_addresses),
            len(replaced_addresses),
            format_tags(tags),
        )
        return True

    @staticmethod
    def _is_normal_address_answer(answer: dns.resolver.Answer | None) -> bool:
        if answer is None or answer.rrset is None:
            return False
        if answer.response.rcode() != dns.rcode.NOERROR:
            return False
        return answer.rdtype in {dns.rdatatype.A, dns.rdatatype.AAAA}

    @staticmethod
    def _compile_rule(rule: IpReplaceRuleConfig) -> CompiledIpReplaceRule:
        return CompiledIpReplaceRule(
            name=rule.name,
            match_tags=frozenset(rule.match_tags),
            exclude_tags=frozenset(rule.exclude_tags),
            ipv4_targets=tuple(ip_network(item) for item in rule.ipv4_targets),
            ipv6_targets=tuple(ip_network(item) for item in rule.ipv6_targets),
        )

    def _match_rule(
        self,
        tags: set[str],
        *,
        version: int,
    ) -> CompiledIpReplaceRule | None:
        for rule in self._rules:
            if not rule.match_tags.intersection(tags):
                continue
            if rule.exclude_tags.intersection(tags):
                continue
            targets = rule.ipv4_targets if version == 4 else rule.ipv6_targets
            if targets:
                return rule
        return None

    @staticmethod
    def _extract_addresses(answer: dns.resolver.Answer) -> list[str]:
        addresses: list[str] = []
        for record in answer.rrset or ():
            address = getattr(record, "address", None)
            if address is not None:
                addresses.append(address)
        return addresses

    def _expand_addresses(
        self,
        original_addresses: list[str],
        targets: tuple[IPv4Network, ...] | tuple[IPv6Network, ...],
    ) -> list[str]:
        expanded: list[str] = []
        seen: set[str] = set()
        for address in original_addresses:
            original_ip = ip_address(address)
            for target in targets:
                replaced = self._map_ip_to_network(original_ip, target)
                text = replaced.compressed
                if text in seen:
                    continue
                seen.add(text)
                expanded.append(text)
        return expanded

    @staticmethod
    def _map_ip_to_network(
        original_ip: IPv4Address | IPv6Address,
        target: IPv4Network | IPv6Network,
    ) -> IPv4Address | IPv6Address:
        host_bits = original_ip.max_prefixlen - target.prefixlen
        host_mask = (1 << host_bits) - 1 if host_bits > 0 else 0
        mapped_value = int(target.network_address) | (int(original_ip) & host_mask)
        return ip_address(mapped_value)
