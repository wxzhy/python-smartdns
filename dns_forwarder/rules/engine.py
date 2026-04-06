from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import dns.message
import dns.rdatatype

from dns_forwarder.config import DispatchStrategyType, RuleConfig


@dataclass(frozen=True, slots=True)
class RuleSelection:
    upstream_group: str
    dispatcher: DispatchStrategyType | None = None
    rule_name: str | None = None


class RuleEngine:
    def __init__(
        self,
        rules: Iterable[RuleConfig],
        default_upstream_group: str,
    ) -> None:
        self._rules = list(rules)
        self._default_upstream_group = default_upstream_group

    def select(self, request: dns.message.Message) -> RuleSelection:
        question = request.question[0]
        qname = question.name.to_text().rstrip(".").lower()
        qtype = dns.rdatatype.to_text(question.rdtype).upper()

        for rule in self._rules:
            if not rule.enabled:
                continue
            if not self._matches(rule, qname, qtype):
                continue
            return RuleSelection(
                upstream_group=rule.action.upstream_group or self._default_upstream_group,
                dispatcher=rule.action.dispatcher,
                rule_name=rule.name,
            )

        return RuleSelection(upstream_group=self._default_upstream_group)

    @staticmethod
    def _matches(rule: RuleConfig, qname: str, qtype: str) -> bool:
        match = rule.match

        if match.qtypes and qtype not in match.qtypes:
            return False

        exact_matched = not match.exact_domains or qname in match.exact_domains
        suffix_matched = not match.suffix_domains or any(
            qname == suffix or qname.endswith(f".{suffix}") for suffix in match.suffix_domains
        )

        if match.exact_domains and match.suffix_domains:
            return exact_matched or suffix_matched
        if match.exact_domains:
            return exact_matched
        if match.suffix_domains:
            return suffix_matched
        return True
