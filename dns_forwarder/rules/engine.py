from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import dns.rdatatype

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dns_forwarder.config import DispatchStrategyType, RuleConfig
    from dns_forwarder.pipeline.context import RequestContext


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

    def select(self, context: RequestContext) -> RuleSelection:
        qtype = dns.rdatatype.to_text(context.request.question[0].rdtype).upper()
        for rule in self._rules:
            if not rule.enabled:
                continue
            if not self._matches(rule, context.tags, qtype):
                continue
            return RuleSelection(
                upstream_group=rule.action.upstream_group or self._default_upstream_group,
                dispatcher=rule.action.dispatcher,
                rule_name=rule.name,
            )

        return RuleSelection(upstream_group=self._default_upstream_group)

    @staticmethod
    def _matches(rule: RuleConfig, tags: set[str], qtype: str) -> bool:
        match = rule.match

        if match.exclude_tags and any(tag in tags for tag in match.exclude_tags):
            return False
        if match.match_tags and not any(tag in tags for tag in match.match_tags):
            return False
        if match.qtypes and qtype not in match.qtypes:  # noqa: SIM103
            return False
        return True
