from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import dns.message
import dns.rcode
import dns.resolver


class NestedResolveError(RuntimeError):
    """Raised when plugin nested resolve cannot be completed safely."""


class NestedResolveRecursionError(NestedResolveError):
    """Raised when plugin nested resolve enters a recursive call chain."""


NestedResolveHandler = Callable[
    ["RequestContext", str, str],
    Awaitable[dns.resolver.Answer],
]


@dataclass(slots=True)
class UpstreamResult:
    upstream_name: str
    duration_ms: float
    answer: dns.resolver.Answer | None = None
    error: Exception | None = None
    tags: set[str] = field(default_factory=set)

    @property
    def success(self) -> bool:
        return self.answer is not None


@dataclass(slots=True)
class RequestContext:
    request: dns.message.Message
    clientaddr: Any
    listener_name: str
    request_id: int = field(init=False)
    received_at: float = field(default_factory=time.monotonic)
    selected_rule: str | None = None
    selected_group: str | None = None
    selected_dispatcher: str | None = None
    final_answer: dns.resolver.Answer | None = None
    final_response: dns.message.Message | None = None
    drop_request: bool = False
    stop_processing: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)
    extensions: dict[str, Any] = field(default_factory=dict)
    answer_registry_refs: dict[str, Any] = field(default_factory=dict)
    upstream_results: list[UpstreamResult] = field(default_factory=list)
    _resolve_handler: NestedResolveHandler | None = field(default=None, repr=False)
    _nested_resolve_chain: tuple[tuple[str, str], ...] = field(default_factory=tuple, repr=False)
    _nested_resolve_max_depth: int = field(default=8, repr=False)

    def __post_init__(self) -> None:
        self.request_id = self.request.id

    @property
    def is_nested_resolve(self) -> bool:
        return bool(self._nested_resolve_chain)

    async def resolve(self, qname: str, qtype: str) -> dns.resolver.Answer:
        if self._resolve_handler is None:
            raise NestedResolveError("context.resolve 未初始化")

        normalized_qname = str(qname).strip().rstrip(".").lower()
        if not normalized_qname:
            raise ValueError("qname 不能为空")
        normalized_qtype = str(qtype).strip().upper()
        if not normalized_qtype:
            raise ValueError("qtype 不能为空")
        return await self._resolve_handler(self, normalized_qname, normalized_qtype)


def clone_response_for_request(
    response: dns.message.Message, request: dns.message.Message
) -> dns.message.Message:
    cloned = dns.message.from_wire(response.to_wire())
    cloned.id = request.id
    return cloned


def build_answer_from_response(
    request: dns.message.Message,
    response: dns.message.Message,
) -> dns.resolver.Answer:
    question = request.question[0]
    normalized_response = clone_response_for_request(response, request)
    answer = dns.resolver.Answer(
        question.name,
        question.rdtype,
        question.rdclass,
        normalized_response,
    )
    if answer.rrset is None and normalized_response.answer:
        rrset = normalized_response.answer[0]
        answer.rrset = rrset
        answer.canonical_name = rrset.name
        answer.expiration = time.time() + rrset.ttl
    return answer


def sync_answer_response(answer: dns.resolver.Answer) -> dns.resolver.Answer:
    rrset = answer.rrset
    if rrset is not None and (rrset.rdtype != answer.rdtype or rrset.rdclass != answer.rdclass):
        raise ValueError("answer.rrset 的类型或 class 与查询不一致")

    source_response = answer.response
    target_index: int | None = None
    for index, item in enumerate(source_response.answer):
        if item.rdtype == answer.rdtype and item.rdclass == answer.rdclass:
            target_index = index

    if rrset is None:
        if target_index is not None:
            del source_response.answer[target_index]
    elif target_index is not None:
        source_response.answer[target_index] = rrset
    else:
        source_response.answer.append(rrset)

    response = dns.message.from_wire(source_response.to_wire())

    rebuilt = dns.resolver.Answer(
        answer.qname,
        answer.rdtype,
        answer.rdclass,
        response,
        nameserver=answer.nameserver,
        port=answer.port,
    )
    answer.response = rebuilt.response
    answer.chaining_result = rebuilt.chaining_result
    answer.canonical_name = rebuilt.canonical_name
    answer.rrset = rebuilt.rrset
    answer.expiration = rebuilt.expiration
    return answer


def inherit_request_tags(result: UpstreamResult, request_tags: set[str]) -> UpstreamResult:
    if not request_tags:
        return result
    if result.tags is request_tags:
        result.tags = set(request_tags)
        return result
    result.tags.update(request_tags)
    return result


def make_error_response(
    request: dns.message.Message, rcode: dns.rcode.Rcode
) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.set_rcode(rcode)
    response.id = request.id
    return response
