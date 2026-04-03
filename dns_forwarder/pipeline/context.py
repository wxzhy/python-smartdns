from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import dns.message
import dns.rcode
import dns.resolver


@dataclass(slots=True)
class UpstreamResult:
    upstream_name: str
    duration_ms: float
    answer: dns.resolver.Answer | None = None
    error: Exception | None = None

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
    selected_group: str | None = None
    final_answer: dns.resolver.Answer | None = None
    final_response: dns.message.Message | None = None
    drop_request: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    extensions: dict[str, Any] = field(default_factory=dict)
    answer_registry_refs: dict[str, Any] = field(default_factory=dict)
    upstream_results: list[UpstreamResult] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.request_id = self.request.id


def clone_response_for_request(response: dns.message.Message, request: dns.message.Message) -> dns.message.Message:
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


def make_error_response(request: dns.message.Message, rcode: dns.rcode.Rcode) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.set_rcode(rcode)
    response.id = request.id
    return response
