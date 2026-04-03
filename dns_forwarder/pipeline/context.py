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


def make_error_response(request: dns.message.Message, rcode: dns.rcode.Rcode) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.set_rcode(rcode)
    response.id = request.id
    return response
