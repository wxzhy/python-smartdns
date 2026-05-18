from __future__ import annotations

import asyncio
import time

import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from dns_forwarder.pipeline import build_answer_from_response, clone_response_for_request


class FrontCache:
    def __init__(self, max_size: int) -> None:
        self._cache = dns.resolver.LRUCache(max_size=max_size)
        self._pending: dict[dns.resolver.CacheKey, asyncio.Future[bytes | None]] = {}
        self._pending_lock = asyncio.Lock()

    def get_response(self, request: dns.message.Message) -> dns.message.Message | None:
        key = self._make_key_from_request(request)
        if key is None:
            return None
        cached = self._cache.get(key)
        if cached is None:
            return None
        return self._clone_response(cached, request)

    def put_response(
        self,
        request: dns.message.Message,
        response: dns.message.Message | None,
    ) -> bool:
        if response is None or response.rcode() != dns.rcode.NOERROR:
            return False
        key = self._make_key_from_request(request)
        if key is None:
            return False

        answer = build_answer_from_response(request, response)
        if answer.rrset is None:
            return False
        self._cache.put(key, answer)
        return True

    async def acquire_pending(
        self,
        request: dns.message.Message,
    ) -> tuple[dns.resolver.CacheKey | None, asyncio.Future[bytes | None] | None]:
        key = self._make_key_from_request(request)
        if key is None:
            return None, None

        async with self._pending_lock:
            pending = self._pending.get(key)
            if pending is not None:
                return key, pending

            future: asyncio.Future[bytes | None] = asyncio.get_running_loop().create_future()
            self._pending[key] = future
            return key, None

    async def complete_pending(
        self,
        key: dns.resolver.CacheKey | None,
        response: dns.message.Message | None,
        *,
        cache_written: bool,
    ) -> None:
        if key is None:
            return

        async with self._pending_lock:
            pending = self._pending.pop(key, None)
        if pending is None or pending.done():
            return

        pending.set_result(None if cache_written or response is None else response.to_wire())

    @staticmethod
    async def wait_for_pending_response(
        pending: asyncio.Future[bytes | None],
        request: dns.message.Message,
    ) -> dns.message.Message | None:
        wire = await asyncio.shield(pending)
        if wire is None:
            return None
        return clone_response_for_request(dns.message.from_wire(wire), request)

    @staticmethod
    def _make_key_from_request(request: dns.message.Message) -> dns.resolver.CacheKey | None:
        if request.opcode() != dns.opcode.QUERY or len(request.question) != 1:
            return None
        question = request.question[0]
        if question.rdclass != dns.rdataclass.IN:
            return None
        return question.name, question.rdtype, question.rdclass

    @staticmethod
    def _clone_response(
        answer: dns.resolver.Answer,
        request: dns.message.Message,
    ) -> dns.message.Message:
        cloned = clone_response_for_request(answer.response, request)
        remaining_ttl = max(0, int(answer.expiration - time.time()))
        for section in (cloned.answer, cloned.authority, cloned.additional):
            for rrset in section:
                if rrset.rdtype in {dns.rdatatype.OPT, dns.rdatatype.TSIG}:
                    continue
                rrset.ttl = remaining_ttl
        return cloned
