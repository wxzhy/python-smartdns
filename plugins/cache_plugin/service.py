from __future__ import annotations

import asyncio
import time

import dns.message
import dns.rdatatype
import dns.resolver

from dns_forwarder.pipeline import clone_response_for_request


class DnsCacheService:
    def __init__(self, *, max_size: int) -> None:
        self._cache = dns.resolver.LRUCache(max_size=max_size)
        self._pending: dict[dns.resolver.CacheKey, asyncio.Future[bytes | None]] = {}
        self._pending_lock = asyncio.Lock()

    @staticmethod
    def make_key(
        qname,
        rdtype,
        rdclass,
    ) -> dns.resolver.CacheKey:
        return (qname, rdtype, rdclass)

    @classmethod
    def make_key_from_request(cls, request: dns.message.Message) -> dns.resolver.CacheKey:
        question = request.question[0]
        return cls.make_key(question.name, question.rdtype, question.rdclass)

    @classmethod
    def make_key_from_answer(cls, answer: dns.resolver.Answer) -> dns.resolver.CacheKey:
        return cls.make_key(answer.qname, answer.rdtype, answer.rdclass)

    def get_for_request(self, request: dns.message.Message) -> dns.resolver.Answer | None:
        cached = self._cache.get(self.make_key_from_request(request))
        if cached is None:
            return None
        return self._clone_answer(
            cached, remaining_ttl=max(0, int(cached.expiration - time.time()))
        )

    def put_answer(self, answer: dns.resolver.Answer) -> None:
        self._cache.put(self.make_key_from_answer(answer), self._clone_answer(answer))

    async def acquire_pending(
        self, key: dns.resolver.CacheKey
    ) -> asyncio.Future[bytes | None] | None:
        async with self._pending_lock:
            pending = self._pending.get(key)
            if pending is not None:
                return pending

            future: asyncio.Future[bytes | None] = asyncio.get_running_loop().create_future()
            self._pending[key] = future
            return None

    async def complete_pending(
        self,
        key: dns.resolver.CacheKey,
        response: dns.message.Message | None,
    ) -> None:
        async with self._pending_lock:
            pending = self._pending.pop(key, None)

        if pending is None or pending.done():
            return
        pending.set_result(response.to_wire() if response is not None else None)

    async def has_pending(self, key: dns.resolver.CacheKey) -> bool:
        async with self._pending_lock:
            return key in self._pending

    @staticmethod
    async def wait_for_pending_response(
        pending: asyncio.Future[bytes | None],
        request: dns.message.Message,
    ) -> dns.message.Message | None:
        wire = await asyncio.shield(pending)
        if wire is None:
            return None
        return clone_response_for_request(dns.message.from_wire(wire), request)

    def flush(self, key: dns.resolver.CacheKey | None = None) -> None:
        self._cache.flush(key)

    def hits(self) -> int:
        return self._cache.hits()

    def misses(self) -> int:
        return self._cache.misses()

    @staticmethod
    def _clone_answer(
        answer: dns.resolver.Answer, remaining_ttl: int | None = None
    ) -> dns.resolver.Answer:
        cloned_response = dns.message.from_wire(answer.response.to_wire())
        if remaining_ttl is not None:
            for section in (
                cloned_response.answer,
                cloned_response.authority,
                cloned_response.additional,
            ):
                for rrset in section:
                    if rrset.rdtype in {dns.rdatatype.OPT, dns.rdatatype.TSIG}:
                        continue
                    rrset.ttl = remaining_ttl
        cloned_answer = dns.resolver.Answer(
            answer.qname,
            answer.rdtype,
            answer.rdclass,
            cloned_response,
            nameserver=answer.nameserver,
            port=answer.port,
        )
        cloned_answer.expiration = answer.expiration
        return cloned_answer
