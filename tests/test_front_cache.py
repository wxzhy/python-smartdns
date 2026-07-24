from __future__ import annotations

import dns.message
import dns.rrset

from dns_forwarder.core.front_cache import FrontCache


def make_response(request: dns.message.Message, address: str, ttl: int = 60) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            request.question[0].name.to_text(),
            ttl,
            "IN",
            "A",
            address,
        )
    )
    return response


def test_front_cache_returns_cloned_response_with_reduced_ttl(monkeypatch) -> None:
    cache = FrontCache(max_size=10)
    request = dns.message.make_query("example.test", "A")
    response = make_response(request, "203.0.113.10", ttl=60)

    monkeypatch.setattr("dns_forwarder.core.front_cache.time.time", lambda: 1000.0)
    assert cache.put_response(request, response) is True

    second_request = dns.message.make_query("example.test", "A")
    monkeypatch.setattr("dns_forwarder.core.front_cache.time.time", lambda: 1012.4)
    cached = cache.get_response(second_request)

    assert cached is not None
    assert cached.id == second_request.id
    assert cached.answer[0].ttl == 47
    assert cached.answer[0][0].address == "203.0.113.10"


async def test_front_cache_coalesces_pending_requests() -> None:
    cache = FrontCache(max_size=10)
    request = dns.message.make_query("example.test", "A")
    response = make_response(request, "203.0.113.20")

    pending_key, owner_pending = await cache.acquire_pending(request)
    assert pending_key is not None
    assert owner_pending is None

    follower_key, follower_pending = await cache.acquire_pending(
        dns.message.make_query("example.test", "A")
    )
    assert follower_key == pending_key
    assert follower_pending is not None

    cache_written = cache.put_response(request, response)
    await cache.complete_pending(pending_key, response, cache_written=cache_written)

    shared = await cache.wait_for_pending_response(follower_pending, request)
    assert shared is None
    assert cache.get_response(request) is not None
