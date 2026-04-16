from __future__ import annotations

from unittest.mock import Mock

import dns.message

from dns_forwarder.resolver.nameservers.dnscrypt import DNSCryptNameserver


def test_dnscrypt_nameserver_query_delegates_to_resolver() -> None:
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    resolver = Mock()
    resolver.query.return_value = response

    nameserver = DNSCryptNameserver(
        "208.67.220.220",
        provider_name="2.dnscrypt-cert.opendns.com",
        provider_pk="B7351140206F225D3E2BD822D7FD691EA1C33CC8D6668D0CBE04BFABCA43FB79",
        port=443,
        resolver=resolver,
    )

    result = nameserver.query(
        request,
        timeout=1.0,
        source=None,
        source_port=0,
        max_size=False,
    )

    assert result is response
    resolver.query.assert_called_once_with(
        request,
        timeout=1.0,
        source=None,
        source_port=0,
        max_size=False,
        one_rr_per_rrset=False,
        ignore_trailing=False,
    )


async def test_dnscrypt_nameserver_async_query_delegates_to_resolver() -> None:
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    resolver = Mock()
    resolver.query.return_value = response

    nameserver = DNSCryptNameserver(
        "208.67.220.220",
        provider_name="2.dnscrypt-cert.opendns.com",
        provider_pk="B7351140206F225D3E2BD822D7FD691EA1C33CC8D6668D0CBE04BFABCA43FB79",
        port=443,
        resolver=resolver,
    )

    result = await nameserver.async_query(
        request,
        timeout=1.0,
        source=None,
        source_port=0,
        max_size=True,
        backend=object(),
    )

    assert result is response
    resolver.query.assert_called_once_with(
        request,
        1.0,
        None,
        0,
        True,
        False,
        False,
    )
