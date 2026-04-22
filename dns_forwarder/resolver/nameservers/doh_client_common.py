from __future__ import annotations

import base64
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import dns.message

DNS_MESSAGE_MEDIA_TYPE = "application/dns-message"


@dataclass(frozen=True)
class DoHRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None


def build_doh_request(
    request: dns.message.QueryMessage,
    url: str,
    *,
    want_get: bool,
    http_host: str | None,
) -> DoHRequest:
    wire = request.to_wire()
    headers = {"Accept": DNS_MESSAGE_MEDIA_TYPE}
    if http_host:
        headers["Host"] = http_host
    if want_get:
        return DoHRequest("GET", _url_with_dns_param(url, wire), headers, None)

    headers["Content-Type"] = DNS_MESSAGE_MEDIA_TYPE
    return DoHRequest("POST", url, headers, wire)


def parse_doh_response(
    content: bytes,
    *,
    one_rr_per_rrset: bool,
    ignore_trailing: bool,
) -> dns.message.Message:
    return dns.message.from_wire(
        content,
        one_rr_per_rrset=one_rr_per_rrset,
        ignore_trailing=ignore_trailing,
    )


def replace_url_hostname(url: str, hostname: str | None) -> str:
    if not hostname:
        return url
    parts = urlsplit(url)
    port = f":{parts.port}" if parts.port else ""
    return urlunsplit(parts._replace(netloc=f"{_format_host(hostname)}{port}"))


def url_hostname(url: str) -> str | None:
    return urlsplit(url).hostname


def url_port(url: str) -> int:
    parts = urlsplit(url)
    if parts.port is not None:
        return parts.port
    return 443 if parts.scheme == "https" else 80


def is_ip_address(value: str | None) -> bool:
    if value is None:
        return False
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _url_with_dns_param(url: str, wire: bytes) -> str:
    parts = urlsplit(url)
    query_items = parse_qsl(parts.query, keep_blank_values=True)
    query_items.append(("dns", _base64url_no_padding(wire)))
    return urlunsplit(parts._replace(query=urlencode(query_items)))


def _base64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _format_host(hostname: str) -> str:
    if ":" in hostname and not hostname.startswith("["):
        return f"[{hostname}]"
    return hostname
