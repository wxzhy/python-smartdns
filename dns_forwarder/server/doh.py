from __future__ import annotations

import base64
import binascii
from typing import TYPE_CHECKING, Annotated

import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
from fastapi import APIRouter, FastAPI, HTTPException, Query, Request, Response, status

from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline import make_error_response

if TYPE_CHECKING:
    from dns_forwarder.core.runtime import RuntimeManager


DOH_MEDIA_TYPE = "application/dns-message"
DOH_DNS_QUERY_PATH = "/dns-query"
logger = get_logger("server.doh")


def register_doh_routes(
    app: FastAPI, runtime_manager: "RuntimeManager", listener_name: str = "doh"
) -> None:
    router = APIRouter()

    @router.get(DOH_DNS_QUERY_PATH, response_class=Response)
    async def handle_get(
        request: Request,
        dns: Annotated[str | None, Query()] = None,
    ) -> Response:
        if dns is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="missing dns query parameter"
            )
        wire = _decode_doh_query(dns)
        return await _handle_doh_wire(runtime_manager, listener_name, request, wire, is_get=True)

    @router.post(DOH_DNS_QUERY_PATH, response_class=Response)
    async def handle_post(request: Request) -> Response:
        content_type = _normalize_media_type(request.headers.get("content-type"))
        if content_type != DOH_MEDIA_TYPE:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="unsupported media type"
            )
        wire = await request.body()
        if not wire:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="empty dns request body"
            )
        return await _handle_doh_wire(runtime_manager, listener_name, request, wire, is_get=False)

    app.include_router(router)


async def _handle_doh_wire(
    runtime_manager: "RuntimeManager",
    listener_name: str,
    request: Request,
    wire: bytes,
    *,
    is_get: bool,
) -> Response:
    _ensure_accepts_dns_message(request.headers.get("accept"))

    try:
        message = dns.message.from_wire(wire)
    except Exception as exc:
        logger.warning("DoH 请求解析失败 listener=%s error=%s", listener_name, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid dns message"
        ) from exc

    clientaddr = _client_address(request)
    logger.debug(
        "DoH 收到请求 listener=%s client=%r method=%s qname=%s qtype=%s",
        listener_name,
        clientaddr,
        request.method,
        message.question[0].name.to_text().rstrip(".") if message.question else "",
        dns.rdatatype.to_text(message.question[0].rdtype) if message.question else "",
    )
    response = await runtime_manager.process_query(message, clientaddr, listener_name)
    if response is None:
        logger.info("DoH 请求被策略拒绝 listener=%s client=%r", listener_name, clientaddr)
        response = make_error_response(message, dns.rcode.REFUSED)

    headers: dict[str, str] = {}
    if is_get:
        headers["Cache-Control"] = _cache_control_header(response)
    return Response(content=response.to_wire(), media_type=DOH_MEDIA_TYPE, headers=headers)


def _decode_doh_query(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid dns query parameter"
        ) from exc


def _normalize_media_type(value: str | None) -> str | None:
    if value is None:
        return None
    return value.split(";", 1)[0].strip().lower()


def _ensure_accepts_dns_message(value: str | None) -> None:
    if value is None or not value.strip():
        return
    media_types = {
        part.split(";", 1)[0].strip().lower() for part in value.split(",") if part.strip()
    }
    if DOH_MEDIA_TYPE in media_types or "*/*" in media_types or "application/*" in media_types:
        return
    raise HTTPException(
        status_code=status.HTTP_406_NOT_ACCEPTABLE, detail="response type not acceptable"
    )


def _cache_control_header(response: dns.message.Message) -> str:
    answer_ttls = [rrset.ttl for rrset in response.answer]
    if answer_ttls:
        return f"max-age={min(answer_ttls)}"

    authority_ttls: list[int] = []
    for rrset in response.authority:
        if rrset.rdclass != dns.rdataclass.IN or rrset.rdtype != dns.rdatatype.SOA:
            continue
        for record in rrset:
            authority_ttls.append(min(rrset.ttl, record.minimum))
    if authority_ttls:
        return f"max-age={min(authority_ttls)}"
    return "no-store"


def _client_address(request: Request) -> tuple[str, int]:
    if request.client is None:
        return "0.0.0.0", 0
    return request.client.host, request.client.port


__all__ = ["DOH_DNS_QUERY_PATH", "DOH_MEDIA_TYPE", "register_doh_routes"]
