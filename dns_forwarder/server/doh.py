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
    app: FastAPI, runtime_manager: RuntimeManager, listener_name: str = "doh"
) -> None:
    """向 FastAPI 注册 DoH GET/POST 查询路由（RFC 8484）。"""
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
    runtime_manager: RuntimeManager,
    listener_name: str,
    request: Request,
    wire: bytes,
    *,
    is_get: bool,
) -> Response:
    """解析 wire 报文为 DNS 消息并交由运行时处理，返回 DoH 响应。"""
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
    """将 URL 安全 base64 的 dns 查询参数解码为 wire 字节，失败返回 400。"""
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid dns query parameter"
        ) from exc


def _normalize_media_type(value: str | None) -> str | None:
    """去除 ``;`` 参数后归一化媒体类型为小写，如 ``application/dns-message``。"""
    if value is None:
        return None
    return value.split(";", 1)[0].strip().lower()


def _ensure_accepts_dns_message(value: str | None) -> None:
    """校验 Accept 头是否接受 DoH 媒体类型，否则返回 406。"""
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
    """根据响应 TTL 生成 ``Cache-Control: max-age=N``，无可用 TTL 时返回 no-store。"""
    answer_ttls = [rrset.ttl for rrset in response.answer]
    if answer_ttls:
        return f"max-age={min(answer_ttls)}"

    # 从 SOA 权威记录中取最小 TTL，用于 HTTP 缓存建议。
    authority_ttls = [
        min(rrset.ttl, record.minimum)
        for rrset in response.authority
        if rrset.rdclass == dns.rdataclass.IN and rrset.rdtype == dns.rdatatype.SOA
        for record in rrset
    ]
    if authority_ttls:
        return f"max-age={min(authority_ttls)}"
    return "no-store"


def _client_address(request: Request) -> tuple[str, int]:
    """从请求中提取客户端 (host, port)，缺失时返回占位地址。"""
    if request.client is None:
        return "0.0.0.0", 0
    return request.client.host, request.client.port


__all__ = ["DOH_DNS_QUERY_PATH", "DOH_MEDIA_TYPE", "register_doh_routes"]
