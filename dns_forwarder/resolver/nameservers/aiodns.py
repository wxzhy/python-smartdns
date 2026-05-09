from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import aiodns
import dns.asyncbackend
import dns.message
import dns.name
import dns.nameserver
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.svcbbase
import dns.rrset
import dns.wire
import pycares
from aiodns import error as aiodns_error
from dns.rdtypes.ANY.CAA import CAA as CAAData
from dns.rdtypes.ANY.CNAME import CNAME as CNAMEData
from dns.rdtypes.ANY.MX import MX as MXData
from dns.rdtypes.ANY.NS import NS as NSData
from dns.rdtypes.ANY.PTR import PTR as PTRData
from dns.rdtypes.ANY.SOA import SOA as SOAData
from dns.rdtypes.ANY.TLSA import TLSA as TLSAData
from dns.rdtypes.ANY.TXT import TXT as TXTData
from dns.rdtypes.ANY.URI import URI as URIData
from dns.rdtypes.IN.A import A as AData
from dns.rdtypes.IN.AAAA import AAAA as AAAAData
from dns.rdtypes.IN.HTTPS import HTTPS as HTTPSData
from dns.rdtypes.IN.NAPTR import NAPTR as NAPTRData
from dns.rdtypes.IN.SRV import SRV as SRVData

from dns_forwarder.config import AiodnsNameserverConfig


class AiodnsDNSResolver(aiodns.DNSResolver):
    def query_dns(
        self, host: str, qtype: str, qclass: str | None = None
    ) -> asyncio.Future[pycares.DNSResult]:
        if qtype != "HTTPS":
            return super().query_dns(host, qtype, qclass)

        qclass_int: int | None = None
        if qclass is not None:
            try:
                qclass_int = aiodns.query_class_map[qclass]
            except KeyError as exc:
                raise ValueError(f"invalid query class: {qclass}") from exc

        fut: asyncio.Future[pycares.DNSResult]
        fut, callback = self._get_future_callback()
        if qclass_int is not None:
            self._channel.query(
                host,
                pycares.QUERY_TYPE_HTTPS,
                query_class=qclass_int,
                callback=callback,
            )
        else:
            self._channel.query(host, pycares.QUERY_TYPE_HTTPS, callback=callback)
        return fut


@dataclass(frozen=True)
class _ResolverKey:
    loop_id: int
    servers: tuple[str, ...]
    port: int
    timeout: float
    tcp: bool


_RESOLVERS: dict[_ResolverKey, AiodnsDNSResolver] = {}


def _get_resolver(
    servers: tuple[str, ...],
    port: int,
    timeout: float,
    tcp: bool,
) -> AiodnsDNSResolver:
    loop = asyncio.get_running_loop()
    key = _ResolverKey(id(loop), servers, port, timeout, tcp)
    resolver = _RESOLVERS.get(key)
    if resolver is None:
        flags = pycares.ARES_FLAG_USEVC if tcp else None
        resolver = AiodnsDNSResolver(
            nameservers=list(servers),
            loop=loop,
            flags=flags,
            timeout=timeout,
            tcp_port=port,
            udp_port=port,
            rotate=True,
        )
        _RESOLVERS[key] = resolver
    return resolver


async def close_shared_sessions() -> None:
    resolvers = list(_RESOLVERS.values())
    _RESOLVERS.clear()
    for resolver in resolvers:
        await resolver.close()


class AiodnsNameserver(dns.nameserver.Nameserver):
    def __init__(
        self,
        servers: list[str],
        *,
        port: int = 53,
        tcp: bool = False,
        timeout: float = 1.0,
    ) -> None:
        self.servers = tuple(servers)
        self.port = port
        self.tcp = tcp
        self.timeout = timeout

    def __str__(self) -> str:
        return f"aiodns://{','.join(self.servers)}:{self.port}"

    def kind(self) -> str:
        return "aiodns"

    def is_always_max_size(self) -> bool:
        return self.tcp

    def answer_nameserver(self) -> str:
        return self.servers[0]

    def answer_port(self) -> int:
        return self.port

    def query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        raise NotImplementedError("aiodns nameserver only supports async queries")

    async def async_query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        backend: dns.asyncbackend.Backend,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        _ = timeout, source, source_port, backend, ignore_trailing
        question = request.question[0]
        host = question.name.to_text().rstrip(".") or "."
        qtype = dns.rdatatype.to_text(question.rdtype)
        qclass = dns.rdataclass.to_text(question.rdclass)
        resolver = _get_resolver(self.servers, self.port, self.timeout, self.tcp or max_size)
        try:
            result = await resolver.query_dns(host, qtype, qclass)
        except aiodns_error.DNSError as exc:
            response = _error_response(request, exc)
            if response is None:
                raise
            return response
        return _build_response(request, result, one_rr_per_rrset)


def _error_response(
    request: dns.message.QueryMessage,
    exc: aiodns_error.DNSError,
) -> dns.message.Message | None:
    if not exc.args:
        return None
    rcode = _ERROR_RCODES.get(exc.args[0])
    if rcode is None:
        return None
    response = dns.message.make_response(request)
    response.set_rcode(rcode)
    return response


_ERROR_RCODES = {
    aiodns_error.ARES_ENOTFOUND: dns.rcode.NXDOMAIN,
    aiodns_error.ARES_ENODATA: dns.rcode.NOERROR,
    aiodns_error.ARES_ESERVFAIL: dns.rcode.SERVFAIL,
    aiodns_error.ARES_EREFUSED: dns.rcode.REFUSED,
    aiodns_error.ARES_ENOTIMP: dns.rcode.NOTIMP,
    aiodns_error.ARES_EFORMERR: dns.rcode.FORMERR,
}


def _build_response(
    request: dns.message.QueryMessage,
    result: pycares.DNSResult,
    one_rr_per_rrset: bool,
) -> dns.message.Message:
    response = dns.message.make_response(request)
    _append_records(response.answer, result.answer, one_rr_per_rrset)
    _append_records(response.authority, result.authority, one_rr_per_rrset)
    _append_records(response.additional, result.additional, one_rr_per_rrset)
    return response


def _append_records(
    section: list[dns.rrset.RRset],
    records: list[pycares.DNSRecord],
    one_rr_per_rrset: bool,
) -> None:
    rrsets: dict[tuple[dns.name.Name, dns.rdataclass.RdataClass, dns.rdatatype.RdataType], dns.rrset.RRset] = {}
    for record in records:
        rdclass = dns.rdataclass.RdataClass.make(record.record_class)
        rdtype = dns.rdatatype.RdataType.make(record.type)
        name = dns.name.from_text(record.name)
        rdata = _record_data_to_rdata(record.data, rdclass, rdtype)
        if one_rr_per_rrset:
            rrset = dns.rrset.RRset(name, rdclass, rdtype)
            rrset.add(rdata, record.ttl)
            section.append(rrset)
            continue

        key = (name, rdclass, rdtype)
        rrset = rrsets.get(key)
        if rrset is None:
            rrset = dns.rrset.RRset(name, rdclass, rdtype)
            rrsets[key] = rrset
            section.append(rrset)
        rrset.add(rdata, record.ttl)


def _record_data_to_rdata(
    data: Any,
    rdclass: dns.rdataclass.RdataClass,
    rdtype: dns.rdatatype.RdataType,
) -> dns.rdata.Rdata:
    if isinstance(data, pycares.ARecordData):
        return AData(rdclass, rdtype, data.addr)
    if isinstance(data, pycares.AAAARecordData):
        return AAAAData(rdclass, rdtype, data.addr)
    if isinstance(data, pycares.MXRecordData):
        return MXData(rdclass, rdtype, data.priority, data.exchange)
    if isinstance(data, pycares.TXTRecordData):
        return TXTData(rdclass, rdtype, [data.data])
    if isinstance(data, pycares.CAARecordData):
        return CAAData(rdclass, rdtype, data.critical, data.tag, data.value)
    if isinstance(data, pycares.CNAMERecordData):
        return CNAMEData(rdclass, rdtype, data.cname)
    if isinstance(data, pycares.NAPTRRecordData):
        return NAPTRData(
            rdclass,
            rdtype,
            data.order,
            data.preference,
            data.flags,
            data.service,
            data.regexp,
            data.replacement,
        )
    if isinstance(data, pycares.NSRecordData):
        return NSData(rdclass, rdtype, data.nsdname)
    if isinstance(data, pycares.PTRRecordData):
        return PTRData(rdclass, rdtype, data.dname)
    if isinstance(data, pycares.SOARecordData):
        return SOAData(
            rdclass,
            rdtype,
            data.mname,
            data.rname,
            data.serial,
            data.refresh,
            data.retry,
            data.expire,
            data.minimum,
        )
    if isinstance(data, pycares.SRVRecordData):
        return SRVData(rdclass, rdtype, data.priority, data.weight, data.port, data.target)
    if isinstance(data, pycares.TLSARecordData):
        return TLSAData(
            rdclass,
            rdtype,
            data.cert_usage,
            data.selector,
            data.matching_type,
            data.cert_association_data,
        )
    if isinstance(data, pycares.HTTPSRecordData):
        params: dict[dns.rdtypes.svcbbase.ParamKey, dns.rdtypes.svcbbase.Param | None] = {}
        for raw_key, raw_value in data.params:
            key = dns.rdtypes.svcbbase.ParamKey.make(raw_key)
            param_cls = dns.rdtypes.svcbbase._class_for_key.get(
                key,
                dns.rdtypes.svcbbase.GenericParam,
            )
            params[key] = param_cls.from_wire_parser(dns.wire.Parser(raw_value))
        return HTTPSData(rdclass, rdtype, data.priority, data.target or ".", params)
    if isinstance(data, pycares.URIRecordData):
        return URIData(rdclass, rdtype, data.priority, data.weight, data.target)
    raise ValueError(f"unsupported pycares DNS record data: {type(data).__name__}")


def build_nameserver(config: AiodnsNameserverConfig) -> AiodnsNameserver:
    return AiodnsNameserver(
        config.servers,
        port=config.port,
        tcp=config.tcp,
        timeout=config.timeout,
    )


__all__ = [
    "AiodnsDNSResolver",
    "AiodnsNameserver",
    "build_nameserver",
    "close_shared_sessions",
]
