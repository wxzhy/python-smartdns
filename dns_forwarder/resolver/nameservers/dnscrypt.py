from __future__ import annotations

import anyio
import ipaddress
import socket
import struct
from time import time
from typing import Final

import dns.asyncbackend
import dns.message
import dns.nameserver
import dns.query
import dns.rdatatype
import dns.resolver
from dns.exception import FormError, Timeout
from dns.flags import TC
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import VerifyKey
from nacl.utils import random

from dns_forwarder.config import DNSCryptNameserverConfig

DNSCRYPT_MINIMUM_SIZE: Final[int] = 256
DNSCRYPT_MODULO_SIZE: Final[int] = 64
DNSCRYPT_NONCE_SIZE: Final[int] = 12
DNSCRYPT_RESOLVER_MAGIC: Final[bytes] = b"r6fnvWj8"
DNSCRYPT_CERT_MAGIC: Final[bytes] = b"DNSC"


def _normalize_hex(value: str) -> bytes:
    return value.replace(":", "").strip().lower().encode("ascii")


def _parse_port_text(port_text: str) -> int:
    port = int(port_text)
    if not (1 <= port <= 65535):
        raise ValueError("端口号超出范围")
    return port


def _normalize_server_address(address: str, port: int) -> tuple[str, int]:
    value = address.strip()
    if not value:
        raise ValueError("dnscrypt address 不能为空")

    if value.startswith("["):
        closing = value.find("]")
        if closing > 0:
            host = value[1:closing]
            suffix = value[closing + 1 :]
            if suffix.startswith(":") and len(suffix) > 1:
                return host, _parse_port_text(suffix[1:])
            return host, port

    try:
        ipaddress.ip_address(value)
        return value, port
    except ValueError:
        pass

    host, sep, port_text = value.rpartition(":")
    if sep and host:
        try:
            return host, _parse_port_text(port_text)
        except ValueError:
            return value, port
    return value, port


def _pad_query(message: bytes) -> bytes:
    target_size = max(len(message) + 1, DNSCRYPT_MINIMUM_SIZE)
    remainder = target_size % DNSCRYPT_MODULO_SIZE
    if remainder:
        target_size += DNSCRYPT_MODULO_SIZE - remainder
    padding_size = target_size - len(message)
    if padding_size <= 0:
        return message
    return message + b"\x80" + (b"\x00" * (padding_size - 1))


def _is_multicast(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_multicast
    except ValueError:
        return False


class DNSCryptResolver:
    def __init__(
        self,
        address: str,
        provider_name: str,
        provider_pk: str,
        private_key: str | None = None,
        port: int = 53,
        cert_timeout: float = 5.0,
    ) -> None:
        self.address, self.port = _normalize_server_address(address, port)
        self._tcp_only = False
        self._private = self._load_private_key(private_key)

        verify_key = self._load_verify_key(provider_name, provider_pk)
        self._client_magic, public_key = self._fetch_server_key(
            provider_name,
            verify_key,
            cert_timeout,
        )
        self._secretbox = Box(self._private, public_key)

    @staticmethod
    def _load_private_key(private_key: str | None) -> PrivateKey:
        if private_key is None:
            return PrivateKey.generate()
        return PrivateKey(_normalize_hex(private_key), HexEncoder)

    @staticmethod
    def _load_verify_key(provider_name: str, provider_pk: str) -> VerifyKey:
        try:
            return VerifyKey(_normalize_hex(provider_pk), HexEncoder)
        except Exception:
            try:
                answer = dns.resolver.resolve(provider_pk, rdtype=dns.rdatatype.TXT)
                fingerprint = b"".join(answer.response.answer[0][0].strings).decode("ascii")
                return VerifyKey(_normalize_hex(fingerprint), HexEncoder)
            except Exception as exc:
                raise TypeError(f"No valid public key for {provider_name}") from exc

    def _fetch_server_key(
        self,
        provider_name: str,
        verify_key: VerifyKey,
        cert_timeout: float,
    ) -> tuple[bytes, PublicKey]:
        question = dns.message.make_query(provider_name, rdtype=dns.rdatatype.TXT)
        try:
            answer = dns.query.udp(
                question,
                self.address,
                port=self.port,
                timeout=cert_timeout,
            )
            if answer.flags & TC:
                answer = dns.query.tcp(
                    question,
                    self.address,
                    port=self.port,
                    timeout=cert_timeout,
                )
        except Timeout:
            self._tcp_only = True
            answer = dns.query.tcp(
                question,
                self.address,
                port=self.port,
                timeout=cert_timeout,
            )

        now = time()
        selected: tuple[int, bytes, PublicKey] | None = None

        for rrset in answer.answer:
            for rdata in rrset:
                candidate = b"".join(rdata.strings)
                if len(candidate) <= 8:
                    continue
                magic, es_version, _minor_version, signed = struct.unpack(
                    f"!4sHH{len(candidate) - 8}s",
                    candidate,
                )
                if magic != DNSCRYPT_CERT_MAGIC or es_version != 1:
                    continue

                try:
                    data = verify_key.verify(signed)
                except BadSignatureError:
                    continue

                if len(data) <= 52:
                    continue

                pk, client_magic, serial, start, expire, _ = struct.unpack(
                    f"!32s8sIII{len(data) - 52}s",
                    data,
                )
                if start > now or expire < now:
                    continue

                if selected is None or serial > selected[0]:
                    selected = (serial, client_magic, PublicKey(pk))

        if selected is None:
            raise TypeError(
                f"No valid certificate found for {self.address}:{self.port} ({provider_name})"
            )

        return selected[1], selected[2]

    def _encrypt_query(self, query: dns.message.QueryMessage) -> bytes:
        message = _pad_query(query.to_wire())
        client_nonce = random(DNSCRYPT_NONCE_SIZE)
        encrypted = self._secretbox.encrypt(
            message,
            client_nonce + (b"\x00" * DNSCRYPT_NONCE_SIZE),
        )
        encrypted = encrypted[0:DNSCRYPT_NONCE_SIZE] + encrypted[DNSCRYPT_NONCE_SIZE * 2 :]
        return self._client_magic + self._private.public_key.encode() + encrypted

    def _decrypt_response(
        self,
        wire: bytes,
        one_rr_per_rrset: bool,
        ignore_trailing: bool,
    ) -> dns.message.Message:
        if len(wire) < 32:
            raise FormError("DNSCrypt response too short")

        magic, nonce, data = struct.unpack(f"!8s24s{len(wire) - 32}s", wire)
        if magic != DNSCRYPT_RESOLVER_MAGIC:
            raise FormError("This does not appear to be DNSCrypt")

        payload = self._secretbox.decrypt(data, nonce)
        return dns.message.from_wire(
            payload,
            ignore_trailing=ignore_trailing,
            one_rr_per_rrset=one_rr_per_rrset,
        )

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
        if max_size or self._tcp_only:
            return self.tcp(
                request,
                timeout=timeout,
                source=source,
                source_port=source_port,
                one_rr_per_rrset=one_rr_per_rrset,
                ignore_trailing=ignore_trailing,
            )

        response = self.udp(
            request,
            timeout=timeout,
            source=source,
            source_port=source_port,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
        )
        if response.flags & TC:
            return self.tcp(
                request,
                timeout=timeout,
                source=source,
                source_port=source_port,
                one_rr_per_rrset=one_rr_per_rrset,
                ignore_trailing=ignore_trailing,
            )
        return response

    def tcp(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        wire = self._encrypt_query(request)
        af, destination, source_address = dns.query._destination_and_source(
            self.address,
            self.port,
            source,
            source_port,
        )

        sock = dns.query.socket_factory(af, socket.SOCK_STREAM)
        begin_time: float | None = None
        try:
            _, expiration = dns.query._compute_times(timeout)
            sock.setblocking(False)
            if source_address is not None:
                sock.bind(source_address)
            dns.query._connect(sock, destination)
            begin_time = time()
            dns.query._net_write(sock, struct.pack("!H", len(wire)) + wire, expiration)
            length_wire = dns.query._net_read(sock, 2, expiration)
            (payload_length,) = struct.unpack("!H", length_wire)
            response_wire = dns.query._net_read(sock, payload_length, expiration)
        finally:
            response_time = 0 if begin_time is None else time() - begin_time
            sock.close()

        response = self._decrypt_response(response_wire, one_rr_per_rrset, ignore_trailing)
        response.time = response_time
        if not request.is_response(response):
            raise dns.query.BadResponse
        return response

    def udp(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        ignore_unexpected: bool = True,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        wire = self._encrypt_query(request)
        af, destination, source_address = dns.query._destination_and_source(
            self.address,
            self.port,
            source,
            source_port,
        )

        sock = dns.query.socket_factory(af, socket.SOCK_DGRAM)
        begin_time: float | None = None
        try:
            _, expiration = dns.query._compute_times(timeout)
            sock.setblocking(False)
            if source_address is not None:
                sock.bind(source_address)
            dns.query._wait_for_writable(sock, expiration)
            begin_time = time()
            sock.sendto(wire, destination)

            while True:
                dns.query._wait_for_readable(sock, expiration)
                response_wire, from_address = sock.recvfrom(65535)
                if dns.query._addresses_equal(af, from_address, destination) or (
                    _is_multicast(self.address) and from_address[1:] == destination[1:]
                ):
                    break
                if not ignore_unexpected:
                    raise dns.query.UnexpectedSource(
                        f"got a response from {from_address} instead of {destination}"
                    )
        finally:
            response_time = 0 if begin_time is None else time() - begin_time
            sock.close()

        response = self._decrypt_response(response_wire, one_rr_per_rrset, ignore_trailing)
        response.time = response_time
        if not request.is_response(response):
            raise dns.query.BadResponse
        return response


class DNSCryptNameserver(dns.nameserver.Nameserver):
    def __init__(
        self,
        address: str,
        provider_name: str,
        provider_pk: str,
        private_key: str | None = None,
        port: int = 53,
        cert_timeout: float = 5.0,
        resolver: DNSCryptResolver | None = None,
    ) -> None:
        super().__init__()
        self.address, self.port = _normalize_server_address(address, port)
        self.provider_name = provider_name
        self.provider_pk = provider_pk
        self._resolver = resolver or DNSCryptResolver(
            self.address,
            provider_name=provider_name,
            provider_pk=provider_pk,
            private_key=private_key,
            port=self.port,
            cert_timeout=cert_timeout,
        )

    def __str__(self) -> str:
        return f"DNSCrypt:{self.address}@{self.port}/{self.provider_name}"

    def kind(self) -> str:
        return "DNSCrypt"

    def is_always_max_size(self) -> bool:
        return False

    def answer_nameserver(self) -> str:
        return self.address

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
        return self._resolver.query(
            request,
            timeout=timeout,
            source=source,
            source_port=source_port,
            max_size=max_size,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
        )

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
        _ = backend
        return await anyio.to_thread.run_sync(
            self._resolver.query,
            request,
            timeout,
            source,
            source_port,
            max_size,
            one_rr_per_rrset,
            ignore_trailing,
        )


def build_nameserver(config: DNSCryptNameserverConfig) -> DNSCryptNameserver:
    return DNSCryptNameserver(
        config.address,
        provider_name=config.provider_name,
        provider_pk=config.provider_pk,
        private_key=config.private_key,
        port=config.port,
        cert_timeout=config.cert_timeout,
    )


__all__ = ["DNSCryptNameserver", "DNSCryptResolver", "build_nameserver"]
