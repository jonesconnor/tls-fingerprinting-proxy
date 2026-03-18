"""
tls_parser.py — ClientHello extraction using scapy's TLS layer.

Scapy handles the binary record/handshake framing and cipher suite list.
We pull specific extension values (SNI, ALPN, supported versions, etc.)
from the parsed extension objects.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

# Suppress scapy's startup warnings before importing
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.tls.record import TLS  # noqa: E402

GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

EXT_SNI                 = 0x0000
EXT_ALPN                = 0x0010
EXT_SUPPORTED_VERSIONS  = 0x002b
EXT_SIGNATURE_ALGORITHMS = 0x000d
EXT_SUPPORTED_GROUPS    = 0x000a
EXT_COMPRESS_CERTIFICATE = 0x001b
EXT_ECH                 = 0xfe0d


@dataclass
class ClientHelloInfo:
    cipher_suites: list[int] = field(default_factory=list)
    extension_types: list[int] = field(default_factory=list)
    sni: Optional[str] = None
    alpn_protocols: list[str] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    has_grease: bool = False
    has_ech: bool = False
    has_compress_cert: bool = False
    legacy_version: int = 0
    parse_error: Optional[str] = None

    @property
    def tls_version(self) -> int:
        """Best TLS version: highest from supported_versions ext, or legacy_version."""
        real = [v for v in self.supported_versions if v not in GREASE_VALUES]
        return max(real) if real else self.legacy_version

    @property
    def alpn_first(self) -> Optional[str]:
        return self.alpn_protocols[0] if self.alpn_protocols else None


def parse_client_hello(data: bytes) -> ClientHelloInfo:
    info = ClientHelloInfo()
    try:
        ch = TLS(data).msg[0]  # TLSClientHello
        info.legacy_version = int(ch.version)

        for c in ch.ciphers or []:
            val = int(c)
            info.cipher_suites.append(val)
            if val in GREASE_VALUES:
                info.has_grease = True

        for ext in ch.ext or []:
            try:
                ext_type = int(ext.type)
            except Exception:
                continue

            info.extension_types.append(ext_type)

            if ext_type in GREASE_VALUES:
                info.has_grease = True
                continue
            if ext_type == EXT_ECH:
                info.has_ech = True
            elif ext_type == EXT_COMPRESS_CERTIFICATE:
                info.has_compress_cert = True

            _extract(ext_type, ext, info)

    except Exception as exc:
        info.parse_error = str(exc)

    return info


def _extract(ext_type: int, ext, info: ClientHelloInfo) -> None:
    """Pull structured values out of scapy's parsed extension objects.
    Every field access is wrapped in try/except — scapy's extension API
    varies slightly across versions, and unknown extensions are returned
    as raw bytes with no structured fields."""
    try:
        if ext_type == EXT_SNI:
            info.sni = ext.servernames[0].servername.decode("ascii")

        elif ext_type == EXT_SUPPORTED_VERSIONS:
            info.supported_versions = [int(v) for v in ext.versions]

        elif ext_type == EXT_ALPN:
            info.alpn_protocols = [
                bytes(p.protocol).decode("ascii") for p in ext.protocols
            ]

        elif ext_type == EXT_SIGNATURE_ALGORITHMS:
            info.signature_algorithms = [int(s) for s in ext.sig_algs]

        elif ext_type == EXT_SUPPORTED_GROUPS:
            info.supported_groups = [int(g) for g in ext.groups]

    except Exception:
        pass  # best-effort; raw/unknown extensions have no structured fields
