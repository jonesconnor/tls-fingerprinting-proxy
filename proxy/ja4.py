"""
ja4.py — JA4 TLS fingerprint computation.

Implements the JA4 specification published by FoxIO:
https://github.com/FoxIO-LLC/ja4

JA4 format:  {a}_{b}_{c}

  a  =  {transport}{tls_version}{sni_type}{num_ciphers}{num_extensions}{alpn}
            t/q/d       13/12/11     d/i       00-99         00-99        h2
         (10 chars total)

  b  =  first 12 hex chars of SHA-256(
            comma-separated cipher suite hex values, sorted, GREASE excluded
        )

  c  =  first 12 hex chars of SHA-256(
            comma-separated extension type hex values, sorted,
            GREASE + SNI(0000) + ALPN(0010) excluded
            + "_" +
            comma-separated signature algorithm hex values, original order
        )

Example output: t13d1516h2_8daaf6152771_b0da82dd1658
"""

import hashlib

from tls_parser import GREASE_VALUES, ClientHelloInfo

# Extensions excluded from the hash in part C (their values are captured
# separately in the 'a' component or in the sig_alg portion)
_EXT_EXCLUDE_FROM_C = {0x0000, 0x0010}  # SNI, ALPN

_TLS_VERSION_MAP = {
    0x0304: "13",  # TLS 1.3
    0x0303: "12",  # TLS 1.2
    0x0302: "11",  # TLS 1.1
    0x0301: "10",  # TLS 1.0
    0x0300: "s3",  # SSL 3.0
}


def _version_str(version: int) -> str:
    return _TLS_VERSION_MAP.get(version, "00")


def _alpn_chars(protocol: str | None) -> str:
    """
    First and last character of the first ALPN protocol value.
    "h2"        → "h2"
    "http/1.1"  → "h1"
    None        → "00"
    """
    if not protocol:
        return "00"
    if len(protocol) == 1:
        return protocol + protocol
    return protocol[0] + protocol[-1]


def _sha256_prefix(s: str, n: int = 12) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:n]


def compute_ja4(ch: ClientHelloInfo) -> str:
    """
    Compute the full JA4 fingerprint string from a ParsedClientHello.
    Returns a string like: t13d1516h2_8daaf6152771_b0da82dd1658
    """
    # --- Part A ---
    transport = "t"  # we only handle TCP/TLS; QUIC would be "q"

    ver = _version_str(ch.tls_version)

    sni_type = "d" if ch.sni else "i"

    real_ciphers = [c for c in ch.cipher_suites if c not in GREASE_VALUES]
    num_ciphers = f"{min(len(real_ciphers), 99):02d}"

    real_ext_types = [t for t in ch.extension_types if t not in GREASE_VALUES]
    num_extensions = f"{min(len(real_ext_types), 99):02d}"

    alpn = _alpn_chars(ch.alpn_first)

    part_a = f"{transport}{ver}{sni_type}{num_ciphers}{num_extensions}{alpn}"

    # --- Part B: cipher suite hash ---
    sorted_ciphers = sorted(real_ciphers)
    cipher_str = ",".join(f"{c:04x}" for c in sorted_ciphers)
    part_b = _sha256_prefix(cipher_str)

    # --- Part C: extension + signature algorithm hash ---
    ext_types_for_hash = sorted(
        t for t in real_ext_types if t not in _EXT_EXCLUDE_FROM_C
    )
    ext_str = ",".join(f"{t:04x}" for t in ext_types_for_hash)
    sig_str = ",".join(f"{s:04x}" for s in ch.signature_algorithms)

    part_c = _sha256_prefix(f"{ext_str}_{sig_str}")

    return f"{part_a}_{part_b}_{part_c}"


def compute_ja4_raw(ch: ClientHelloInfo) -> dict:
    """
    Return the intermediate components used to build the JA4 hash.
    Useful for the dashboard, logging, and debugging.
    """
    real_ciphers = [c for c in ch.cipher_suites if c not in GREASE_VALUES]
    real_ext_types = [t for t in ch.extension_types if t not in GREASE_VALUES]
    ext_types_for_hash = sorted(
        t for t in real_ext_types if t not in _EXT_EXCLUDE_FROM_C
    )

    return {
        "tls_version": _version_str(ch.tls_version),
        "tls_version_raw": f"{ch.tls_version:#06x}",
        "sni": ch.sni,
        "cipher_suites": [f"{c:04x}" for c in real_ciphers],
        "cipher_suites_sorted": [f"{c:04x}" for c in sorted(real_ciphers)],
        "num_ciphers": len(real_ciphers),
        "extension_types_ordered": [f"{t:04x}" for t in real_ext_types],
        "extension_types_for_hash": [f"{t:04x}" for t in ext_types_for_hash],
        "num_extensions": len(real_ext_types),
        "alpn_protocols": ch.alpn_protocols,
        "alpn_chars": _alpn_chars(ch.alpn_first),
        "signature_algorithms": [f"{s:04x}" for s in ch.signature_algorithms],
        "supported_groups": [f"{g:04x}" for g in ch.supported_groups],
        "has_grease": ch.has_grease,
        "has_ech": ch.has_ech,
        "has_compress_certificate": ch.has_compress_cert,
        "parse_error": ch.parse_error,
    }
