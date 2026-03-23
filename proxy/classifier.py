"""
classifier.py - Heuristic client classification from JA4 + ClientHello signals.

Classification is intentionally multi-signal and defensive: a single signal is
never sufficient. The heuristics here are starting points — real fingerprint
catalogue lookups are handled by lookup.py (Ja4Database), which takes precedence
over these heuristics.

Client types:
  browser   - A human-driven browser (Chrome, Firefox, Safari, Edge)
  headless  - A headless browser (Playwright, Puppeteer) - nearly identical to
              "browser" but distinguishable in specific cases
  agent     - An AI agent or automation SDK (Python requests/httpx, Go, Node.js)
  tool      - A command-line tool (curl, wget, HTTPie)
  unknown   - Cannot classify with reasonable confidence
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tls_parser import GREASE_VALUES, ClientHelloInfo


@dataclass
class Classification:
    client_type: str        # browser | headless | agent | tool | unknown
    confidence: str         # high | medium | low
    detail: str             # human-readable description
    signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "client_type": self.client_type,
            "confidence": self.confidence,
            "detail": self.detail,
            "signals": self.signals,
        }



def classify(ja4: str, ch: ClientHelloInfo) -> Classification:
    """
    Classify a client based on its JA4 string and ClientHello fields.
    Returns a Classification with type, confidence, detail, and contributing signals.
    """
    signals: list[str] = []

    real_ciphers = [c for c in ch.cipher_suites if c not in GREASE_VALUES]
    real_ext_types = [t for t in ch.extension_types if t not in GREASE_VALUES]
    num_ciphers = len(real_ciphers)
    num_extensions = len(real_ext_types)
    tls_ver = ch.tls_version

    # Collect observable signals
    if ch.has_grease:
        signals.append("grease")          # Chrome family: deliberately sends reserved values
    if ch.has_ech:
        signals.append("ech")             # Encrypted Client Hello - Chrome 117+
    if ch.has_compress_cert:
        signals.append("compress_cert")   # RFC 8879 - Chrome, Edge, Firefox

    if tls_ver == 0x0304:
        signals.append("tls13")
    elif tls_ver == 0x0303:
        signals.append("tls12")

    if num_ciphers <= 6:
        signals.append("minimal_ciphers")     # Go crypto/tls signature
    elif num_ciphers >= 40:
        signals.append("permissive_ciphers")  # Python/OpenSSL - accepts anything
    elif 12 <= num_ciphers <= 22:
        signals.append("curated_ciphers")     # Browser-style curated list

    if num_extensions <= 5:
        signals.append("minimal_extensions")  # Go, old curl
    elif num_extensions >= 14:
        signals.append("rich_extensions")     # Browser

    # ── Heuristic rules (ordered most-specific → least-specific) ──────────

    # Chrome/Edge: GREASE + ECH + compress_cert + TLS 1.3 + rich extension set.
    # Playwright with a real Chrome binary is indistinguishable from this.
    if ch.has_grease and ch.has_ech and ch.has_compress_cert and tls_ver == 0x0304:
        return Classification(
            client_type="browser",
            confidence="high",
            detail="Chrome/Edge - BoringSSL (GREASE + ECH + compress_cert)",
            signals=signals,
        )

    # Chrome/Edge without ECH (older release or ECH disabled)
    if ch.has_grease and ch.has_compress_cert and num_ciphers >= 12:
        return Classification(
            client_type="browser",
            confidence="high",
            detail="Chrome/Edge - BoringSSL (GREASE + compress_cert, no ECH)",
            signals=signals,
        )

    # Firefox: no GREASE, has compress_cert, rich extension set, TLS 1.3
    if not ch.has_grease and ch.has_compress_cert and num_extensions >= 12 and tls_ver == 0x0304:
        return Classification(
            client_type="browser",
            confidence="medium",
            detail="Firefox - NSS (compress_cert, no GREASE)",
            signals=signals,
        )

    # Safari/WebKit: curated ciphers, rich extensions, no GREASE, no compress_cert,
    # AND has ALPN (Safari always advertises h2). This is the critical separator from
    # macOS Python, which also has curated ciphers but sends no ALPN at all.
    if (not ch.has_grease and not ch.has_compress_cert
            and "curated_ciphers" in signals and num_extensions >= 10
            and ch.alpn_first is not None):
        return Classification(
            client_type="browser",
            confidence="medium",
            detail="Safari/WebKit - Apple TLS stack (no GREASE, ALPN present)",
            signals=signals,
        )

    # macOS Python (urllib / requests / httpx on macOS): curated cipher list from
    # Apple's LibreSSL or python.org's bundled OpenSSL, but NO ALPN — programmatic
    # clients don't set ALPN unless explicitly configured. Fingerprint looks like
    # Safari except for the missing ALPN field.
    if not ch.has_grease and "curated_ciphers" in signals and ch.alpn_first is None:
        return Classification(
            client_type="agent",
            confidence="medium",
            detail="Python on macOS - Apple/LibreSSL TLS (curated ciphers, no ALPN)",
            signals=signals,
        )

    # curl / wget: OpenSSL, large cipher list, very few extensions (<=8), no GREASE.
    # Check this BEFORE the Python agent rule — both use OpenSSL and look similar,
    # but curl sends fewer extensions than Python's ssl module.
    if not ch.has_grease and "permissive_ciphers" in signals and num_extensions <= 8:
        return Classification(
            client_type="tool",
            confidence="medium",
            detail="curl / wget - command-line tool (OpenSSL)",
            signals=signals,
        )

    # Python agent (requests / httpx / aiohttp / openai-python / anthropic-python):
    # Large permissive cipher list, more extensions than curl, no GREASE.
    # This is the fingerprint of virtually every Python-based AI agent SDK.
    if not ch.has_grease and "permissive_ciphers" in signals and num_extensions <= 12:
        return Classification(
            client_type="agent",
            confidence="high",
            detail="Python HTTP client - OpenSSL (requests/httpx/aiohttp/AI SDK)",
            signals=signals,
        )

    # Go agent (net/http): very small cipher list, no GREASE, modest extension count.
    # Real Go crypto/tls sends 3-5 ciphers and 5-8 extensions — test-go-sim
    # simulates this with a restricted cipher list.
    if not ch.has_grease and "minimal_ciphers" in signals and num_extensions <= 8:
        return Classification(
            client_type="agent",
            confidence="high",
            detail="Go net/http - crypto/tls (minimal cipher set)",
            signals=signals,
        )

    # Node.js agent (fetch / axios / got): BoringSSL-derived but no GREASE,
    # moderate cipher count, decent extension set
    if not ch.has_grease and 8 <= num_ciphers <= 20 and num_extensions >= 8:
        return Classification(
            client_type="agent",
            confidence="medium",
            detail="Node.js HTTP client - BoringSSL (no GREASE)",
            signals=signals,
        )

    return Classification(
        client_type="unknown",
        confidence="low",
        detail=(
            f"Unclassified ({num_ciphers} ciphers, {num_extensions} ext, grease={ch.has_grease})"
        ),
        signals=signals,
    )
