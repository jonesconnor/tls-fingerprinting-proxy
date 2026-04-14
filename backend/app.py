"""
app.py — Dual-representation backend.

Reads the X-Client-Type header injected by the proxy and serves either:
  - HTML: a fully-rendered article page for human browsers
  - JSON: a structured, agent-optimized representation of the same content

Routes
------
  GET /         content-negotiated response (HTML or JSON)
  GET /debug    all received headers + classification as JSON (always JSON)
  GET /health   health check
"""

import json
import os
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Article content — the demo payload.
# Using the project itself as the subject matter is intentional: when an agent
# hits this endpoint, the JSON it receives explains exactly what detected it.
# ---------------------------------------------------------------------------

ARTICLE = {
    "id": "tls-fingerprinting-and-the-agentic-web",
    "title": "What Your TLS Handshake Reveals About You",
    "subtitle": "Before you ask for a page, the server already knows what you are.",
    "author": "TLS Fingerprinting Proxy",
    "published_at": "2025-01-01T00:00:00Z",
    "canonical_url": "/",
    "topics": ["tls", "networking", "ai-agents", "fingerprinting", "security"],
    "reading_time_minutes": 4,
    "sections": [
        {
            "heading": "The Handshake Happens First",
            "body": (
                "Every HTTPS connection begins with a TLS handshake. Before your browser "
                "sends a GET request, before any cookies are transmitted, before JavaScript "
                "runs — the client and server negotiate how to communicate securely. The "
                "client sends a ClientHello message listing the cipher suites and TLS "
                "extensions it supports. That list is determined by the underlying TLS "
                "library, not by the application. Chrome uses Google's BoringSSL. Python "
                "uses OpenSSL. Go has its own crypto/tls. Each produces a detectably "
                "different ClientHello."
            ),
        },
        {
            "heading": "JA4: Hashing the Handshake",
            "body": (
                "JA4 (developed by John Althouse at FoxIO) takes the fields of a "
                "ClientHello — cipher suites, extension types, ALPN values, signature "
                "algorithms — and hashes them into a structured, queryable fingerprint "
                "string. A lookup database at ja4db.com maps known hashes to identified "
                "clients. The format is: {transport}{version}{sni}{ciphers}{extensions}"
                "{alpn}_{cipher_hash}_{extension_hash}."
            ),
        },
        {
            "heading": "GREASE: The Most Reliable Browser Signal",
            "body": (
                "Chrome deliberately inserts reserved 'garbage' values into its cipher "
                "suite and extension lists. This is GREASE (Generate Random Extensions And "
                "Sustain Extensibility, RFC 8701) — a mechanism to prevent server software "
                "from hardcoding assumptions about valid ClientHello values. Its presence "
                "strongly indicates a Chrome-family browser. Its absence in an otherwise "
                "browser-like fingerprint is a meaningful signal."
            ),
        },
        {
            "heading": "AI Agents Have a Fingerprint Too",
            "body": (
                "Every major AI agent SDK — OpenAI's Python client, Anthropic's SDK, "
                "LangChain, LlamaIndex — makes HTTP requests using Python's httpx or "
                "requests library, which uses OpenSSL under the hood. The OpenSSL "
                "fingerprint is distinctive: a large permissive cipher list (40+ suites), "
                "few extensions, no GREASE, no Encrypted Client Hello. This is not a flaw "
                "in the SDKs — it's simply what the Python TLS stack looks like."
            ),
        },
        {
            "heading": "Serving Agents Differently",
            "body": (
                "Once you can identify agents at the network layer, you can route them to "
                "a representation of your content that is optimized for machine consumption: "
                "structured JSON instead of HTML, explicit action schemas instead of forms, "
                "complete data instead of paginated views, absolute URLs, and rich metadata. "
                "The web has always served one representation to every client. That assumption "
                "is about to break."
            ),
        },
    ],
}

POSTS = [
    {
        "title": "What Your TLS Handshake Reveals About You",
        "url": "/writing/tls-fingerprinting",
        "date_display": "Jan 2025",
        "reading_time_minutes": 4,
    },
]

RELATED = [
    {
        "title": "JA4+ Specification",
        "url": "https://github.com/FoxIO-LLC/ja4",
        "description": "The full JA4 fingerprint family specification.",
    },
    {
        "title": "JA4 Database",
        "url": "https://ja4db.com",
        "description": "Known JA4 hashes mapped to identified clients.",
    },
    {
        "title": "See Your Browser's Fingerprint",
        "url": "https://tls.peet.ws",
        "description": "Live TLS fingerprint viewer for your current browser.",
    },
]


# ---------------------------------------------------------------------------
# Helper: build the structured JSON response for agents
# ---------------------------------------------------------------------------

def _agent_response(classification: dict, canonical_path: str | None = None) -> dict:
    """
    Build a structured JSON representation optimized for machine consumption.

    Design principles applied here:
    - No pagination: complete content in one response
    - Explicit action schemas: actions are machine-executable, not just links
    - Absolute URLs: agents don't inherit a base URL from a browser session
    - Capability declarations: what the agent is permitted to do with this data
    - Self-describing: the response explains what detected the agent and why
    """
    base_url = request.host_url.rstrip("/")
    resolved_path = canonical_path or ARTICLE["canonical_url"]

    return {
        "type": "article",
        "id": ARTICLE["id"],
        "title": ARTICLE["title"],
        "subtitle": ARTICLE["subtitle"],
        "canonical_url": f"{base_url}{resolved_path}",
        "metadata": {
            "author": ARTICLE["author"],
            "published_at": ARTICLE["published_at"],
            "topics": ARTICLE["topics"],
            "reading_time_minutes": ARTICLE["reading_time_minutes"],
            "word_count": sum(len(s["body"].split()) for s in ARTICLE["sections"]),
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        },
        "content": {
            "sections": ARTICLE["sections"],
        },
        "related": [
            {**item, "url": item["url"]}
            for item in RELATED
        ],
        # Explicit action schemas: every state transition described as a
        # machine-readable object the agent can reason about and execute.
        "actions": [
            {
                "id": "view_debug",
                "type": "fetch",
                "description": "Retrieve raw request headers and classification details",
                "url": f"{base_url}/debug",
                "method": "GET",
                "returns": "application/json",
            },
            {
                "id": "view_human",
                "type": "fetch",
                "description": "Retrieve the human-readable HTML version of this article",
                "url": f"{base_url}/",
                "method": "GET",
                "headers": {"Accept": "text/html"},
                "returns": "text/html",
                "note": "Override content negotiation by sending Accept: text/html",
            },
        ],
        # Agent identity metadata: tells the agent exactly what was detected
        # and why it received this representation instead of HTML.
        "agent_meta": {
            "detection_method": "tls_fingerprinting",
            "detection_layer": "network",  # before any HTTP data was exchanged
            "ja4_fingerprint": classification.get("ja4"),
            "client_type": classification.get("client_type"),
            "classification_detail": classification.get("detail"),
            "confidence": classification.get("confidence"),
            "signals": classification.get("signals", []),
            "note": (
                "You were identified as a non-browser client via TLS fingerprinting "
                "of your ClientHello message. This JSON response was generated because "
                "your client_type is not 'browser'. No HTTP request data was inspected "
                "to make this classification."
            ),
            "capabilities": {
                "can_store": True,
                "can_index": True,
                "can_reproduce": True,
                "attribution_required": False,
            },
        },
    }


# ---------------------------------------------------------------------------
# /compare — reference data and JA4 parsing
# ---------------------------------------------------------------------------

# Canonical reference profiles used in the comparison table.
# Values are representative of a typical recent version of each client.
# Captured values from the local catalogue are used where available.
REFERENCE_PROFILES = [
    {
        "name": "Chrome / Edge",
        "tls_lib": "BoringSSL",
        "client_type": "browser",
        "cipher_count": 15,
        "ext_count": 16,
        "alpn": "h2",
        "grease": True,
        "ech": True,
        "compress_cert": True,
    },
    {
        "name": "Firefox",
        "tls_lib": "NSS",
        "client_type": "browser",
        "cipher_count": 17,
        "ext_count": 15,
        "alpn": "h2",
        "grease": False,
        "ech": False,
        "compress_cert": True,
    },
    {
        "name": "Safari / WebKit",
        "tls_lib": "Apple TLS",
        "client_type": "browser",
        "cipher_count": 17,
        "ext_count": 12,
        "alpn": "h2",
        "grease": False,
        "ech": False,
        "compress_cert": False,
    },
    {
        "name": "Python / OpenSSL",
        "tls_lib": "OpenSSL",
        "client_type": "agent",
        "cipher_count": 40,
        "ext_count": 9,
        "alpn": "—",
        "grease": False,
        "ech": False,
        "compress_cert": False,
    },
    {
        "name": "Go net/http",
        "tls_lib": "crypto/tls",
        "client_type": "agent",
        "cipher_count": 13,
        "ext_count": 11,
        "alpn": "—",
        "grease": False,
        "ech": False,
        "compress_cert": False,
    },
    {
        "name": "curl",
        "tls_lib": "OpenSSL",
        "client_type": "tool",
        "cipher_count": 31,
        "ext_count": 12,
        "alpn": "h2",
        "grease": False,
        "ech": False,
        "compress_cert": False,
    },
]

# Plain-English descriptions for each classifier signal.
_SIGNAL_LABELS = {
    "grease": {
        "title": "GREASE values present",
        "body": (
            "Your client sends reserved 'garbage' values in its cipher suite and extension "
            "lists (RFC 8701). This is a deliberate Chrome/Edge/BoringSSL behaviour — "
            "designed to prevent server software from hardcoding assumptions about what a "
            "valid ClientHello looks like. Its presence is one of the strongest browser "
            "indicators in the handshake."
        ),
        "verdict": "Chrome or Edge",
    },
    "ech": {
        "title": "Encrypted Client Hello",
        "body": (
            "Your client advertises support for Encrypted Client Hello (ECH), which hides "
            "the target server name from passive observers during the handshake. This feature "
            "shipped in Chrome 117 and has not been widely adopted outside the Chrome family."
        ),
        "verdict": "Chrome 117+",
    },
    "compress_cert": {
        "title": "Certificate compression (RFC 8879)",
        "body": (
            "Your client advertises support for TLS certificate compression, which reduces "
            "handshake overhead by compressing the server's certificate chain. Both Chrome "
            "and Firefox support this. Its presence narrows classification to the browser "
            "family — programmatic clients don't typically request it."
        ),
        "verdict": "Chrome, Edge, or Firefox",
    },
    "permissive_ciphers": {
        "title": "Large cipher suite (40+ suites)",
        "body": (
            "Your client offered 40 or more cipher suites — the OpenSSL default behaviour. "
            "OpenSSL ships with a permissive list that accepts almost anything the server "
            "offers. This is the dominant signal for Python's ssl module (used by requests, "
            "httpx, and every major AI agent SDK), as well as curl and most OpenSSL-backed "
            "HTTP clients."
        ),
        "verdict": "Python, curl, or OpenSSL-backed client",
    },
    "minimal_ciphers": {
        "title": "Minimal cipher suite (≤6 suites)",
        "body": (
            "Your client offered very few cipher suites — the Go crypto/tls signature. "
            "Go's TLS implementation deliberately uses a small, vetted list rather than "
            "inheriting OS defaults. A cipher count this low is almost exclusively "
            "associated with Go net/http."
        ),
        "verdict": "Go net/http",
    },
    "curated_ciphers": {
        "title": "Curated cipher suite (12–22 suites)",
        "body": (
            "Your client offered a moderate, curated cipher list — typical of browser TLS "
            "stacks. Browsers balance broad compatibility with security hygiene; they don't "
            "use the OpenSSL kitchen-sink default, but they also don't restrict to Go's "
            "minimal set."
        ),
        "verdict": "Browser-family client",
    },
    "rich_extensions": {
        "title": "Rich TLS extension set (14+ extensions)",
        "body": (
            "Your client sent 14 or more TLS extensions — consistent with modern browser "
            "behaviour. Browsers negotiate a large, structured set of features including "
            "session resumption, certificate status, signed timestamps, and ALPN. High "
            "extension counts are a reliable browser signal."
        ),
        "verdict": "Browser",
    },
    "minimal_extensions": {
        "title": "Minimal extension set (≤5 extensions)",
        "body": (
            "Your client sent 5 or fewer TLS extensions — consistent with Go crypto/tls "
            "or older curl builds. Programmatic clients only request extensions they "
            "explicitly need, resulting in a sparse extension list."
        ),
        "verdict": "Go or minimal HTTP client",
    },
    "tls13": {
        "title": "TLS 1.3",
        "body": (
            "Your client negotiated TLS 1.3, the current standard. TLS 1.3 removes legacy "
            "cipher suites, cuts round-trips in the handshake, and provides forward secrecy "
            "by default. All modern browsers and current SDK versions prefer it."
        ),
        "verdict": "Modern client",
    },
    "tls12": {
        "title": "TLS 1.2",
        "body": (
            "Your client negotiated TLS 1.2. Modern browsers and recent SDK versions "
            "prefer TLS 1.3, so this may indicate an older client, a restrictive "
            "configuration, or a server that doesn't yet support 1.3."
        ),
        "verdict": "Older or restricted client",
    },
    "catalogue_match": {
        "title": "Exact catalogue match",
        "body": (
            "Your JA4 fingerprint matched an entry in the local fingerprint catalogue — "
            "a database of hashes captured directly from known SDKs and tools across "
            "multiple platforms. This is the highest-confidence identification path: "
            "the full fingerprint is known."
        ),
        "verdict": "Positively identified",
    },
    "catalogue_near_match": {
        "title": "Near-match in catalogue",
        "body": (
            "Your JA4 fingerprint shares cipher suite characteristics with a known "
            "catalogue entry (Parts A and B match) but differs in extension or "
            "sig-alg hash (Part C). This typically means the same SDK family on a "
            "slightly different OS or library version."
        ),
        "verdict": "Probable match",
    },
    "ja4db_match": {
        "title": "Match in ja4db",
        "body": (
            "Your JA4 fingerprint was found in the ja4db public database, which maps "
            "known hashes to identified clients including browsers, common tools, and "
            "widely-used libraries."
        ),
        "verdict": "Known fingerprint",
    },
}


def _parse_ja4_part_a(ja4: str) -> dict | None:
    """
    Parse a JA4 string into its decoded fields.

    JA4 Part A format: t{ver}{sni}{cc:02d}{ec:02d}{alpn}
    Example: t13d1516h2 → TCP, TLS 1.3, SNI present, 15 ciphers, 16 ext, ALPN h2

    Returns None if the string is absent, too short, or malformed.
    """
    if not ja4:
        return None
    parts = ja4.split("_")
    if len(parts) != 3:
        return None
    part_a, part_b, part_c = parts
    if len(part_a) < 10:
        return None
    try:
        tls_raw = part_a[1:3]
        alpn_raw = part_a[8:10]
        return {
            "raw": part_a,
            "transport": "TCP" if part_a[0] == "t" else "UDP",
            "tls_version": {"13": "1.3", "12": "1.2", "11": "1.1"}.get(tls_raw, tls_raw),
            "sni": "present" if part_a[3] == "d" else "absent",
            "cipher_count": int(part_a[4:6]),
            "ext_count": int(part_a[6:8]),
            "alpn": alpn_raw if alpn_raw != "00" else "—",
            "part_b": part_b,
            "part_c": part_c,
            "full": ja4,
        }
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _get_classification() -> tuple[dict, bool]:
    """Read proxy classification headers and resolve content negotiation."""
    client_type = request.headers.get("X-Client-Type", "unknown")
    classification = {
        "client_type": client_type,
        "ja4":         request.headers.get("X-Client-JA4", ""),
        "detail":      request.headers.get("X-Client-Detail", ""),
        "confidence":  request.headers.get("X-Client-Confidence", "low"),
        "signals":     [s for s in request.headers.get("X-Client-Signals", "").split(",") if s],
        "match_type":  request.headers.get("X-Client-Match-Type", "heuristic"),
    }
    accept     = request.headers.get("Accept", "")
    wants_html = client_type == "browser" or "text/html" in accept
    return classification, wants_html


@app.route("/")
def index():
    classification, wants_html = _get_classification()

    if wants_html:
        return render_template(
            "index.html",
            posts=POSTS,
            classification=classification,
        )
    else:
        return app.response_class(
            response=json.dumps(_agent_response(classification), indent=2),
            status=200,
            mimetype="application/json",
        )


@app.route("/writing/tls-fingerprinting")
def article_tls_fingerprinting():
    classification, wants_html = _get_classification()

    if wants_html:
        return render_template(
            "article.html",
            article=ARTICLE,
            related=RELATED,
            classification=classification,
        )
    else:
        return app.response_class(
            response=json.dumps(
                _agent_response(classification, canonical_path="/writing/tls-fingerprinting"),
                indent=2,
            ),
            status=200,
            mimetype="application/json",
        )


@app.route("/debug")
def debug():
    """Show all received headers and the proxy classification. Always JSON."""
    headers_dict = dict(request.headers)
    proxy_headers = {
        k: v for k, v in headers_dict.items()
        if k.lower().startswith("x-client-")
    }
    return jsonify({
        "all_headers": headers_dict,
        "classification_headers": proxy_headers,
        "remote_addr": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/compare")
def compare():
    """Visual fingerprint breakdown and comparison against reference clients."""
    classification, _ = _get_classification()
    signals = classification.get("signals", [])
    ja4 = classification.get("ja4", "")

    ja4_parsed = _parse_ja4_part_a(ja4)

    # Build the visitor's row for the comparison table.
    you = None
    if ja4_parsed:
        you = {
            "cipher_count": ja4_parsed["cipher_count"],
            "ext_count":    ja4_parsed["ext_count"],
            "alpn":         ja4_parsed["alpn"],
            "grease":       "grease" in signals,
            "ech":          "ech" in signals,
            "compress_cert": "compress_cert" in signals,
        }

    signal_explanations = [
        _SIGNAL_LABELS[s] for s in signals if s in _SIGNAL_LABELS
    ]

    return render_template(
        "compare.html",
        classification=classification,
        ja4_parsed=ja4_parsed,
        you=you,
        references=REFERENCE_PROFILES,
        signal_explanations=signal_explanations,
    )


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.getenv("BACKEND_PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False)
