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
import sqlite3
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

TRAFFIC_DB_PATH = os.getenv("TRAFFIC_DB_PATH", "")

# ---------------------------------------------------------------------------
# Article content — the demo payload.
# Using the project itself as the subject matter is intentional: when an agent
# hits this endpoint, the JSON it receives explains exactly what detected it.
# ---------------------------------------------------------------------------

ARTICLE = {
    "id": "tls-fingerprinting-and-the-agentic-web",
    "title": (
        "Cloudflare published an Agent Readiness Score. "
        "I've been trying to answer a different question."
    ),
    "subtitle": (
        "Their tool asks if your site is configured to serve agents. "
        "Mine asks if you can identify agent traffic before it says a word."
    ),
    "author": "Connor Jones",
    "published_at": "2026-04-22T00:00:00Z",
    "canonical_url": "/writing/tls-fingerprinting",
    "topics": ["tls", "networking", "ai-agents", "fingerprinting", "security"],
    "reading_time_minutes": 8,
    "sections": [
        {
            "heading": "The Lede",
            "body": (
                "Cloudflare published a post last week introducing a tool that checks whether "
                "your site is configured to work well with AI agents — an 'agent readiness "
                "score.' Does it have a robots.txt? Does it serve clean markdown when an agent "
                "asks for it? Does it expose an MCP server? All good signals, but every one "
                "depends on the agent or the server choosing to declare intent. The authors "
                "mention that as of February 2026, only 3 of 7 agents they tested actually "
                "request markdown by default. I've been working on a different question: can "
                "you tell what kind of client is connecting before it says anything at all? "
                "I expected to find that each AI SDK left its own mark. It doesn't work that "
                "way. Every Python AI SDK looked identical. The mark isn't left by the SDK — "
                "it's left by something lower down."
            ),
        },
        {
            "heading": "The handshake happens before hello",
            "body": (
                "When you connect to a website over HTTPS, there's a negotiation that happens "
                "before any content is exchanged. The client sends a ClientHello message — the "
                "first packet in the TLS handshake — listing the cipher suites and extensions "
                "it supports. Only after the handshake completes does the browser send an HTTP "
                "request. The contents of that ClientHello are controlled by the TLS library the "
                "client was compiled against, not the application running on top of it. A Python "
                "script using the Anthropic SDK and one using the OpenAI SDK both go through the "
                "same underlying TLS library. They look identical at this layer. JA4 is a hashing "
                "scheme that turns ClientHello contents into a short, comparable string. Chrome "
                "deliberately inserts random reserved values (GREASE, RFC 8701) into its "
                "ClientHello — their presence is a near-certain browser signal."
            ),
        },
        {
            "heading": "What the catalogue actually shows",
            "body": (
                "All Python AI SDKs — OpenAI, Anthropic, LangChain — produce the same fingerprint "
                "on the same machine. Not similar. Identical. The SDK doesn't control the TLS "
                "handshake; the language does, specifically the TLS library it's built on. "
                "Go's TLS implementation is entirely its own (crypto/tls) — unambiguous from the "
                "first packet, nothing else in the catalogue resembles it. curl on macOS links "
                "against LibreSSL; curl on Linux links against OpenSSL — same tool, completely "
                "different profile. The overlap between Rust and curl on Linux is real: both link "
                "against OpenSSL, sharing cipher suite characteristics. ALPN presence is usually "
                "enough to separate them, but this is probabilistic, not deterministic. The "
                "agent/tool distinction in the classifier rests on a single signal: extension "
                "count. curl sends 7-8 extensions, Python's HTTP library sends 9-12. One "
                "threshold. A curl with extra flags, or a minimal Python client, would cross it "
                "in the wrong direction."
            ),
        },
        {
            "heading": "This site serves agents differently",
            "body": (
                "The terminal at the top of the article page wasn't a mockup. When you loaded "
                "it, a proxy classified your connection before the TLS handshake was complete and "
                "routed you to a different backend based on what it found. Browsers get HTML. "
                "Python clients, Go programs, and curl get JSON. The proxy reads the ClientHello "
                "using MSG_PEEK — a socket operation that copies bytes from the kernel buffer "
                "without consuming them. That's enough to compute the JA4 fingerprint and "
                "classify the client. The bytes remain in the buffer; the proxy proceeds with a "
                "normal TLS handshake. The classification headers (X-Client-Type, X-Client-JA4, "
                "X-Client-Confidence) arrive at the backend before a single line of application "
                "code runs. You are reading this JSON response because your client_type was "
                "classified as non-browser at the network layer, before any HTTP was exchanged."
            ),
        },
        {
            "heading": "Two layers, two different problems",
            "body": (
                "The application layer tells you whether your site is configured to serve agents. "
                "The TLS layer tells you what's actually connecting, regardless of what it claims. "
                "Neither is sufficient alone. TLS identity without good application-layer serving "
                "is just a label. Application-layer readiness without identity requires agents to "
                "opt in before it works. Cloudflare Tunnel terminates TLS at the edge — the "
                "ClientHello never reaches your origin server, so transport-layer fingerprinting "
                "is unavailable in that architecture. Running this classification requires sitting "
                "before that termination point. What you get is routing logic that requires no "
                "application changes: serve structured data to agents, rate-limit by client class, "
                "log runtime version drift — all from a header the proxy injects"
                " before HTTP begins."
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


def _query_traffic_stats() -> dict:
    """
    Run all /stats queries against the traffic SQLite DB.
    Returns empty defaults if the DB is unavailable.
    """
    empty = {
        "recent": [],
        "top_ja4": [],
        "gap_candidates": [],
        "chart_labels": [f"{h:02d}:00" for h in range(24)],
        "chart_datasets": {},
        "db_available": False,
    }
    if not TRAFFIC_DB_PATH:
        return empty

    try:
        conn = sqlite3.connect(f"file:{TRAFFIC_DB_PATH}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    except Exception:
        return empty

    try:
        recent = [
            dict(r) for r in conn.execute(
                "SELECT ts, ja4, path, client_type, detail, match_type"
                " FROM traffic_log ORDER BY id DESC LIMIT 50"
            )
        ]

        top_ja4 = [
            dict(r) for r in conn.execute(
                "SELECT ja4, client_type, detail, COUNT(*) as cnt"
                " FROM traffic_log"
                " WHERE ts >= datetime('now', '-24 hours')"
                " GROUP BY ja4 ORDER BY cnt DESC LIMIT 5"
            )
        ]

        gap_candidates = [
            dict(r) for r in conn.execute(
                "SELECT ja4, detail, COUNT(*) as cnt, MAX(ts) as last_seen"
                " FROM traffic_log"
                " WHERE match_type = 'heuristic'"
                " GROUP BY ja4 HAVING cnt >= 3"
                " ORDER BY cnt DESC"
            )
        ]

        hourly_rows = conn.execute(
            "SELECT strftime('%H', ts) as hour, client_type, COUNT(*) as cnt"
            " FROM traffic_log"
            " WHERE ts >= datetime('now', '-24 hours')"
            " GROUP BY hour, client_type ORDER BY hour"
        ).fetchall()

        client_types = ["browser", "agent", "tool", "headless", "unknown"]
        datasets: dict[str, list[int]] = {ct: [0] * 24 for ct in client_types}
        for row in hourly_rows:
            h = int(row["hour"])
            ct = row["client_type"]
            if ct in datasets:
                datasets[ct][h] = row["cnt"]

        return {
            "recent": recent,
            "top_ja4": top_ja4,
            "gap_candidates": gap_candidates,
            "chart_labels": [f"{h:02d}:00" for h in range(24)],
            "chart_datasets": datasets,
            "db_available": True,
        }
    except Exception:
        return empty
    finally:
        conn.close()


@app.route("/stats")
def stats():
    """Traffic dashboard — last 50 requests, hourly breakdown, catalogue gaps."""
    classification, _ = _get_classification()
    data = _query_traffic_stats()
    return render_template(
        "stats.html",
        classification=classification,
        chart_data_json=json.dumps({
            "labels": data["chart_labels"],
            "datasets": data["chart_datasets"],
        }),
        **data,
    )


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.getenv("BACKEND_PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False)
