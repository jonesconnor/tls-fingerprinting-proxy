"""
app.py — Agent upstream service.

Receives requests routed by the proxy when it detects a non-browser client
(client_type in {agent, tool, headless}). Always returns JSON — no content
negotiation, no HTML.

Routes
------
  GET /             structured JSON response for machine consumption
  GET /fingerprint  TLS fingerprint profile for any caller
  GET /compare      JSON fingerprint data (browser clients get the visual HTML page)
  GET /catalogue    serve ai-sdk-fingerprints.json as a JSON array
  GET /health       health check
"""

import json
import logging
import os
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("agent")

OWNER = "Connor Jones"
TAGLINE = (
    "Software engineer. I work on infrastructure and distributed systems — "
    "understanding how they behave, how they should be designed, and why they sometimes aren't."
)

LINKS = [
    {"rel": "github", "url": "https://github.com/jonesconnor"},
    {"rel": "linkedin", "url": "https://linkedin.com/in/connorgarrettjones"},
    {"rel": "x", "url": "https://x.com/jonesconnorg"},
    {"rel": "project", "url": "https://github.com/jonesconnor/tls-fingerprinting-proxy"},
]

_catalogue = None
TRAFFIC_DB_PATH = os.getenv("TRAFFIC_DB_PATH", "")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _catalogue
    catalogue_path = os.getenv("CATALOGUE_PATH", "")
    if catalogue_path:
        try:
            with open(catalogue_path) as f:
                _catalogue = json.load(f)
            logger.info("Catalogue loaded: %d entries", len(_catalogue))
        except Exception as exc:
            logger.warning("Catalogue load failed: %s — /catalogue will return 503", exc)
            _catalogue = None
    yield


app = FastAPI(lifespan=lifespan)


def _parse_fingerprint_headers(request: Request) -> dict:
    """Parse X-Client-* headers injected by the proxy. Returns null fields when absent."""
    ja4 = request.headers.get("X-Client-JA4")
    client_type = request.headers.get("X-Client-Type")
    detail = request.headers.get("X-Client-Detail")
    confidence = request.headers.get("X-Client-Confidence")
    raw_signals = request.headers.get("X-Client-Signals")
    match_type = request.headers.get("X-Client-Match-Type")

    if ja4 is None:
        return {
            "ja4": None,
            "client_type": None,
            "detail": None,
            "confidence": None,
            "signals": None,
            "match_type": None,
            "note": "request did not pass through proxy",
        }

    signals = [s.strip() for s in raw_signals.split(",") if s.strip()] if raw_signals else []

    return {
        "ja4": ja4,
        "client_type": client_type,
        "detail": detail,
        "confidence": confidence,
        "signals": signals,
        "match_type": match_type,
    }


@app.get("/")
def index(request: Request):
    return JSONResponse(
        content={
            "type": "personal-site",
            "owner": OWNER,
            "tagline": TAGLINE,
            "note": (
                "You are receiving this JSON response because your client was identified "
                "as a non-browser agent via TLS fingerprinting. Browser clients receive "
                "an HTML page at the same URL."
            ),
            "links": LINKS,
            "endpoints": {
                "fingerprint": "/fingerprint",
                "catalogue": "/catalogue",
            },
            "fingerprint": _parse_fingerprint_headers(request),
        },
    )


@app.get("/fingerprint")
def fingerprint(request: Request):
    return JSONResponse(content=_parse_fingerprint_headers(request))


@app.get("/compare")
def compare(request: Request):
    """
    Machine-readable version of the /compare fingerprint breakdown page.
    The visual HTML page is served to browsers; non-browser clients receive
    this JSON response with the same underlying data.
    """
    return JSONResponse(
        content={
            "note": (
                "/compare is a visual fingerprint breakdown page served to browsers. "
                "You are receiving JSON because your client was identified as a non-browser. "
                "Your fingerprint data is below. Visit /compare from a browser for the "
                "interactive version."
            ),
            "fingerprint": _parse_fingerprint_headers(request),
        },
    )


@app.get("/catalogue")
def catalogue():
    if _catalogue is None:
        return JSONResponse(status_code=503, content={"error": "catalogue unavailable"})
    return JSONResponse(content=_catalogue)


@app.get("/stats")
def stats_json():
    """JSON traffic dashboard — mirrors backend /stats for non-browser clients."""
    if not TRAFFIC_DB_PATH:
        return JSONResponse(status_code=503, content={"error": "traffic log unavailable"})
    try:
        conn = sqlite3.connect(f"file:{TRAFFIC_DB_PATH}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    except Exception as exc:
        return JSONResponse(status_code=503, content={"error": f"traffic log unavailable: {exc}"})

    try:
        recent = [dict(r) for r in conn.execute(
            "SELECT ts, ja4, path, client_type, detail, match_type"
            " FROM traffic_log ORDER BY id DESC LIMIT 50"
        )]
        top_ja4 = [dict(r) for r in conn.execute(
            "SELECT ja4, client_type, detail, COUNT(*) as cnt"
            " FROM traffic_log WHERE ts >= datetime('now', '-24 hours')"
            " GROUP BY ja4 ORDER BY cnt DESC LIMIT 5"
        )]
        gap_candidates = [dict(r) for r in conn.execute(
            "SELECT ja4, detail, COUNT(*) as cnt, MAX(ts) as last_seen"
            " FROM traffic_log WHERE match_type = 'heuristic'"
            " GROUP BY ja4 HAVING cnt >= 3 ORDER BY cnt DESC"
        )]
        return JSONResponse(content={
            "recent_requests": recent,
            "top_ja4_24h": top_ja4,
            "catalogue_gap_candidates": gap_candidates,
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})
    finally:
        conn.close()


@app.get("/health")
def health():
    return JSONResponse(content={"status": "ok"})


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("AGENT_PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port)
