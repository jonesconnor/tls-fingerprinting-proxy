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
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("agent")

OWNER = "Connor Jones"
TAGLINE = "Software engineer. I work on infrastructure and distributed systems — understanding how they behave, how they should be designed, and why they sometimes aren't."

LINKS = [
    {"rel": "github", "url": "https://github.com/jonesconnor"},
    {"rel": "linkedin", "url": "https://linkedin.com/in/connorgarrettjones"},
    {"rel": "x", "url": "https://x.com/jonesconnorg"},
    {"rel": "project", "url": "https://github.com/jonesconnor/tls-fingerprinting-proxy"},
]

_catalogue = None


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

    if ja4 is None:
        return {
            "ja4": None,
            "client_type": None,
            "detail": None,
            "confidence": None,
            "signals": None,
            "note": "request did not pass through proxy",
        }

    signals = [s.strip() for s in raw_signals.split(",") if s.strip()] if raw_signals else []

    return {
        "ja4": ja4,
        "client_type": client_type,
        "detail": detail,
        "confidence": confidence,
        "signals": signals,
    }


@app.get("/")
def index(request: Request):
    return JSONResponse(
        content={
            "type": "personal-site",
            "owner": OWNER,
            "tagline": TAGLINE,
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


@app.get("/health")
def health():
    return JSONResponse(content={"status": "ok"})


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("AGENT_PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port)
