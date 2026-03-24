"""
app.py — Agent upstream service.

Receives requests routed by the proxy when it detects a non-browser client
(client_type in {agent, tool, headless}). Always returns JSON — no content
negotiation, no HTML.

Routes
------
  GET /       structured JSON response for machine consumption
  GET /health health check
"""

import os

from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

OWNER = "Connor Jones"

LINKS = [
    {"rel": "github", "url": "https://github.com/jonesconnor"},
    {"rel": "linkedin", "url": "https://linkedin.com/in/connorjones"},
    {"rel": "project", "url": "https://github.com/jonesconnor/tls-fingerprinting-proxy"},
]


# The proxy reads backend responses until the server closes the connection.
# Uvicorn defaults to HTTP/1.1 keep-alive (5s timeout), which would cause the
# proxy to block for 5 seconds per request. Connection: close tells uvicorn to
# close immediately after each response.
_HEADERS = {"Connection": "close"}


@app.get("/")
def index():
    return JSONResponse(
        content={
            "type": "personal-site",
            "owner": OWNER,
            "links": LINKS,
            "note": "I know you're an agent.",
        },
        headers=_HEADERS,
    )


@app.get("/health")
def health():
    return JSONResponse(content={"status": "ok"}, headers=_HEADERS)


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("AGENT_PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port)
