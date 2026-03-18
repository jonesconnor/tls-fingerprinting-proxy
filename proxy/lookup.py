"""
lookup.py — ja4db.com database client.

Fetches the full ja4db on startup and does O(1) in-memory lookups per connection.
Falls back to heuristic classification (classifier.py) for unknown hashes.

API: GET https://ja4db.com/api/read/
Docs: https://docs.ja4db.com/ja4+-database/usage/read-the-database

Response is a JSON array of records:
    {
        "application": "Chrome 120",
        "library": null,
        "os": "Windows",
        "user_agent_string": "Mozilla/5.0 ...",
        "ja4_fingerprint": "t13d1516h2_8daaf6152771_02713d6af862",
        ...
    }
"""

import logging

import httpx

from classifier import Classification

log = logging.getLogger("proxy.lookup")

JA4DB_URL = "https://ja4db.com/api/read/"

# Keywords in `application`, `library`, or `user_agent_string` that map to our client types.
# Checked in order — first match wins.
_KEYWORDS: list[tuple[str, str]] = [
    ("playwright",  "headless"),
    ("puppeteer",   "headless"),
    ("selenium",    "headless"),
    ("chrome",      "browser"),
    ("firefox",     "browser"),
    ("safari",      "browser"),
    ("edge",        "browser"),
    ("opera",       "browser"),
    ("brave",       "browser"),
    ("curl",        "tool"),
    ("wget",        "tool"),
    ("httpie",      "tool"),
    ("python",      "agent"),
    ("requests",    "agent"),
    ("httpx",       "agent"),
    ("go-http",     "agent"),
    ("node",        "agent"),
    ("java",        "agent"),
    ("ruby",        "agent"),
    ("rust",        "agent"),
    ("dart",        "agent"),
]


def _infer_type(record: dict) -> str:
    text = " ".join(
        (record.get(f) or "").lower()
        for f in ("application", "library", "user_agent_string")
    )
    for keyword, client_type in _KEYWORDS:
        if keyword in text:
            return client_type
    return "unknown"


def _make_detail(record: dict) -> str:
    parts = [
        record.get("application") or "",
        record.get("library") or "",
        record.get("os") or "",
    ]
    return " / ".join(p for p in parts if p) or "Known fingerprint"


class Ja4Database:
    def __init__(self) -> None:
        self._db: dict[str, dict] = {}

    async def load(self) -> None:
        """Download the full ja4db and index it by JA4 hash. Safe to call at startup."""
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(JA4DB_URL, timeout=30)
                r.raise_for_status()
                records: list[dict] = r.json()

            self._db = {
                rec["ja4_fingerprint"]: rec
                for rec in records
                if rec.get("ja4_fingerprint")
            }
            log.info(f"ja4db loaded: {len(self._db)} fingerprints")

        except Exception as exc:
            log.warning(f"ja4db unavailable ({exc}) - heuristics only")

    def lookup(self, ja4: str) -> Classification | None:
        """
        Return a Classification if the hash is in ja4db, otherwise None.
        Caller should fall back to heuristic classify() on None.
        """
        record = self._db.get(ja4)
        if not record:
            return None

        return Classification(
            client_type=_infer_type(record),
            confidence="high",
            detail=f"{_make_detail(record)} (ja4db)",
            signals=["ja4db_match"],
        )

    @property
    def size(self) -> int:
        return len(self._db)
