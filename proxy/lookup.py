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

import json
import logging
import os

import httpx

from classifier import Classification

log = logging.getLogger("proxy.lookup")

JA4DB_URL = "https://ja4db.com/api/read/"
CATALOGUE_PATH = os.environ.get(
    "CATALOGUE_PATH", "/data/catalogue/ai-sdk-fingerprints.json"
)

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


def _from_catalogue_entry(entry: dict, *, match_type: str = "exact") -> Classification:
    """
    Convert a local catalogue entry to a Classification.

    client_type is read from the entry when present. Entries captured before
    the field was added to the schema default to "agent" for backward
    compatibility (the catalogue originally contained only Python AI SDKs,
    all of which are agents).
    """
    client_type = entry.get("client_type", "agent")
    client = entry.get("http_client", "unknown")
    version = entry.get("http_client_version", "")
    runtime = entry.get("runtime", "")
    runtime_version = entry.get("runtime_version", "")
    os_name = entry.get("os", "")

    client_str = f"{client} {version}".strip() if version else client
    runtime_str = f"{runtime} {runtime_version}".strip() if runtime_version else runtime
    platform_parts = [p for p in (runtime_str, os_name) if p]
    platform_str = " / ".join(platform_parts)

    if platform_str:
        detail = f"{client_str} on {platform_str}"
    else:
        detail = client_str

    confidence = "high" if match_type == "exact" else "medium"
    return Classification(
        client_type=client_type,
        confidence=confidence,
        detail=f"{detail} (catalogue)",
        signals=["catalogue_match"],
        match_type=match_type,
    )


def _near_match_classification(entry: dict, score: int) -> Classification:
    """Build a Classification for a near-match catalogue entry."""
    client = entry.get("http_client", "unknown")
    version = entry.get("http_client_version", "")
    runtime = entry.get("runtime", "")
    runtime_version = entry.get("runtime_version", "")
    os_name = entry.get("os", "")
    client_type = entry.get("client_type", "agent")

    client_str = f"{client} {version}".strip() if version else client
    runtime_str = f"{runtime} {runtime_version}".strip() if runtime_version else runtime
    platform_parts = [p for p in (runtime_str, os_name) if p]
    platform_str = " / ".join(platform_parts)

    if platform_str:
        label = f"{client_str} on {platform_str}"
    else:
        label = client_str

    detail = f"Likely {label}, {score}% match (catalogue)"
    return Classification(
        client_type=client_type,
        confidence="medium",
        detail=detail,
        signals=["catalogue_near_match"],
        match_type="near",
    )


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

    def _load_local_catalogue(self) -> None:
        """Load local AI SDK fingerprint catalogue and merge into _db. Silent on missing file."""
        if not os.path.exists(CATALOGUE_PATH):
            return
        try:
            with open(CATALOGUE_PATH) as f:
                entries: list[dict] = json.loads(f.read())
        except Exception as exc:
            log.warning(f"catalogue load failed ({exc}) - skipping")
            return
        loaded = 0
        for entry in entries:
            if not entry.get("ja4"):
                continue
            self._db[entry["ja4"]] = entry
            loaded += 1
        log.info(f"local catalogue loaded: {loaded} fingerprints")

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

        self._load_local_catalogue()

    def lookup(self, ja4: str) -> Classification | None:
        """
        Return a Classification if the hash is in ja4db or local catalogue, otherwise None.
        Caller should fall back to lookup_nearest() or heuristic classify() on None.
        """
        record = self._db.get(ja4)
        if not record:
            return None

        # Local catalogue entries have a "ja4" key; ja4db entries have "ja4_fingerprint".
        if "ja4" in record and "ja4_fingerprint" not in record:
            return _from_catalogue_entry(record, match_type="exact")

        return Classification(
            client_type=_infer_type(record),
            confidence="high",
            detail=f"{_make_detail(record)} (ja4db)",
            signals=["ja4db_match"],
            match_type="exact",
        )

    def lookup_nearest(self, ja4: str) -> Classification | None:
        """
        Return a near-match Classification for catalogue entries that share Part A and B
        of the JA4 hash (same TLS version/counts and cipher suite hash) but differ on
        Part C (extension/sig-alg hash).

        Scoring (Option A — hash-part comparison):
          - Part A match is a prerequisite; candidates that differ on Part A are skipped.
          - Part B match contributes 60 points; Part C match contributes 40 points.
          - An exact match (100 points) is already handled by lookup(); it is skipped here.
          - A+B match (60 points) → "Likely <sdk>, 60% match" / confidence "medium".
          - A only (0 points) → below threshold; not returned.

        Only local catalogue entries are considered — ja4db entries lack the SDK-level
        metadata needed to build a meaningful near-match detail string.

        Returns None if no candidate scores above MIN_SCORE.
        """
        MIN_SCORE = 50  # A+B match (60) clears this; A-only (0) does not.

        parts = ja4.split("_")
        if len(parts) != 3:
            return None
        part_a, part_b, part_c = parts

        best: Classification | None = None
        best_score = -1

        for entry in self._db.values():
            # Only compare local catalogue entries.
            if "ja4" not in entry or "ja4_fingerprint" in entry:
                continue

            entry_ja4 = entry.get("ja4", "")
            entry_parts = entry_ja4.split("_")
            if len(entry_parts) != 3:
                continue
            e_a, e_b, e_c = entry_parts

            # Part A must match exactly (TLS version + cipher/ext counts + ALPN).
            if e_a != part_a:
                continue

            # Skip exact matches — handled by the fast path in lookup().
            if e_b == part_b and e_c == part_c:
                continue

            score = 0
            if e_b == part_b:
                score += 60
            if e_c == part_c:
                score += 40

            if score <= MIN_SCORE:
                continue

            if score > best_score:
                best_score = score
                best = _near_match_classification(entry, score)

        return best

    @property
    def size(self) -> int:
        return len(self._db)
