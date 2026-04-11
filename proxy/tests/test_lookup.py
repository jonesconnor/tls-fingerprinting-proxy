"""
Tests for lookup.py — Ja4Database local catalogue loading and adapter.
"""

import json
from unittest.mock import patch

import pytest

from lookup import Ja4Database, _from_catalogue_entry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_catalogue(path, entries):
    with open(path, "w") as f:
        json.dump(entries, f)


SAMPLE_ENTRY = {
    "runtime":             "python",
    "runtime_version":     "3.11.x",
    "http_client":         "openai",
    "http_client_version": "1.65.4",
    "os":                  "macOS 15",
    "tls_library":         "LibreSSL 3.x",
    "ja4":                 "t13d0000h2_aabbccddeeff_aabbccddeeff",
    "alpn_present":        False,
    "captured_at":         "2026-03-21T12:00:00Z",
    # No client_type field — exercises the backward-compat default ("agent").
}

# Runtime-capture entries include an explicit client_type.
SAMPLE_ENTRY_TOOL = {
    **SAMPLE_ENTRY,
    "ja4":        "t13d0001h2_aabbccddeeff_aabbccddeeff",
    "runtime":    "curl",
    "http_client": "curl",
    "client_type": "tool",
}

SAMPLE_ENTRY_HEADLESS = {
    **SAMPLE_ENTRY,
    "ja4":        "t13d0002h2_aabbccddeeff_aabbccddeeff",
    "runtime":    "chromium",
    "http_client": "chromium",
    "client_type": "headless",
}


# ---------------------------------------------------------------------------
# TestCatalogueAdapter
# ---------------------------------------------------------------------------

class TestCatalogueAdapter:
    def test_defaults_to_agent_when_client_type_absent(self):
        # Entries captured before client_type was added to the schema have no
        # client_type field. They must still be classified as "agent" (backward compat).
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        assert clf.client_type == "agent"

    def test_reads_tool_client_type_from_entry(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY_TOOL)
        assert clf.client_type == "tool"

    def test_reads_headless_client_type_from_entry(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY_HEADLESS)
        assert clf.client_type == "headless"

    def test_reads_agent_client_type_from_entry(self):
        entry = {**SAMPLE_ENTRY, "client_type": "agent"}
        clf = _from_catalogue_entry(entry)
        assert clf.client_type == "agent"

    def test_confidence_is_high(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        assert clf.confidence == "high"

    def test_confidence_is_high_for_tool_entry(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY_TOOL)
        assert clf.confidence == "high"

    def test_signals_contains_catalogue_match(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        assert "catalogue_match" in clf.signals

    def test_detail_includes_http_client(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        assert "openai" in clf.detail

    def test_entry_without_version(self):
        clf = _from_catalogue_entry({"http_client": "httpx", "ja4": "t13d..."})
        assert clf.client_type == "agent"
        assert "httpx" in clf.detail


# ---------------------------------------------------------------------------
# TestLocalCatalogue
# ---------------------------------------------------------------------------

class TestLocalCatalogue:
    @pytest.fixture
    def db(self):
        return Ja4Database()

    def test_loads_valid_catalogue(self, db, tmp_path):
        catalogue = tmp_path / "fingerprints.json"
        _write_catalogue(catalogue, [SAMPLE_ENTRY])

        with patch("lookup.CATALOGUE_PATH", str(catalogue)):
            db._load_local_catalogue()

        assert db.size == 1

    def test_missing_catalogue_is_silent(self, db, tmp_path):
        nonexistent = str(tmp_path / "does_not_exist.json")
        with patch("lookup.CATALOGUE_PATH", nonexistent):
            db._load_local_catalogue()  # must not raise

        assert db.size == 0

    def test_malformed_json_is_silent(self, db, tmp_path):
        catalogue = tmp_path / "bad.json"
        catalogue.write_text("not valid json {{{")

        with patch("lookup.CATALOGUE_PATH", str(catalogue)):
            db._load_local_catalogue()  # must not raise

        assert db.size == 0

    def test_entry_missing_ja4_key_is_skipped(self, db, tmp_path):
        entries = [
            {"http_client": "no-ja4-key", "http_client_version": "1.0"},
            SAMPLE_ENTRY,
        ]
        catalogue = tmp_path / "fingerprints.json"
        _write_catalogue(catalogue, entries)

        with patch("lookup.CATALOGUE_PATH", str(catalogue)):
            db._load_local_catalogue()

        assert db.size == 1  # only the valid entry

    def test_local_catalogue_wins_over_ja4db(self, db, tmp_path):
        ja4_hash = SAMPLE_ENTRY["ja4"]

        # Pre-seed _db with a ja4db-style record for the same hash
        db._db[ja4_hash] = {
            "ja4_fingerprint": ja4_hash,
            "application": "Chrome 120",
            "library": None,
            "os": "Windows",
            "user_agent_string": "",
        }

        catalogue = tmp_path / "fingerprints.json"
        _write_catalogue(catalogue, [SAMPLE_ENTRY])

        with patch("lookup.CATALOGUE_PATH", str(catalogue)):
            db._load_local_catalogue()

        # After loading, the catalogue entry should have overwritten the ja4db entry.
        # Catalogue entries have "ja4" key but not "ja4_fingerprint".
        assert "ja4_fingerprint" not in db._db[ja4_hash]
        assert db._db[ja4_hash]["http_client"] == "openai"

    def test_lookup_returns_agent_for_catalogue_entry(self, db, tmp_path):
        catalogue = tmp_path / "fingerprints.json"
        _write_catalogue(catalogue, [SAMPLE_ENTRY])

        with patch("lookup.CATALOGUE_PATH", str(catalogue)):
            db._load_local_catalogue()

        clf = db.lookup(SAMPLE_ENTRY["ja4"])
        assert clf is not None
        assert clf.client_type == "agent"
        assert clf.confidence == "high"
        assert "catalogue_match" in clf.signals

    def test_lookup_returns_tool_for_tool_entry(self, db, tmp_path):
        """curl or Go net/http baseline entries must be routed as 'tool', not 'agent'."""
        catalogue = tmp_path / "fingerprints.json"
        _write_catalogue(catalogue, [SAMPLE_ENTRY_TOOL])

        with patch("lookup.CATALOGUE_PATH", str(catalogue)):
            db._load_local_catalogue()

        clf = db.lookup(SAMPLE_ENTRY_TOOL["ja4"])
        assert clf is not None
        assert clf.client_type == "tool"

    def test_lookup_returns_headless_for_browser_entry(self, db, tmp_path):
        """Playwright/Chromium entries must be routed as 'headless', not 'agent'."""
        catalogue = tmp_path / "fingerprints.json"
        _write_catalogue(catalogue, [SAMPLE_ENTRY_HEADLESS])

        with patch("lookup.CATALOGUE_PATH", str(catalogue)):
            db._load_local_catalogue()

        clf = db.lookup(SAMPLE_ENTRY_HEADLESS["ja4"])
        assert clf is not None
        assert clf.client_type == "headless"

    def test_mixed_catalogue_routes_each_entry_correctly(self, db, tmp_path):
        """With multiple client_type values in one catalogue, each must route correctly."""
        catalogue = tmp_path / "fingerprints.json"
        _write_catalogue(catalogue, [SAMPLE_ENTRY, SAMPLE_ENTRY_TOOL, SAMPLE_ENTRY_HEADLESS])

        with patch("lookup.CATALOGUE_PATH", str(catalogue)):
            db._load_local_catalogue()

        assert db.lookup(SAMPLE_ENTRY["ja4"]).client_type == "agent"
        assert db.lookup(SAMPLE_ENTRY_TOOL["ja4"]).client_type == "tool"
        assert db.lookup(SAMPLE_ENTRY_HEADLESS["ja4"]).client_type == "headless"
