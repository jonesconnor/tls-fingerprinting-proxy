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
    "sdk": "openai-python",
    "sdk_version": "1.65.4",
    "python_version": "3.11.x",
    "os": "macOS 15",
    "tls_library": "LibreSSL 3.x",
    "ja4": "t13d0000h2_aabbccddeeff_aabbccddeeff",
    "alpn_present": False,
    "captured_at": "2026-03-21T12:00:00Z",
}


# ---------------------------------------------------------------------------
# TestCatalogueAdapter
# ---------------------------------------------------------------------------

class TestCatalogueAdapter:
    def test_returns_agent_classification(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        assert clf.client_type == "agent"

    def test_confidence_is_high(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        assert clf.confidence == "high"

    def test_signals_contains_catalogue_match(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        assert "catalogue_match" in clf.signals

    def test_detail_includes_sdk_name(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        assert "openai-python" in clf.detail

    def test_entry_without_version(self):
        clf = _from_catalogue_entry({"sdk": "httpx", "ja4": "t13d..."})
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
            {"sdk": "no-ja4-key", "sdk_version": "1.0"},
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
        assert db._db[ja4_hash]["sdk"] == "openai-python"

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
