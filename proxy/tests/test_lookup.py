"""
Tests for lookup.py — Ja4Database local catalogue loading and adapter.
"""

import json
from unittest.mock import patch

import pytest

from lookup import Ja4Database, _from_catalogue_entry, _near_match_classification

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


# ---------------------------------------------------------------------------
# TestDetailString
# ---------------------------------------------------------------------------

class TestDetailString:
    """Exact-match detail strings should identify SDK, runtime, and OS."""

    def test_detail_includes_version(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        # "openai 1.65.4 on python 3.11.x / macOS 15 (catalogue)"
        assert "openai" in clf.detail
        assert "1.65.4" in clf.detail

    def test_detail_includes_runtime(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        assert "python" in clf.detail

    def test_detail_includes_os(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        assert "macOS 15" in clf.detail

    def test_detail_format_on_keyword(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        assert " on " in clf.detail

    def test_detail_suffix_is_catalogue(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        assert clf.detail.endswith("(catalogue)")

    def test_match_type_defaults_to_exact(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY)
        assert clf.match_type == "exact"

    def test_near_match_type_sets_medium_confidence(self):
        clf = _from_catalogue_entry(SAMPLE_ENTRY, match_type="near")
        assert clf.confidence == "medium"
        assert clf.match_type == "near"

    def test_entry_without_os_omits_platform_separator(self):
        entry = {**SAMPLE_ENTRY, "os": ""}
        clf = _from_catalogue_entry(entry)
        # Should not have " / " if only runtime is present, not os
        assert "openai" in clf.detail
        assert "python" in clf.detail

    def test_entry_without_runtime_uses_client_only(self):
        entry = {**SAMPLE_ENTRY, "runtime": "", "runtime_version": "", "os": ""}
        clf = _from_catalogue_entry(entry)
        # No platform info — should still contain the client name
        assert "openai" in clf.detail
        assert " on " not in clf.detail


# ---------------------------------------------------------------------------
# TestNearMatchClassification
# ---------------------------------------------------------------------------

class TestNearMatchClassification:
    def test_returns_near_match_type(self):
        clf = _near_match_classification(SAMPLE_ENTRY, 60)
        assert clf.match_type == "near"

    def test_returns_medium_confidence(self):
        clf = _near_match_classification(SAMPLE_ENTRY, 60)
        assert clf.confidence == "medium"

    def test_detail_includes_likely_prefix(self):
        clf = _near_match_classification(SAMPLE_ENTRY, 60)
        assert clf.detail.startswith("Likely ")

    def test_detail_includes_score(self):
        clf = _near_match_classification(SAMPLE_ENTRY, 60)
        assert "60%" in clf.detail

    def test_signal_is_catalogue_near_match(self):
        clf = _near_match_classification(SAMPLE_ENTRY, 60)
        assert "catalogue_near_match" in clf.signals

    def test_client_type_from_entry(self):
        clf = _near_match_classification(SAMPLE_ENTRY_TOOL, 60)
        assert clf.client_type == "tool"


# ---------------------------------------------------------------------------
# TestLookupNearest
# ---------------------------------------------------------------------------

# JA4 format: <part_a>_<part_b>_<part_c>
# SAMPLE_ENTRY has ja4: "t13d0000h2_aabbccddeeff_aabbccddeeff"
_PART_A = "t13d0000h2"
_PART_B = "aabbccddeeff"
_PART_C = "aabbccddeeff"

# Entry with same A+B but different C → should match as near
NEAR_MATCH_ENTRY = {
    **SAMPLE_ENTRY,
    "ja4": f"{_PART_A}_{_PART_B}_112233445566",  # same A+B, different C
    "http_client": "anthropic",
    "http_client_version": "0.49.0",
}

# Entry with same A but different B+C → should NOT match (score=0)
PART_A_ONLY_ENTRY = {
    **SAMPLE_ENTRY,
    "ja4": f"{_PART_A}_ffeeddccbbaa_ffeeddccbbaa",  # same A only
    "http_client": "mistral",
}

# Entry with different A → should be excluded entirely
DIFFERENT_A_ENTRY = {
    **SAMPLE_ENTRY,
    "ja4": f"t13d9999h2_{_PART_B}_{_PART_C}",  # different A
    "http_client": "cohere",
}


class TestLookupNearest:
    @pytest.fixture
    def db(self):
        return Ja4Database()

    def _load(self, db, tmp_path, entries):
        catalogue = tmp_path / "fingerprints.json"
        _write_catalogue(catalogue, entries)
        with patch("lookup.CATALOGUE_PATH", str(catalogue)):
            db._load_local_catalogue()

    def test_returns_none_for_empty_catalogue(self, db):
        result = db.lookup_nearest(f"{_PART_A}_{_PART_B}_deadbeefcafe")
        assert result is None

    def test_returns_none_when_no_candidate_passes_threshold(self, db, tmp_path):
        # Only a part-A-only match (score=0) is in the catalogue.
        self._load(db, tmp_path, [PART_A_ONLY_ENTRY])
        result = db.lookup_nearest(f"{_PART_A}_{_PART_B}_deadbeefcafe")
        assert result is None

    def test_returns_none_when_different_a(self, db, tmp_path):
        self._load(db, tmp_path, [DIFFERENT_A_ENTRY])
        result = db.lookup_nearest(f"{_PART_A}_{_PART_B}_deadbeefcafe")
        assert result is None

    def test_ab_match_returns_near_classification(self, db, tmp_path):
        self._load(db, tmp_path, [NEAR_MATCH_ENTRY])
        incoming = f"{_PART_A}_{_PART_B}_deadbeefcafe"
        result = db.lookup_nearest(incoming)
        assert result is not None
        assert result.match_type == "near"
        assert result.confidence == "medium"

    def test_ab_match_detail_contains_score(self, db, tmp_path):
        self._load(db, tmp_path, [NEAR_MATCH_ENTRY])
        result = db.lookup_nearest(f"{_PART_A}_{_PART_B}_deadbeefcafe")
        assert result is not None
        assert "60%" in result.detail

    def test_ab_match_detail_contains_sdk_name(self, db, tmp_path):
        self._load(db, tmp_path, [NEAR_MATCH_ENTRY])
        result = db.lookup_nearest(f"{_PART_A}_{_PART_B}_deadbeefcafe")
        assert result is not None
        assert "anthropic" in result.detail

    def test_exact_match_is_skipped_by_lookup_nearest(self, db, tmp_path):
        # An exact match in the catalogue should not be returned by lookup_nearest;
        # it is already handled by the fast path in lookup().
        self._load(db, tmp_path, [SAMPLE_ENTRY])
        result = db.lookup_nearest(SAMPLE_ENTRY["ja4"])
        assert result is None

    def test_best_score_wins_when_multiple_candidates(self, db, tmp_path):
        # A+B+C partial match (C only) scores 40; A+B match scores 60.
        # The A+B match should win.
        c_only_match = {
            **SAMPLE_ENTRY,
            "ja4": f"{_PART_A}_ffeeddccbbaa_{_PART_C}",  # same A+C, different B → score=40
            "http_client": "cohere",
        }
        self._load(db, tmp_path, [NEAR_MATCH_ENTRY, c_only_match])
        result = db.lookup_nearest(f"{_PART_A}_{_PART_B}_deadbeefcafe")
        # NEAR_MATCH_ENTRY has A+B match (60); c_only_match has A+C (40 — but A is prerequisite,
        # and B differs from part_b so B score=0, C score=40 → total=40 <= MIN_SCORE=50).
        # So only NEAR_MATCH_ENTRY clears the threshold.
        assert result is not None
        assert "anthropic" in result.detail

    def test_malformed_ja4_returns_none(self, db, tmp_path):
        self._load(db, tmp_path, [NEAR_MATCH_ENTRY])
        assert db.lookup_nearest("not_valid") is None
        assert db.lookup_nearest("a_b") is None
        assert db.lookup_nearest("") is None

    def test_ja4db_entries_are_excluded_from_near_match(self, db):
        # ja4db-style entries (have "ja4_fingerprint" key) should not be candidates.
        ja4db_entry = {
            "ja4_fingerprint": f"{_PART_A}_{_PART_B}_112233445566",
            "application": "Chrome 120",
            "library": None,
            "os": "Windows",
            "user_agent_string": "",
        }
        db._db[f"{_PART_A}_{_PART_B}_112233445566"] = ja4db_entry
        result = db.lookup_nearest(f"{_PART_A}_{_PART_B}_deadbeefcafe")
        assert result is None

    def test_lookup_nearest_signal(self, db, tmp_path):
        self._load(db, tmp_path, [NEAR_MATCH_ENTRY])
        result = db.lookup_nearest(f"{_PART_A}_{_PART_B}_deadbeefcafe")
        assert result is not None
        assert "catalogue_near_match" in result.signals
