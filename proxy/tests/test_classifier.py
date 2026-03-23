"""
Tests for classifier.py — heuristic client classification.

Each test targets a specific classification rule and verifies both the
client_type and confidence. Rules are tested in the same order they appear
in the classifier (most-specific → least-specific).
"""


from classifier import Classification, classify

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clf(make_ch, **kwargs) -> Classification:
    ch = make_ch(**kwargs)
    return classify("t13d0003h2_aabbccddeeff_aabbccddeeff", ch)


# ---------------------------------------------------------------------------
# Chrome / Edge — full profile (GREASE + ECH + compress_cert + TLS 1.3)
# ---------------------------------------------------------------------------

class TestChrome:
    def test_full_profile_is_browser_high(self, make_ch):
        clf = _clf(
            make_ch,
            has_grease=True,
            has_ech=True,
            has_compress_cert=True,
            supported_versions=[0x0304],
        )
        assert clf.client_type == "browser"
        assert clf.confidence == "high"

    def test_full_profile_signals(self, make_ch):
        clf = _clf(
            make_ch,
            has_grease=True,
            has_ech=True,
            has_compress_cert=True,
            supported_versions=[0x0304],
        )
        assert "grease" in clf.signals
        assert "ech" in clf.signals
        assert "compress_cert" in clf.signals
        assert "tls13" in clf.signals

    def test_no_ech_still_browser_high_with_enough_ciphers(self, make_ch):
        # Chrome/Edge without ECH (older release): GREASE + compress_cert + >=12 ciphers
        clf = _clf(
            make_ch,
            has_grease=True,
            has_ech=False,
            has_compress_cert=True,
            cipher_suites=list(range(0x1301, 0x130e)),  # 13 ciphers
        )
        assert clf.client_type == "browser"
        assert clf.confidence == "high"

    def test_grease_without_compress_cert_does_not_match_chrome_rules(self, make_ch):
        # GREASE alone is not enough for the Chrome rules — needs compress_cert
        clf = _clf(
            make_ch,
            has_grease=True,
            has_ech=False,
            has_compress_cert=False,
            cipher_suites=list(range(0x1301, 0x130e)),
            extension_types=list(range(0x0001, 0x000a)),  # 9 extensions, no rich_extensions
        )
        # Should fall through to Node.js or unknown, not Chrome
        assert clf.client_type != "browser"


# ---------------------------------------------------------------------------
# Firefox — compress_cert, no GREASE, rich extensions, TLS 1.3
# ---------------------------------------------------------------------------

class TestFirefox:
    def test_firefox_profile_is_browser_medium(self, make_ch):
        clf = _clf(
            make_ch,
            has_grease=False,
            has_compress_cert=True,
            has_ech=False,
            supported_versions=[0x0304],
            extension_types=list(range(0x0001, 0x000f)),  # 14 extensions
        )
        assert clf.client_type == "browser"
        assert clf.confidence == "medium"

    def test_firefox_needs_tls13(self, make_ch):
        # Same profile but TLS 1.2 should NOT match the Firefox rule
        clf = _clf(
            make_ch,
            has_grease=False,
            has_compress_cert=True,
            supported_versions=[0x0303],  # TLS 1.2
            extension_types=list(range(0x0001, 0x000f)),
        )
        assert clf.client_type != "browser"

    def test_firefox_needs_at_least_12_extensions(self, make_ch):
        clf = _clf(
            make_ch,
            has_grease=False,
            has_compress_cert=True,
            supported_versions=[0x0304],
            extension_types=list(range(0x0001, 0x000b)),  # only 10 extensions
        )
        assert clf.client_type != "browser"


# ---------------------------------------------------------------------------
# Safari / WebKit — curated ciphers, no GREASE, no compress_cert, has ALPN
# ---------------------------------------------------------------------------

class TestSafari:
    def test_safari_profile_is_browser_medium(self, make_ch):
        clf = _clf(
            make_ch,
            has_grease=False,
            has_compress_cert=False,
            cipher_suites=list(range(0x1301, 0x130e)),   # 13 ciphers (curated)
            extension_types=list(range(0x0001, 0x000c)),  # 11 extensions
            alpn_protocols=["h2"],
        )
        assert clf.client_type == "browser"
        assert clf.confidence == "medium"

    def test_safari_requires_alpn(self, make_ch):
        # Same profile but no ALPN → should classify as macOS Python, not Safari
        clf = _clf(
            make_ch,
            has_grease=False,
            has_compress_cert=False,
            cipher_suites=list(range(0x1301, 0x130e)),
            extension_types=list(range(0x0001, 0x000c)),
            alpn_protocols=[],
        )
        assert clf.client_type != "browser"


# ---------------------------------------------------------------------------
# macOS Python — curated ciphers, no GREASE, NO ALPN
# The critical separator from Safari is the absence of ALPN.
# ---------------------------------------------------------------------------

class TestMacOSPython:
    def test_macos_python_is_agent_medium(self, make_ch):
        clf = _clf(
            make_ch,
            has_grease=False,
            has_compress_cert=False,
            cipher_suites=list(range(0x1301, 0x130e)),  # 13 ciphers (curated)
            alpn_protocols=[],                           # NO ALPN — the key signal
        )
        assert clf.client_type == "agent"
        assert clf.confidence == "medium"

    def test_macos_python_detail_mentions_macos(self, make_ch):
        clf = _clf(
            make_ch,
            has_grease=False,
            cipher_suites=list(range(0x1301, 0x130e)),
            alpn_protocols=[],
        )
        assert "macos" in clf.detail.lower() or "mac" in clf.detail.lower()


# ---------------------------------------------------------------------------
# curl / wget — permissive cipher list, very few extensions
# ---------------------------------------------------------------------------

class TestCurl:
    def test_curl_profile_is_tool_medium(self, make_ch):
        clf = _clf(
            make_ch,
            has_grease=False,
            cipher_suites=list(range(0x0001, 0x0030)),  # 47 ciphers (permissive >=40)
            extension_types=list(range(0x0001, 0x0008)),  # 7 extensions (<=8)
        )
        assert clf.client_type == "tool"
        assert clf.confidence == "medium"

    def test_curl_signals_include_permissive_ciphers(self, make_ch):
        clf = _clf(
            make_ch,
            has_grease=False,
            cipher_suites=list(range(0x0001, 0x0030)),
            extension_types=list(range(0x0001, 0x0008)),
        )
        assert "permissive_ciphers" in clf.signals


# ---------------------------------------------------------------------------
# Python agent — permissive ciphers, 9–12 extensions (more than curl)
# Covers: requests, httpx, aiohttp, openai-python, anthropic-python
# ---------------------------------------------------------------------------

class TestPythonAgent:
    def test_python_agent_is_agent_high(self, make_ch):
        clf = _clf(
            make_ch,
            has_grease=False,
            cipher_suites=list(range(0x0001, 0x0030)),  # 47 ciphers (permissive)
            extension_types=list(range(0x0001, 0x000b)),  # 10 extensions (9–12)
        )
        assert clf.client_type == "agent"
        assert clf.confidence == "high"

    def test_python_agent_not_classified_as_tool(self, make_ch):
        # Python agents have more extensions than curl (>8)
        clf = _clf(
            make_ch,
            has_grease=False,
            cipher_suites=list(range(0x0001, 0x0030)),
            extension_types=list(range(0x0001, 0x000b)),  # 10 — above curl threshold of 8
        )
        assert clf.client_type != "tool"


# ---------------------------------------------------------------------------
# Go net/http — minimal cipher set, no GREASE
# ---------------------------------------------------------------------------

class TestGoAgent:
    def test_go_profile_is_agent_high(self, make_ch):
        clf = _clf(
            make_ch,
            has_grease=False,
            cipher_suites=[0x1301, 0x1302, 0x1303],      # 3 ciphers (minimal <=6)
            extension_types=list(range(0x0001, 0x0007)),  # 6 extensions (<=8)
        )
        assert clf.client_type == "agent"
        assert clf.confidence == "high"

    def test_go_signals_include_minimal_ciphers(self, make_ch):
        clf = _clf(
            make_ch,
            has_grease=False,
            cipher_suites=[0x1301, 0x1302],
            extension_types=list(range(0x0001, 0x0007)),
        )
        assert "minimal_ciphers" in clf.signals


# ---------------------------------------------------------------------------
# Node.js — moderate ciphers, no GREASE, decent extension count
# ---------------------------------------------------------------------------

class TestNodeAgent:
    def test_node_profile_is_agent_medium(self, make_ch):
        # 10 ciphers: above minimal(6), below curated(12), below permissive(40)
        # 9 extensions: above minimal(5), satisfies Node.js threshold(>=8)
        clf = _clf(
            make_ch,
            has_grease=False,
            has_compress_cert=False,
            cipher_suites=list(range(0x1301, 0x130b)),   # 10 ciphers
            extension_types=list(range(0x0001, 0x000a)),  # 9 extensions
        )
        assert clf.client_type == "agent"
        assert clf.confidence == "medium"


# ---------------------------------------------------------------------------
# Unknown — profile that doesn't match any rule
# ---------------------------------------------------------------------------

class TestUnknown:
    def test_unclassifiable_profile_is_unknown_low(self, make_ch):
        # 8 ciphers: not minimal(>6), not curated(<12), not permissive(<40)
        # 6 extensions: not enough for Node.js(>=8), not minimal(>5)
        # No GREASE, no compress_cert
        clf = _clf(
            make_ch,
            has_grease=False,
            has_compress_cert=False,
            cipher_suites=list(range(0x0001, 0x0009)),   # 8 ciphers
            extension_types=list(range(0x0001, 0x0007)),  # 6 extensions
        )
        assert clf.client_type == "unknown"
        assert clf.confidence == "low"


# ---------------------------------------------------------------------------
# Catalogue lookup — highest-confidence fast path (via Ja4Database)
# ---------------------------------------------------------------------------

class TestKnownHash:
    def test_catalogue_hash_returns_agent_high(self, tmp_path):
        """A hash in the local catalogue should return agent/high via Ja4Database.lookup()."""
        import json
        from unittest.mock import patch
        from lookup import Ja4Database

        test_hash = "t00d0000h2_000000000000_000000000000"
        entry = {
            "sdk": "openai-python",
            "sdk_version": "1.0.0",
            "ja4": test_hash,
        }
        catalogue = tmp_path / "fingerprints.json"
        catalogue.write_text(json.dumps([entry]))

        db = Ja4Database()
        with patch("lookup.CATALOGUE_PATH", str(catalogue)):
            db._load_local_catalogue()

        clf = db.lookup(test_hash)
        assert clf is not None
        assert clf.client_type == "agent"
        assert clf.confidence == "high"
        assert "catalogue_match" in clf.signals
