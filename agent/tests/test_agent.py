"""
Tests for agent/app.py — JSON responses and route correctness.
"""

from unittest import mock

from fastapi.testclient import TestClient

import app as agent_app
from app import app

client = TestClient(app)

FULL_HEADERS = {
    "X-Client-JA4": "t13d1516h2_8daaf6152771_b1ff8ab2d16f",
    "X-Client-Type": "agent",
    "X-Client-Detail": "Python/urllib (macOS LibreSSL)",
    "X-Client-Confidence": "high",
    "X-Client-Signals": "alpn,cipher_order",
    "X-Client-Match-Type": "exact",
}


class TestIndex:
    def test_returns_200(self):
        r = client.get("/")
        assert r.status_code == 200

    def test_content_type_is_json(self):
        r = client.get("/")
        assert "application/json" in r.headers["content-type"]

    def test_type_field(self):
        r = client.get("/")
        assert r.json()["type"] == "personal-site"

    def test_owner_field(self):
        r = client.get("/")
        assert r.json()["owner"] == "Connor Jones"

    def test_links_is_list(self):
        r = client.get("/")
        assert isinstance(r.json()["links"], list)

    def test_links_not_empty(self):
        r = client.get("/")
        assert len(r.json()["links"]) > 0

    def test_note_field(self):
        r = client.get("/")
        assert "agent" in r.json()["note"].lower()

    def test_fingerprint_full_headers(self):
        r = client.get("/", headers=FULL_HEADERS)
        fp = r.json()["fingerprint"]
        assert fp["ja4"] == FULL_HEADERS["X-Client-JA4"]
        assert fp["client_type"] == "agent"
        assert fp["detail"] == "Python/urllib (macOS LibreSSL)"
        assert fp["confidence"] == "high"
        assert fp["signals"] == ["alpn", "cipher_order"]

    def test_fingerprint_signals_is_list_not_string(self):
        r = client.get("/", headers=FULL_HEADERS)
        assert isinstance(r.json()["fingerprint"]["signals"], list)

    def test_fingerprint_match_type_from_header(self):
        r = client.get("/", headers=FULL_HEADERS)
        assert r.json()["fingerprint"]["match_type"] == "exact"

    def test_fingerprint_no_headers_returns_nulls(self):
        r = client.get("/")
        fp = r.json()["fingerprint"]
        assert fp["ja4"] is None
        assert fp["client_type"] is None
        assert fp["detail"] is None
        assert fp["confidence"] is None
        assert fp["signals"] is None
        assert fp["match_type"] is None
        assert "note" in fp

    def test_fingerprint_partial_headers(self):
        r = client.get("/", headers={"X-Client-JA4": "t13d..."})
        fp = r.json()["fingerprint"]
        assert fp["ja4"] == "t13d..."
        assert fp["client_type"] is None
        assert fp["confidence"] is None
        assert fp["signals"] == []


class TestFingerprint:
    def test_returns_200(self):
        r = client.get("/fingerprint", headers=FULL_HEADERS)
        assert r.status_code == 200

    def test_full_headers(self):
        r = client.get("/fingerprint", headers=FULL_HEADERS)
        fp = r.json()
        assert fp["ja4"] == FULL_HEADERS["X-Client-JA4"]
        assert fp["client_type"] == "agent"
        assert fp["detail"] == "Python/urllib (macOS LibreSSL)"
        assert fp["confidence"] == "high"
        assert fp["signals"] == ["alpn", "cipher_order"]

    def test_match_type_from_header(self):
        r = client.get("/fingerprint", headers=FULL_HEADERS)
        assert r.json()["match_type"] == "exact"

    def test_no_headers_returns_nulls_with_note(self):
        r = client.get("/fingerprint")
        fp = r.json()
        assert fp["ja4"] is None
        assert fp["client_type"] is None
        assert fp["signals"] is None
        assert fp["match_type"] is None
        assert "note" in fp

    def test_partial_headers(self):
        r = client.get("/fingerprint", headers={"X-Client-JA4": "t13d...", "X-Client-Type": "tool"})
        fp = r.json()
        assert fp["ja4"] == "t13d..."
        assert fp["client_type"] == "tool"
        assert fp["detail"] is None
        assert fp["signals"] == []

    def test_signals_empty_string_guard(self):
        r = client.get("/fingerprint", headers={**FULL_HEADERS, "X-Client-Signals": ""})
        assert r.json()["signals"] == []


class TestCatalogue:
    def test_file_present_returns_200_json_array(self):
        data = [{"ja4": "t13d...", "sdk": "openai-python"}]
        with mock.patch.object(agent_app, "_catalogue", data):
            r = client.get("/catalogue")
        assert r.status_code == 200
        assert r.json() == data

    def test_file_missing_returns_503(self):
        with mock.patch.object(agent_app, "_catalogue", None):
            r = client.get("/catalogue")
        assert r.status_code == 503
        assert r.json() == {"error": "catalogue unavailable"}

    def test_catalogue_unavailable_returns_503(self):
        # Covers both file-missing and malformed-JSON failure paths:
        # both result in _catalogue=None after lifespan, which returns 503.
        with mock.patch.object(agent_app, "_catalogue", None):
            r = client.get("/catalogue")
        assert r.status_code == 503
        assert r.json() == {"error": "catalogue unavailable"}


class TestHealth:
    def test_returns_200(self):
        r = client.get("/health")
        assert r.status_code == 200

    def test_status_ok(self):
        r = client.get("/health")
        assert r.json() == {"status": "ok"}
