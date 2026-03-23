"""
Tests for agent/app.py — JSON responses and route correctness.
"""

from fastapi.testclient import TestClient

from app import app

client = TestClient(app)


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


class TestHealth:
    def test_returns_200(self):
        r = client.get("/health")
        assert r.status_code == 200

    def test_status_ok(self):
        r = client.get("/health")
        assert r.json() == {"status": "ok"}
