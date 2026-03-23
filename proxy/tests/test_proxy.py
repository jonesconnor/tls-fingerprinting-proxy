"""
Tests for proxy.py — backend selection logic.

These tests cover _select_backend() in isolation using the module-level
HUMAN_BACKEND_* and AGENT_BACKEND_* constants. They do not start a server
or open sockets.
"""

from unittest.mock import patch

import pytest

from classifier import Classification
from proxy import (
    AGENT_BACKEND_HOST,
    AGENT_BACKEND_PORT,
    HUMAN_BACKEND_HOST,
    HUMAN_BACKEND_PORT,
    _select_backend,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clf(client_type: str) -> Classification:
    return Classification(
        client_type=client_type,
        confidence="high",
        detail="test",
        signals=[],
    )


# ---------------------------------------------------------------------------
# TestSelectBackend
# ---------------------------------------------------------------------------

class TestSelectBackend:
    def test_agent_routes_to_agent_backend(self):
        host, port = _select_backend(_clf("agent"))
        assert host == AGENT_BACKEND_HOST
        assert port == AGENT_BACKEND_PORT

    def test_tool_routes_to_agent_backend(self):
        host, port = _select_backend(_clf("tool"))
        assert host == AGENT_BACKEND_HOST
        assert port == AGENT_BACKEND_PORT

    def test_headless_routes_to_agent_backend(self):
        host, port = _select_backend(_clf("headless"))
        assert host == AGENT_BACKEND_HOST
        assert port == AGENT_BACKEND_PORT

    def test_browser_routes_to_human_backend(self):
        host, port = _select_backend(_clf("browser"))
        assert host == HUMAN_BACKEND_HOST
        assert port == HUMAN_BACKEND_PORT

    def test_unknown_routes_to_human_backend(self):
        host, port = _select_backend(_clf("unknown"))
        assert host == HUMAN_BACKEND_HOST
        assert port == HUMAN_BACKEND_PORT

    def test_env_override_agent_backend(self):
        clf = _clf("agent")
        with (
            patch("proxy.AGENT_BACKEND_HOST", "custom-agent"),
            patch("proxy.AGENT_BACKEND_PORT", 9999),
        ):
            host, port = _select_backend(clf)
        assert host == "custom-agent"
        assert port == 9999

    def test_env_override_human_backend(self):
        clf = _clf("browser")
        with (
            patch("proxy.HUMAN_BACKEND_HOST", "custom-human"),
            patch("proxy.HUMAN_BACKEND_PORT", 7777),
        ):
            host, port = _select_backend(clf)
        assert host == "custom-human"
        assert port == 7777
