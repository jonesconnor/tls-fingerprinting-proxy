"""
Tests for proxy.py — HTTP response framing in _forward_to_backend.

Each test spins up a minimal asyncio TCP server on localhost that sends a
crafted response, then calls _forward_to_backend and asserts on the result.
No real backends, no Docker, no network calls.

Test matrix:
  Happy paths:
    - Content-Length response             (most common — Flask, FastAPI JSON)
    - Content-Length: 0                   (204 No Content — empty body edge case)
    - Chunked transfer-encoding           (streaming responses)
    - EOF fallback                        (HTTP/1.0 style, no framing header)

  Regression tests (IRON RULE):
    - Keep-alive server does not block    (the 5-second uvicorn delay bug)
    - Connect failure returns 502         (error handling survives the rewrite)

  Error paths:
    - Malformed chunked encoding          (falls back to EOF read)
"""

import asyncio
import socket

import pytest

from proxy import _forward_to_backend

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _run_mock_server(response: bytes, *, keep_alive: bool = False) -> tuple[str, int]:
    """
    Start a one-shot TCP server on a random loopback port that:
      - accepts one connection
      - sends `response`
      - closes the connection (unless keep_alive=True, in which case it lingers)

    Returns (host, port).
    """
    host = "127.0.0.1"

    async def _handle(reader, writer):
        await reader.read(65536)  # consume the request
        writer.write(response)
        await writer.drain()
        if keep_alive:
            # Linger for a long time — the proxy must NOT block waiting for us
            await asyncio.sleep(10)
        writer.close()

    server = await asyncio.start_server(_handle, host, 0)
    port = server.sockets[0].getsockname()[1]
    asyncio.get_event_loop().create_task(server.serve_forever())
    return host, port


def _http_response(status: str, headers: dict, body: bytes) -> bytes:
    """Build a minimal HTTP/1.1 response."""
    header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
    return (
        f"HTTP/1.1 {status}\r\n{header_lines}\r\n\r\n".encode()
        + body
    )


def _chunked_encode(body: bytes) -> bytes:
    """Encode `body` as a single chunk + terminal."""
    size = f"{len(body):x}".encode()
    return size + b"\r\n" + body + b"\r\n" + b"0\r\n\r\n"


# ---------------------------------------------------------------------------
# TestForwardToBackend
# ---------------------------------------------------------------------------

class TestForwardToBackend:

    @pytest.fixture
    def loop(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        yield loop
        # Cancel any lingering mock-server tasks before closing
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()

    # ── Happy paths ──────────────────────────────────────────────────────────

    def test_reads_response_by_content_length(self, loop):
        body = b'{"status": "ok"}'
        raw = _http_response("200 OK", {"Content-Length": str(len(body))}, body)

        async def run():
            host, port = await _run_mock_server(raw)
            await asyncio.sleep(0)  # let server start
            return await _forward_to_backend(b"GET / HTTP/1.1\r\n\r\n", loop, host, port)

        result = loop.run_until_complete(run())
        assert b'{"status": "ok"}' in result
        assert result.startswith(b"HTTP/1.1 200 OK")

    def test_content_length_zero_returns_headers_only(self, loop):
        """204 No Content — Content-Length: 0 with no body bytes."""
        raw = _http_response("204 No Content", {"Content-Length": "0"}, b"")

        async def run():
            host, port = await _run_mock_server(raw)
            await asyncio.sleep(0)
            return await _forward_to_backend(b"DELETE / HTTP/1.1\r\n\r\n", loop, host, port)

        result = loop.run_until_complete(run())
        assert result.startswith(b"HTTP/1.1 204 No Content")
        # Body portion must be empty
        header_end = result.find(b"\r\n\r\n")
        assert result[header_end + 4:] == b""

    def test_reads_chunked_response(self, loop):
        body = b"hello from chunked backend"
        chunked_body = _chunked_encode(body)
        raw = _http_response("200 OK", {"Transfer-Encoding": "chunked"}, b"") \
            .rstrip(b"\r\n\r\n") + b"\r\n\r\n" + chunked_body
        # Build correctly: headers + chunked body (no Content-Length)
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            + chunked_body
        )

        async def run():
            host, port = await _run_mock_server(raw)
            await asyncio.sleep(0)
            return await _forward_to_backend(b"GET / HTTP/1.1\r\n\r\n", loop, host, port)

        result = loop.run_until_complete(run())
        assert b"hello from chunked backend" in result

    def test_falls_back_to_connection_close(self, loop):
        """HTTP/1.0-style response with no framing header — server closes to signal end."""
        body = b"<html>plain response</html>"
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n\r\n"
            + body
        )

        async def run():
            host, port = await _run_mock_server(raw)
            await asyncio.sleep(0)
            return await _forward_to_backend(b"GET / HTTP/1.1\r\n\r\n", loop, host, port)

        result = loop.run_until_complete(run())
        assert b"<html>plain response</html>" in result

    # ── Regression tests (IRON RULE) ─────────────────────────────────────────

    def test_does_not_block_on_keep_alive_server(self, loop):
        """
        The original bug: proxy blocked for 5 seconds waiting for uvicorn to close.

        A keep-alive server sends a Content-Length response and then KEEPS the
        connection open. The proxy must return as soon as it has read N bytes —
        NOT wait for the connection to close.
        """
        import time

        body = b'{"note": "I know you\'re an agent."}'
        raw = _http_response("200 OK", {"Content-Length": str(len(body))}, body)

        async def run():
            host, port = await _run_mock_server(raw, keep_alive=True)
            await asyncio.sleep(0)
            start = time.monotonic()
            result = await _forward_to_backend(b"GET / HTTP/1.1\r\n\r\n", loop, host, port)
            elapsed = time.monotonic() - start
            return result, elapsed

        result, elapsed = loop.run_until_complete(run())
        assert b"I know you" in result
        assert elapsed < 1.0, f"proxy blocked for {elapsed:.2f}s — keep-alive regression"

    def test_backend_connect_failure_returns_502(self, loop):
        """Error handling must survive the rewrite — connect to a port nothing listens on."""
        # Find a free port, then don't bind to it
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            dead_port = s.getsockname()[1]
        # Port is now closed

        async def run():
            return await _forward_to_backend(
                b"GET / HTTP/1.1\r\n\r\n", loop, "127.0.0.1", dead_port
            )

        result = loop.run_until_complete(run())
        assert b"502" in result
        assert b"Bad Gateway" in result

    # ── Error paths ───────────────────────────────────────────────────────────

    def test_malformed_chunked_falls_back_to_eof(self, loop):
        """
        Malformed chunk-size line → fall back to reading until connection close.
        The response body is still returned (whatever the server sent).
        """
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"NOTAHEX\r\n"          # invalid chunk size
            b"some data\r\n"
        )

        async def run():
            host, port = await _run_mock_server(raw)
            await asyncio.sleep(0)
            return await _forward_to_backend(b"GET / HTTP/1.1\r\n\r\n", loop, host, port)

        result = loop.run_until_complete(run())
        # Must not raise; must return something
        assert isinstance(result, bytes)
        assert len(result) > 0
