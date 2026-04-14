"""
proxy.py — Peek-forward TLS fingerprinting proxy.

Architecture
------------
Client ──TCP──► [Proxy]
                  │ 1. MSG_PEEK: read ClientHello bytes without consuming them
                  │ 2. Parse ClientHello, compute JA4, classify client
                  │ 3. ssl.wrap_socket() — TLS handshake (bytes still in kernel buffer)
                  │ 4. Read decrypted HTTP request
                  │ 5. Inject X-Client-* classification headers
                  └──HTTP──► Backend (plain HTTP on internal Docker network)

The "peek" is the key insight: socket.MSG_PEEK reads from the kernel receive
buffer without consuming it. The subsequent ssl.wrap_socket() call reads the
same bytes as part of the normal TLS handshake. No bytes are lost.

Why MITM and not passthrough?
TLS is opaque: once encrypted, we cannot inject plaintext headers into the stream.
To add HTTP headers we must terminate TLS ourselves, modify the HTTP layer, and
open a new connection to the backend. This is exactly what every TLS-terminating
proxy (nginx, HAProxy, Envoy, Cloudflare) does.
"""

import asyncio
import concurrent.futures
import logging
import os
import socket
import ssl

from classifier import classify
from ja4 import compute_ja4, compute_ja4_raw
from logger import FingerprintLogger
from lookup import Ja4Database
from tls_parser import parse_client_hello  # scapy-backed

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("proxy")

# ---------------------------------------------------------------------------
# Configuration (override via environment variables)
# ---------------------------------------------------------------------------
LISTEN_HOST         = os.getenv("LISTEN_HOST",         "0.0.0.0")
LISTEN_PORT         = int(os.getenv("PROXY_PORT",      "8443"))
HUMAN_BACKEND_HOST  = os.getenv("HUMAN_BACKEND_HOST",  "backend")
HUMAN_BACKEND_PORT  = int(os.getenv("HUMAN_BACKEND_PORT", "8080"))
AGENT_BACKEND_HOST  = os.getenv("AGENT_BACKEND_HOST",  "agent")
AGENT_BACKEND_PORT  = int(os.getenv("AGENT_BACKEND_PORT", "8001"))
CERT_FILE           = os.getenv("CERT_FILE",           "/certs/proxy.crt")
KEY_FILE            = os.getenv("KEY_FILE",            "/certs/proxy.key")

# Bytes to peek. A ClientHello is almost always < 2 KB; 16 KB is more than safe.
PEEK_SIZE = 16_384

# client_type values that route to the agent backend
_AGENT_TYPES = {"agent", "tool", "headless"}


def _select_backend(clf) -> tuple[str, int]:
    """Return (host, port) for the backend that should handle this client."""
    if clf.client_type in _AGENT_TYPES:
        return (AGENT_BACKEND_HOST, AGENT_BACKEND_PORT)
    return (HUMAN_BACKEND_HOST, HUMAN_BACKEND_PORT)


# ---------------------------------------------------------------------------
# TLS context for termination
# ---------------------------------------------------------------------------

def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    # Accept broad cipher support — we're classifying clients, not enforcing policy
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _inject_headers(raw_request: bytes, ja4: str, clf) -> bytes:
    """
    Inject X-Client-* headers into an HTTP/1.x request.

    HTTP headers end at the first \\r\\n\\r\\n sequence. We append our headers
    immediately before that separator:

        GET / HTTP/1.1\\r\\n
        Host: example.com\\r\\n
        User-Agent: curl/8.0\\r\\n
        X-Client-JA4: t13d...\\r\\n      ← injected
        X-Client-Type: tool\\r\\n         ← injected
        ...\\r\\n                          ← injected
        \\r\\n
        [body]
    """
    sep = b"\r\n\r\n"
    idx = raw_request.find(sep)

    injected = (
        f"\r\nX-Client-JA4: {ja4}"
        f"\r\nX-Client-Type: {clf.client_type}"
        f"\r\nX-Client-Detail: {clf.detail}"
        f"\r\nX-Client-Confidence: {clf.confidence}"
        f"\r\nX-Client-Signals: {','.join(clf.signals)}"
        f"\r\nX-Client-Match-Type: {clf.match_type}"
    ).encode()

    if idx == -1:
        # Malformed request with no header terminator — append and hope
        return raw_request + injected + b"\r\n\r\n"

    return raw_request[:idx] + injected + raw_request[idx:]


async def _read_http_request(ssl_sock: ssl.SSLSocket, loop: asyncio.AbstractEventLoop) -> bytes:
    """
    Read a complete HTTP/1.x request from an SSL socket.
    Handles both GET (no body) and POST (with Content-Length body).
    """
    buf = bytearray()
    header_end = -1

    # Read until we have the full header block
    while header_end == -1:
        chunk = await loop.run_in_executor(None, lambda: ssl_sock.recv(8192))
        if not chunk:
            break
        buf.extend(chunk)
        header_end = buf.find(b"\r\n\r\n")

    if header_end == -1:
        return bytes(buf)

    headers_raw = bytes(buf[:header_end])
    body_so_far = bytearray(buf[header_end + 4:])

    # Parse Content-Length to know if there's a body to read
    content_length = 0
    for line in headers_raw.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                content_length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                pass

    # Read remaining body bytes
    while len(body_so_far) < content_length:
        needed = content_length - len(body_so_far)
        chunk = await loop.run_in_executor(
            None, lambda: ssl_sock.recv(min(needed, 65536))
        )
        if not chunk:
            break
        body_so_far.extend(chunk)

    return headers_raw + b"\r\n\r\n" + bytes(body_so_far)


async def _read_chunked_body(
    initial: bytearray,
    sock: socket.socket,
    loop: asyncio.AbstractEventLoop,
) -> bytes:
    """
    Decode a chunked transfer-encoded body from a plain (non-SSL) socket.

    Chunk wire format:
        <hex_size>[; extension]\r\n
        <data>\r\n
        ...
        0\r\n
        \r\n

    Reads more bytes from sock as needed. Raises ValueError on parse error
    (caller should fall back to reading until EOF).
    """
    buf = bytearray(initial)
    decoded = bytearray()

    while True:
        # Find the chunk-size line
        crlf = buf.find(b"\r\n")
        while crlf == -1:
            more = await loop.sock_recv(sock, 65536)
            if not more:
                raise ValueError("connection closed before chunk-size line")
            buf.extend(more)
            crlf = buf.find(b"\r\n")

        size_line = buf[:crlf].split(b";")[0].strip()
        chunk_size = int(size_line, 16)
        buf = buf[crlf + 2:]  # consume size line + CRLF

        if chunk_size == 0:
            break  # terminal chunk

        # Ensure we have chunk_size data bytes + the trailing CRLF
        while len(buf) < chunk_size + 2:
            more = await loop.sock_recv(sock, 65536)
            if not more:
                raise ValueError("connection closed during chunk data")
            buf.extend(more)

        decoded.extend(buf[:chunk_size])
        buf = buf[chunk_size + 2:]  # consume data + trailing CRLF

    return bytes(decoded)


async def _forward_to_backend(
    request: bytes,
    loop: asyncio.AbstractEventLoop,
    host: str,
    port: int,
) -> bytes:
    """
    Open a plain TCP connection to the backend, forward the HTTP request,
    and return the full response.

    Response framing (RFC 7230 §3.3), checked in order:
      1. Content-Length  — read exactly N bytes, then stop.
      2. Transfer-Encoding: chunked — decode chunk stream until terminal 0-chunk.
         Malformed chunk encoding falls back to reading until connection close.
      3. Neither — read until the server closes the connection (HTTP/1.0 style).

    Known limitations (out of scope for the demo):
      - HEAD responses: Content-Length present but no body; would block.
        Neither backend handles HEAD, so this is not a blocker.
      - HTTP 1xx interim responses: not handled.
      - Full response is buffered in memory before forwarding.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        await loop.sock_connect(sock, (host, port))
        await loop.sock_sendall(sock, request)

        # ── Read response headers ────────────────────────────────────────────
        buf = bytearray()
        header_end = -1
        while header_end == -1:
            chunk = await loop.sock_recv(sock, 65536)
            if not chunk:
                break
            buf.extend(chunk)
            header_end = buf.find(b"\r\n\r\n")

        if header_end == -1:
            # Connection closed before headers were complete
            sock.close()
            return bytes(buf)

        headers_raw = bytes(buf[:header_end])
        body = bytearray(buf[header_end + 4:])

        # ── Parse framing headers ────────────────────────────────────────────
        content_length = -1
        transfer_chunked = False
        for line in headers_raw.split(b"\r\n")[1:]:
            lower = line.lower()
            if lower.startswith(b"content-length:"):
                try:
                    content_length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    pass
            elif lower.startswith(b"transfer-encoding:") and b"chunked" in lower:
                transfer_chunked = True

        # ── Read body ────────────────────────────────────────────────────────
        if content_length >= 0:
            # Content-Length: read exactly N bytes (0 is valid — 204 No Content)
            while len(body) < content_length:
                needed = content_length - len(body)
                chunk = await loop.sock_recv(sock, min(needed, 65536))
                if not chunk:
                    break
                body.extend(chunk)

        elif transfer_chunked:
            # Chunked: decode stream; fall back to EOF on parse error
            try:
                body = bytearray(await _read_chunked_body(body, sock, loop))
            except Exception as exc:
                log.warning(f"chunked decode failed ({exc}), falling back to EOF read")
                while True:
                    chunk = await loop.sock_recv(sock, 65536)
                    if not chunk:
                        break
                    body.extend(chunk)

        else:
            # Neither: read until server closes connection (HTTP/1.0 style)
            while True:
                chunk = await loop.sock_recv(sock, 65536)
                if not chunk:
                    break
                body.extend(chunk)

        sock.close()
        return headers_raw + b"\r\n\r\n" + bytes(body)

    except Exception as exc:
        log.error(f"Backend error: {exc}")
        body = b"502 Bad Gateway - backend unreachable"
        return (
            b"HTTP/1.1 502 Bad Gateway\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

async def handle_connection(
    client_sock: socket.socket,
    addr: tuple,
    ssl_ctx: ssl.SSLContext,
    loop: asyncio.AbstractEventLoop,
    db: Ja4Database,
    fp_log: FingerprintLogger,
) -> None:
    client_ip = addr[0]

    try:
        # loop.sock_accept() returns a non-blocking socket. All of our I/O on
        # this socket (MSG_PEEK, wrap_socket, recv) runs in run_in_executor
        # threads, which require blocking mode. Set it once here, up front.
        client_sock.setblocking(True)

        # ── 1. MSG_PEEK: read ClientHello without consuming ─────────────────
        #
        # socket.MSG_PEEK reads from the kernel buffer without advancing the
        # read pointer. The bytes remain available for ssl.wrap_socket() to
        # consume as part of the TLS handshake. This is the core mechanism
        # that makes the "peek" in "peek-forward proxy" possible.
        #
        peek_data = await loop.run_in_executor(
            None, lambda: client_sock.recv(PEEK_SIZE, socket.MSG_PEEK)
        )

        if not peek_data:
            log.debug(f"{client_ip}: empty peek, dropping")
            return

        # ── 2. Parse + fingerprint ──────────────────────────────────────────
        ch = parse_client_hello(peek_data)
        ja4 = "parse_error" if ch.parse_error else compute_ja4(ch)
        raw = {} if ch.parse_error else compute_ja4_raw(ch)
        clf = db.lookup(ja4) or db.lookup_nearest(ja4) or classify(ja4, ch)

        if clf.client_type == "unknown":
            log.warning(f"{client_ip}: unknown fingerprint {ja4} — not in ja4db or catalogue")

        log.info(
            f"{client_ip:>15} | {ja4} | {clf.client_type:8} ({clf.confidence}) | {clf.detail}"
        )

        if not ch.parse_error:
            fp_log.record(
                client_ip=client_ip,
                ja4=ja4,
                ja4_raw=raw,
                clf=clf,
                ch=ch,
            )

        # ── 3. TLS termination ──────────────────────────────────────────────
        #
        # The peeked bytes are still in the kernel receive buffer.
        # wrap_socket() initiates the TLS handshake, which reads the
        # ClientHello normally. From TLS's perspective, nothing unusual happened.
        #
        # A timeout is set so that scanner/prober connections that hang
        # mid-handshake release their executor thread instead of occupying
        # it indefinitely.
        #
        client_sock.settimeout(10)
        try:
            ssl_sock: ssl.SSLSocket = await loop.run_in_executor(
                None, lambda: ssl_ctx.wrap_socket(client_sock, server_side=True)
            )
        except ssl.SSLError as exc:
            # UNEXPECTED_EOF_WHILE_READING is almost always a scanner/prober that
            # sends a ClientHello and immediately closes the connection — not worth logging.
            if "UNEXPECTED_EOF_WHILE_READING" not in str(exc):
                log.warning(f"{client_ip}: TLS handshake failed: {exc}")
            return

        # ── 4. Read decrypted HTTP request ──────────────────────────────────
        request_bytes = await _read_http_request(ssl_sock, loop)
        if not request_bytes:
            return

        # ── 5. Inject classification headers ────────────────────────────────
        modified = _inject_headers(request_bytes, ja4, clf)

        # ── 6. Select backend and forward ────────────────────────────────────
        backend_host, backend_port = _select_backend(clf)
        response = await _forward_to_backend(modified, loop, backend_host, backend_port)

        # ── 7. Return response to client ─────────────────────────────────────
        await loop.run_in_executor(None, lambda: ssl_sock.sendall(response))

    except Exception as exc:
        log.error(f"{client_ip}: unhandled error: {exc}", exc_info=True)
    finally:
        try:
            client_sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    ssl_ctx = _build_ssl_context()
    loop = asyncio.get_running_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=64))

    db = Ja4Database()
    await db.load()

    fp_log = FingerprintLogger()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((LISTEN_HOST, LISTEN_PORT))
    server_sock.listen(256)
    server_sock.setblocking(False)

    log.info(f"Fingerprinting proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
    log.info(f"Human backend:  {HUMAN_BACKEND_HOST}:{HUMAN_BACKEND_PORT}")
    log.info(f"Agent backend:  {AGENT_BACKEND_HOST}:{AGENT_BACKEND_PORT}")
    log.info(f"TLS cert: {CERT_FILE}")

    while True:
        client_sock, addr = await loop.sock_accept(server_sock)
        asyncio.create_task(handle_connection(client_sock, addr, ssl_ctx, loop, db, fp_log))


if __name__ == "__main__":
    asyncio.run(main())
