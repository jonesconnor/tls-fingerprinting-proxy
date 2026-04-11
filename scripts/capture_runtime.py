"""
capture_runtime.py — Multi-language runtime TLS fingerprint capture harness.

Captures TLS fingerprints for language runtimes beyond Python: curl, Node.js
(built-in https, built-in fetch, axios), Go net/http, Rust reqwest, and
Chrome headless via Playwright. Each runtime uses a different TLS stack, which
produces a distinct ClientHello and therefore a distinct JA4 fingerprint.

The proxy must be running before capture. Start it with: make up

Usage
-----
  python3 scripts/capture_runtime.py --runtime curl
  python3 scripts/capture_runtime.py --runtime go-net-http
  python3 scripts/capture_runtime.py --runtime node-axios
  python3 scripts/capture_runtime.py --runtime rust-reqwest
  python3 scripts/capture_runtime.py --runtime curl --linux

Makefile integration
--------------------
  make capture-runtime RUNTIME=curl
  make capture-runtime-linux RUNTIME=node-https
  make capture-all-runtimes               # all runtimes, serialised, then merge
  make capture-all-runtimes-linux         # platform-variant runtimes on Linux
  make merge-catalogue                    # shared with capture_sdk.py

Harness flow
------------
  1. Look up runtime in RUNTIME_CONFIGS (error + list valid names if unknown)
  2. Set up runtime environment (temp dir, npm install, cargo build, etc.)
  3. For Rust: cargo build BEFORE recording T to avoid blowing the NDJSON timeout
  4. Record T = datetime.now(utc) immediately before the request fires
  5. Run the request → HTTPS to localhost:8443
  6. Poll fingerprints.ndjson for entry where ts >= T
  7. Extract runtime metadata (version, TLS library, http_client version)
  8. Construct and validate entry against catalogue/schema.json
  9. Write entry to .capture-tmp/{runtime}-{platform}.json
  10. Print summary line

Linux variant (--linux flag)
-----------------------------
Only meaningful for runtimes whose TLS fingerprint varies by platform:
  - curl    — LibreSSL on macOS vs OpenSSL on Linux (different JA4)
  - node-*  — OpenSSL version bundled with Node differs across platforms

Platform-independent runtimes emit a warning and run natively:
  - go-net-http      — Go uses its own crypto/tls (not OpenSSL); same on all platforms
  - rust-reqwest     — reqwest uses rustls (pure-Rust TLS); same on all platforms
  - chrome-playwright — Chromium uses BoringSSL; same on all platforms

Why some runtimes are interesting
----------------------------------
  - curl:             The canonical "tool" baseline. LibreSSL vs OpenSSL is one of
                      the clearest platform-split signals in the entire dataset.
  - node-https:       Node.js wraps OpenSSL directly via its TLS module. Different
                      cipher suite ordering from Python/urllib despite both using OpenSSL.
  - node-fetch:       Uses Undici, Node's WHATWG fetch implementation. Routes through
                      the same TLS module as node-https but with potentially different
                      extension ordering — a novel comparison point.
  - node-axios:       A popular third-party HTTP library for Node.js. If it produces
                      the same JA4 as node-https, that confirms Node's TLS stack is the
                      determining factor, not the HTTP library.
  - go-net-http:      Go's crypto/tls is a pure-Go TLS implementation — not OpenSSL,
                      not BoringSSL. Produces a very distinctive fingerprint: minimal
                      cipher suite list, structured extension set, no GREASE.
  - rust-reqwest:     reqwest with rustls is also pure-Rust. Will differ from Go in
                      cipher suite choices and extension ordering. An important data
                      point as Rust-based agents become more common.
  - chrome-playwright: BoringSSL — the same TLS stack as real Chrome. The "gold
                       standard" for browser impersonation. If an agent matches this
                       JA4, it's either a real browser or deliberately spoofing.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT     = Path(__file__).resolve().parent.parent
CATALOGUE_DIR    = PROJECT_ROOT / "catalogue"
CAPTURE_TMP_DIR  = PROJECT_ROOT / ".capture-tmp"
SCHEMA_PATH      = CATALOGUE_DIR / "schema.json"
PLAYWRIGHT_ENV   = PROJECT_ROOT / ".playwright-env"

# Proxy endpoint — /health responds quickly regardless of backend routing.
# Override port with CAPTURE_PROXY_PORT env var (e.g. prod uses 443, not 8443).
_capture_port    = os.getenv("CAPTURE_PROXY_PORT", "8443")
PROXY_URL        = f"https://localhost:{_capture_port}"
# Reachable from inside a Docker container on the same host (macOS + Linux).
LINUX_PROXY_URL  = f"https://host.docker.internal:{_capture_port}"

# ── Source code templates ────────────────────────────────────────────────────
#
# These are embedded at the call site by replacing the {url} placeholder with
# the actual proxy URL. We use str.replace() rather than str.format() to avoid
# escaping Go/Rust curly braces.

_GO_SOURCE = """\
package main

import (
\t"crypto/tls"
\t"net/http"
)

func main() {
\ttr := &http.Transport{
\t\tTLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec -- test harness
\t}
\tclient := &http.Client{Transport: tr}
\tclient.Get("{url}") //nolint:errcheck,noctx -- one-shot probe
}
"""

_RUST_CARGO_TOML = """\
[package]
name = "tls-capture"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "tls-capture"
path = "src/main.rs"

[dependencies]
reqwest = { version = "0.12", features = ["blocking"] }
"""

_RUST_MAIN = """\
fn main() {
    let _ = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get("{url}")
        .send();
}
"""

# ── RUNTIME_CONFIGS dispatch table ───────────────────────────────────────────
#
# Each entry defines:
#   runner            internal runner type — drives setup/execution dispatch
#   runtime           catalogue field: language runtime label
#   http_client       catalogue field: HTTP client label
#   description       human-readable summary shown in --list output
#   linux_supported   if False, --linux emits a warning and runs natively
#   docker_image      Docker image used for Linux captures (None if unsupported)
#
# Node entries additionally carry:
#   npm_package       npm package to install (None for built-in modules)
#   script            JS one-liner; {url} is replaced before execution
#
# Note on node-fetch vs node-https: both use OpenSSL under the hood, but
# node-fetch routes through Undici which constructs the ClientHello via a
# slightly different code path. Capturing both tests whether the JA4 is
# determined by the TLS library alone or also by how the library is invoked.

RUNTIME_CONFIGS: dict[str, dict] = {
    "curl": {
        "runner":          "curl",
        "runtime":         "curl",
        "http_client":     "curl",
        "client_type":     "tool",
        "description":     "curl command-line tool (libcurl)",
        "linux_supported": True,
        "docker_image":    "curlimages/curl",
    },
    "node-https": {
        "runner":          "node",
        "runtime":         "node",
        "http_client":     "https",
        "client_type":     "tool",
        "description":     "Node.js built-in https module",
        "npm_package":     None,
        "linux_supported": True,
        "docker_image":    "node:20-slim",
        # Uses the classic https.get() code path — Node's direct TLS wrapper.
        "script": (
            "const https = require('https');"
            "const req = https.get('{url}', {rejectUnauthorized: false}, (res) => {"
            "  res.resume();"
            "  res.on('end', () => process.exit(0));"
            "});"
            "req.on('error', () => process.exit(0));"
            "req.setTimeout(5000, () => { req.destroy(); process.exit(0); });"
        ),
    },
    "node-fetch": {
        "runner":          "node",
        "runtime":         "node",
        "http_client":     "fetch",
        "client_type":     "tool",
        "description":     "Node.js 18+ built-in fetch (Undici)",
        "npm_package":     None,
        "linux_supported": True,
        "docker_image":    "node:20-slim",
        # Built-in fetch doesn't accept an httpsAgent — disable TLS verification
        # via the environment variable instead.
        "script": (
            "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"
            "(async () => {"
            "  try { await (await fetch('{url}')).text(); } catch (e) {}"
            "  process.exit(0);"
            "})();"
        ),
    },
    "node-axios": {
        "runner":          "node",
        "runtime":         "node",
        "http_client":     "axios",
        "client_type":     "tool",
        "description":     "Node.js with the axios HTTP client library",
        "npm_package":     "axios",
        "linux_supported": True,
        "docker_image":    "node:20-slim",
        "script": (
            "const axios = require('axios');"
            "const https = require('https');"
            "(async () => {"
            "  try {"
            "    await axios.get('{url}', {"
            "      httpsAgent: new https.Agent({ rejectUnauthorized: false })"
            "    });"
            "  } catch (e) {}"
            "  process.exit(0);"
            "})();"
        ),
    },
    "go-net-http": {
        "runner":          "go",
        "runtime":         "go",
        "http_client":     "net/http",
        "client_type":     "tool",
        "description":     "Go standard library net/http (pure Go crypto/tls — platform-independent)",
        "linux_supported": False,
        "docker_image":    None,
    },
    "rust-reqwest": {
        "runner":          "rust",
        "runtime":         "rust",
        "http_client":     "reqwest",
        "client_type":     "tool",
        "description":     "Rust reqwest crate with rustls backend (platform-independent)",
        "linux_supported": False,
        "docker_image":    None,
    },
    "chrome-playwright": {
        "runner":          "browser",
        "runtime":         "chromium",
        "http_client":     "chromium",
        "client_type":     "headless",
        "description":     "Chrome headless via Playwright (BoringSSL — matches real Chrome)",
        "linux_supported": False,
        "docker_image":    None,
    },
}

# Why Go and Rust are platform-independent:
#   Go uses its own crypto/tls package — a pure-Go TLS implementation that
#   does not call OpenSSL or any system TLS library. The ClientHello is
#   identical on macOS, Linux, and Windows.
#
#   Rust's reqwest defaults to rustls, a pure-Rust TLS implementation.
#   Same reasoning applies. If you build reqwest with `native-tls` features
#   (which links against OpenSSL or SecureTransport), platform variance
#   would reappear — that's a separate capture target worth adding later.

_PLATFORM_INDEPENDENT_NOTE = {
    "go":      "Go uses its own crypto/tls — same JA4 on all platforms",
    "rust":    "reqwest uses rustls (pure Rust) — same JA4 on all platforms",
    "chromium": "Chromium uses BoringSSL — same JA4 on all platforms",
}

# ── OS label ────────────────────────────────────────────────────────────────

def _os_label() -> str:
    """Human-readable OS string for the catalogue entry."""
    sys_name = platform.system()
    if sys_name == "Darwin":
        mac_ver = platform.mac_ver()[0]
        return f"macOS {mac_ver}".strip() if mac_ver else "macOS"
    if sys_name == "Linux":
        return "Linux"
    return sys_name

# ── NDJSON helpers ──────────────────────────────────────────────────────────
# These mirror the helpers in capture_sdk.py. They are duplicated here so
# that capture_runtime.py is self-contained and can be used independently.

def _read_ndjson_from_proxy() -> str:
    """Read fingerprint log from the running proxy container via docker compose exec."""
    result = subprocess.run(
        ["docker", "compose", "exec", "proxy",
         "cat", "/data/fingerprints/fingerprints.ndjson"],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Could not read NDJSON from proxy container.\n"
            "Is the stack running? Try: make up\n"
            f"stderr: {result.stderr.strip()}"
        )
    return result.stdout


def filter_ndjson_after(ndjson_content: str, t: datetime) -> dict | None:
    """
    Return the first NDJSON entry whose 'ts' field is >= t, or None.

    The proxy logs each connection with a 'ts' field in UTC ISO-8601 format.
    We record T immediately before firing the request, so any entry with
    ts >= T was produced by that request (or a concurrent one if running
    parallel captures — see TODO-8 in TODOS.md).
    """
    t_utc = t.replace(tzinfo=timezone.utc) if t.tzinfo is None else t.astimezone(timezone.utc)
    for line in ndjson_content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts_str = entry.get("ts")
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts.astimezone(timezone.utc) >= t_utc:
                return entry
        except ValueError:
            continue
    return None


def wait_for_fingerprint(t: datetime, timeout: int = 10) -> dict:
    """
    Poll for an NDJSON entry with ts >= t. Exits with a clear message if
    nothing appears within `timeout` seconds (proxy not running scenario).
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            content = _read_ndjson_from_proxy()
        except RuntimeError as exc:
            sys.exit(f"Error: {exc}")
        entry = filter_ndjson_after(content, t)
        if entry:
            return entry
        time.sleep(0.5)
    sys.exit(
        f"No fingerprint captured within {timeout}s. "
        "Is the proxy running? Try: make up"
    )

# ── Schema validation ───────────────────────────────────────────────────────

def load_schema(path: Path = SCHEMA_PATH) -> dict:
    with open(path) as f:
        return json.load(f)


def validate_entry(entry: dict, schema: dict | None = None) -> None:
    """
    Validate entry against catalogue/schema.json.
    Raises jsonschema.ValidationError with a clear message on failure.
    """
    try:
        import jsonschema
    except ImportError:
        raise ImportError("jsonschema is required: pip install jsonschema")
    if schema is None:
        schema = load_schema()
    jsonschema.validate(entry, schema)

# ── Metadata helpers — curl ─────────────────────────────────────────────────

def _get_curl_metadata_native() -> tuple[str, str]:
    """
    Return (version, tls_library) by inspecting the host curl binary.

    curl --version output example:
      curl 8.4.0 (x86_64-apple-darwin23.0) libcurl/8.4.0 LibreSSL/3.3.6 ...
    """
    result = subprocess.run(["curl", "--version"], capture_output=True, text=True)
    return _parse_curl_version_output(result.stdout)


def _get_curl_metadata_linux(docker_image: str) -> tuple[str, str]:
    """Return (version, tls_library) from the Linux Docker image's curl."""
    result = subprocess.run(
        ["docker", "run", "--rm", docker_image, "curl", "--version"],
        capture_output=True,
        text=True,
    )
    return _parse_curl_version_output(result.stdout)


def _parse_curl_version_output(output: str) -> tuple[str, str]:
    """
    Parse curl --version output into (version, tls_library).

    Handles: OpenSSL/x.x.x, LibreSSL/x.x.x, NSS/x.x.x, GnuTLS/x.x.x,
    wolfSSL/x.x.x, mbedTLS/x.x.x, Schannel (Windows), SecureTransport.
    Returns ("unknown", "unknown") on unexpected format.
    """
    line = output.splitlines()[0] if output.strip() else ""
    parts = line.split()

    # curl <version> (platform) libcurl/<version> TLS_LIB/<version> ...
    curl_version = parts[1] if len(parts) > 1 else "unknown"

    tls_library = "unknown"
    tls_prefixes = (
        "LibreSSL/", "OpenSSL/", "NSS/", "GnuTLS/",
        "wolfSSL/", "mbedTLS/", "Schannel", "SecureTransport",
    )
    for part in parts:
        if any(part.startswith(p) for p in tls_prefixes):
            tls_library = part
            break

    return curl_version, tls_library

# ── Metadata helpers — Node.js ───────────────────────────────────────────────

def _get_node_metadata_native() -> tuple[str, str]:
    """Return (runtime_version, tls_library) from the host Node.js installation."""
    version_result = subprocess.run(["node", "--version"], capture_output=True, text=True)
    openssl_result = subprocess.run(
        ["node", "-e", "console.log(process.versions.openssl)"],
        capture_output=True,
        text=True,
    )
    return _parse_node_metadata(version_result.stdout, openssl_result.stdout)


def _get_node_metadata_linux(docker_image: str) -> tuple[str, str]:
    """Return (runtime_version, tls_library) from the Linux Docker image's Node.js."""
    result = subprocess.run(
        [
            "docker", "run", "--rm", docker_image, "node", "-e",
            "console.log(JSON.stringify({"
            "version: process.version, "
            "openssl: process.versions.openssl"
            "}))",
        ],
        capture_output=True,
        text=True,
    )
    try:
        meta = json.loads(result.stdout.strip())
        raw_version = meta.get("version", "unknown")
        openssl     = meta.get("openssl", "unknown")
        return _parse_node_metadata(raw_version, openssl)
    except (json.JSONDecodeError, KeyError):
        return "unknown", "unknown"


def _parse_node_metadata(version_str: str, openssl_str: str) -> tuple[str, str]:
    """
    Parse Node.js version and OpenSSL version strings.

    version_str may be "v20.11.0\n" or "v20.11.0" or "20.11.0".
    openssl_str may be "3.1.4+quic\n" or "3.1.4".
    """
    runtime_version = version_str.strip().lstrip("v")
    openssl_raw     = openssl_str.strip()
    # Strip suffixes like "+quic" that appear in some Node builds.
    openssl_clean   = openssl_raw.split("+")[0] if openssl_raw != "unknown" else "unknown"
    tls_library     = f"OpenSSL/{openssl_clean}" if openssl_clean and openssl_clean != "unknown" else "unknown"
    return runtime_version or "unknown", tls_library


def _get_npm_package_version(npm_dir: str, package: str) -> str:
    """
    Read the installed version of `package` from its package.json in node_modules.
    Falls back to "unknown" if the file is missing or malformed.
    """
    pkg_json = Path(npm_dir) / "node_modules" / package / "package.json"
    try:
        return json.loads(pkg_json.read_text()).get("version", "unknown")
    except (FileNotFoundError, json.JSONDecodeError):
        return "unknown"

# ── Metadata helpers — Go ───────────────────────────────────────────────────

def _get_go_metadata() -> tuple[str, str]:
    """
    Return (runtime_version, tls_library) for the host Go installation.

    `go version` output: "go version go1.22.0 darwin/arm64"
    tls_library is always "go crypto/tls <version>" — Go does not use OpenSSL.
    """
    result = subprocess.run(["go", "version"], capture_output=True, text=True)
    return _parse_go_version_output(result.stdout)


def _parse_go_version_output(output: str) -> tuple[str, str]:
    """
    Parse `go version` output into (runtime_version, tls_library).

    Returns ("unknown", "unknown") if the format is unrecognised.
    """
    # Expected: "go version go1.22.0 darwin/arm64"
    match = re.search(r"go(\d+\.\d+(?:\.\d+)?)", output)
    if not match:
        return "unknown", "unknown"
    version = match.group(1)
    return version, f"go crypto/tls {version}"

# ── Metadata helpers — Rust ─────────────────────────────────────────────────

def _get_rustc_version() -> str:
    """
    Return the rustc version string.
    `rustc --version` output: "rustc 1.75.0 (82e1608df 2023-12-21)"
    """
    result = subprocess.run(["rustc", "--version"], capture_output=True, text=True)
    return _parse_rustc_version_output(result.stdout)


def _parse_rustc_version_output(output: str) -> str:
    """Parse `rustc --version` output. Returns "unknown" on unexpected format."""
    # Expected: "rustc 1.75.0 (82e1608df 2023-12-21)"
    match = re.search(r"rustc\s+(\d+\.\d+\.\d+)", output)
    return match.group(1) if match else "unknown"


def _get_reqwest_version_from_lock(project_dir: str) -> str:
    """
    Extract the reqwest version from Cargo.lock in `project_dir`.

    Cargo.lock format (TOML-style, not full TOML parse needed):
      [[package]]
      name = "reqwest"
      version = "0.12.3"
    """
    lock_path = Path(project_dir) / "Cargo.lock"
    try:
        content = lock_path.read_text()
    except FileNotFoundError:
        return "unknown"

    in_reqwest_block = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            in_reqwest_block = False
        elif stripped == 'name = "reqwest"':
            in_reqwest_block = True
        elif in_reqwest_block and stripped.startswith("version ="):
            # version = "0.12.3"
            match = re.search(r'"([^"]+)"', stripped)
            return match.group(1) if match else "unknown"
    return "unknown"

# ── Metadata helpers — browser ───────────────────────────────────────────────

def _ensure_playwright_env() -> str:
    """
    Ensure Playwright + Chromium are installed in a persistent venv at
    .playwright-env/. Returns the path to the venv Python executable.

    The venv is created on first use. Chromium binaries (~200 MB) are
    downloaded once and reused across captures.
    """
    venv_python   = str(PLAYWRIGHT_ENV / "bin" / "python")
    pw_executable = PLAYWRIGHT_ENV / "bin" / "playwright"

    if not pw_executable.exists():
        print("  [browser] First-time setup: creating .playwright-env ...")
        subprocess.run(
            [sys.executable, "-m", "venv", str(PLAYWRIGHT_ENV)],
            check=True, capture_output=True,
        )
        print("  [browser] Installing playwright (~200 MB Chromium download) ...")
        subprocess.run(
            [venv_python, "-m", "pip", "install", "playwright", "--quiet"],
            check=True, capture_output=True,
        )
        subprocess.run(
            [str(pw_executable), "install", "chromium"],
            check=True,
        )
        print("  [browser] Setup complete.")

    return venv_python


def _run_browser_chromium(url: str, venv_python: str) -> str:
    """
    Launch Chromium headless via Playwright, navigate to `url`, return the
    Chromium version string. Ignores TLS certificate errors (self-signed proxy).
    """
    script = (
        "from playwright.sync_api import sync_playwright\n"
        "with sync_playwright() as p:\n"
        "    b = p.chromium.launch()\n"
        f"    page = b.new_page(ignore_https_errors=True)\n"
        f"    page.goto({url!r}, timeout=15000)\n"
        "    print(b.version)\n"
        "    b.close()\n"
    )
    result = subprocess.run(
        [venv_python, "-c", script],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() or "unknown"

# ── Runner — curl ───────────────────────────────────────────────────────────

def _capture_curl(config: dict, linux: bool, platform_label: str) -> dict:
    url = LINUX_PROXY_URL if linux else PROXY_URL

    if linux:
        t = datetime.now(tz=timezone.utc)
        subprocess.run(
            [
                "docker", "run", "--rm",
                "--add-host=host.docker.internal:host-gateway",
                config["docker_image"],
                "curl", "-sk", "--max-time", "10", url,
            ],
            capture_output=True,
        )
        version, tls_library = _get_curl_metadata_linux(config["docker_image"])
        os_label = "Linux"
    else:
        t = datetime.now(tz=timezone.utc)
        result = subprocess.run(["curl", "-sk", "--max-time", "10", url], capture_output=True)
        if result.returncode != 0:
            sys.exit(f"curl failed (exit {result.returncode}) — is the proxy running? Try: make up")
        version, tls_library = _get_curl_metadata_native()
        os_label = _os_label()

    fingerprint = wait_for_fingerprint(t)
    ja4          = fingerprint.get("ja4", "")
    alpn_present = bool(fingerprint.get("alpn") or [])

    return {
        "runtime":             config["runtime"],
        "runtime_version":     version,
        "http_client":         config["http_client"],
        "http_client_version": version,  # curl is both runtime and HTTP client
        "os":                  os_label,
        "tls_library":         tls_library,
        "ja4":                 ja4,
        "alpn_present":        alpn_present,
        "captured_at":         t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "client_type":         config["client_type"],
    }

# ── Runner — Node.js ─────────────────────────────────────────────────────────

def _capture_node(config: dict, linux: bool, platform_label: str) -> dict:
    npm_package = config.get("npm_package")
    script      = config["script"]
    url         = LINUX_PROXY_URL if linux else PROXY_URL
    js_code     = script.replace("{url}", url)

    if linux:
        t = datetime.now(tz=timezone.utc)
        _run_node_linux(config["docker_image"], npm_package, js_code)
        runtime_version, tls_library = _get_node_metadata_linux(config["docker_image"])
        http_client_version = _get_npm_package_version_linux(
            config["docker_image"], npm_package
        ) if npm_package else runtime_version
        os_label = "Linux"
    else:
        npm_dir: str | None = None
        try:
            if npm_package:
                npm_dir = tempfile.mkdtemp(prefix=f"cap_node_{npm_package}_")
                _npm_install(npm_dir, npm_package)
            t = datetime.now(tz=timezone.utc)
            _run_node_native(npm_dir, js_code)
            runtime_version, tls_library = _get_node_metadata_native()
            http_client_version = (
                _get_npm_package_version(npm_dir, npm_package)
                if npm_package else runtime_version
            )
            os_label = _os_label()
        finally:
            if npm_dir:
                shutil.rmtree(npm_dir, ignore_errors=True)

    fingerprint = wait_for_fingerprint(t)
    ja4          = fingerprint.get("ja4", "")
    alpn_present = bool(fingerprint.get("alpn") or [])

    return {
        "runtime":             config["runtime"],
        "runtime_version":     runtime_version,
        "http_client":         config["http_client"],
        "http_client_version": http_client_version,
        "os":                  os_label,
        "tls_library":         tls_library,
        "ja4":                 ja4,
        "alpn_present":        alpn_present,
        "captured_at":         t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "client_type":         config["client_type"],
    }


def _npm_install(npm_dir: str, package: str) -> None:
    """Install an npm package into npm_dir, creating a minimal package.json."""
    pkg_json = Path(npm_dir) / "package.json"
    pkg_json.write_text(json.dumps({"name": "tls-capture", "version": "0.0.1"}))
    subprocess.run(
        ["npm", "install", package, "--silent", "--no-fund", "--no-audit"],
        check=True,
        capture_output=True,
        cwd=npm_dir,
    )


def _run_node_native(npm_dir: str | None, js_code: str) -> None:
    """Run a JS one-liner with node. If npm_dir is set, use it as cwd."""
    subprocess.run(
        ["node", "-e", js_code],
        capture_output=True,
        cwd=npm_dir,
    )


def _run_node_linux(docker_image: str, npm_package: str | None, js_code: str) -> None:
    """Run a JS one-liner inside a Docker container."""
    if npm_package:
        cmd = (
            f"npm install {shlex.quote(npm_package)} --silent --no-fund --no-audit "
            f"&& node -e {json.dumps(js_code)}"
        )
    else:
        cmd = f"node -e {json.dumps(js_code)}"

    subprocess.run(
        [
            "docker", "run", "--rm",
            "--add-host=host.docker.internal:host-gateway",
            docker_image,
            "bash", "-c", cmd,
        ],
        capture_output=True,
    )


def _get_npm_package_version_linux(docker_image: str, package: str) -> str:
    """Get the latest available version of an npm package from within a Docker container."""
    result = subprocess.run(
        [
            "docker", "run", "--rm", docker_image,
            "node", "-e",
            f"const r = require('child_process').execSync("
            f"'npm show {shlex.quote(package)} version --silent 2>/dev/null').toString().trim();"
            f"console.log(r);",
        ],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() or "unknown"

# ── Runner — Go ──────────────────────────────────────────────────────────────

def _capture_go(config: dict, platform_label: str) -> dict:
    url = PROXY_URL  # Go crypto/tls is platform-independent; always run natively.
    tmp_dir: str | None = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="cap_go_")
        src_path = os.path.join(tmp_dir, "main.go")
        with open(src_path, "w") as f:
            f.write(_GO_SOURCE.replace("{url}", url))

        t = datetime.now(tz=timezone.utc)
        result = subprocess.run(["go", "run", src_path], capture_output=True)
        if result.returncode != 0:
            sys.exit(f"go run failed:\n{result.stderr.decode(errors='replace').strip()[-500:]}")
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    fingerprint = wait_for_fingerprint(t)
    ja4          = fingerprint.get("ja4", "")
    alpn_present = bool(fingerprint.get("alpn") or [])

    runtime_version, tls_library = _get_go_metadata()

    return {
        "runtime":             config["runtime"],
        "runtime_version":     runtime_version,
        "http_client":         config["http_client"],
        "http_client_version": runtime_version,  # net/http is stdlib; version == runtime
        "os":                  _os_label(),
        "tls_library":         tls_library,
        "ja4":                 ja4,
        "alpn_present":        alpn_present,
        "captured_at":         t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "client_type":         config["client_type"],
    }

# ── Runner — Rust ────────────────────────────────────────────────────────────

def _capture_rust(config: dict, platform_label: str) -> dict:
    url = PROXY_URL  # rustls is platform-independent; always run natively.
    tmp_dir: str | None = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="cap_rust_")
        _scaffold_rust_project(tmp_dir, url)

        # Pre-build: compilation happens here, before the timed capture window.
        # cargo run after a successful cargo build is nearly instant (~0.1s)
        # because Cargo detects no source changes.
        print("  building cargo project (may take ~60s on first run) ...")
        build_result = subprocess.run(
            ["cargo", "build", "--manifest-path", os.path.join(tmp_dir, "Cargo.toml")],
            capture_output=True,
            cwd=tmp_dir,
        )
        if build_result.returncode != 0:
            stderr = build_result.stderr.decode(errors="replace").strip()[-500:]
            sys.exit(f"cargo build failed:\n{stderr}")

        # Record T immediately before the network request fires.
        t = datetime.now(tz=timezone.utc)
        result = subprocess.run(
            ["cargo", "run", "--manifest-path", os.path.join(tmp_dir, "Cargo.toml")],
            capture_output=True, cwd=tmp_dir,
        )
        if result.returncode != 0:
            sys.exit(f"cargo run failed:\n{result.stderr.decode(errors='replace').strip()[-500:]}")

        fingerprint     = wait_for_fingerprint(t)
        runtime_version = _get_rustc_version()
        http_client_version = _get_reqwest_version_from_lock(tmp_dir)

    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    ja4          = fingerprint.get("ja4", "")
    alpn_present = bool(fingerprint.get("alpn") or [])

    return {
        "runtime":             config["runtime"],
        "runtime_version":     runtime_version,
        "http_client":         config["http_client"],
        "http_client_version": http_client_version,
        "os":                  _os_label(),
        "tls_library":         "rustls",
        "ja4":                 ja4,
        "alpn_present":        alpn_present,
        "captured_at":         t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "client_type":         config["client_type"],
    }


def _scaffold_rust_project(tmp_dir: str, url: str) -> None:
    """Write Cargo.toml and src/main.rs into tmp_dir."""
    src_dir = os.path.join(tmp_dir, "src")
    os.makedirs(src_dir, exist_ok=True)
    with open(os.path.join(tmp_dir, "Cargo.toml"), "w") as f:
        f.write(_RUST_CARGO_TOML)
    with open(os.path.join(src_dir, "main.rs"), "w") as f:
        f.write(_RUST_MAIN.replace("{url}", url))

# ── Runner — Browser (Playwright / Chromium) ─────────────────────────────────

def _capture_browser(config: dict, platform_label: str) -> dict:
    url = PROXY_URL  # BoringSSL is platform-independent; always run natively.

    venv_python = _ensure_playwright_env()

    t = datetime.now(tz=timezone.utc)
    chromium_version = _run_browser_chromium(url, venv_python)

    fingerprint  = wait_for_fingerprint(t)
    ja4          = fingerprint.get("ja4", "")
    alpn_present = bool(fingerprint.get("alpn") or [])

    return {
        "runtime":             config["runtime"],
        "runtime_version":     chromium_version,
        "http_client":         config["http_client"],
        "http_client_version": chromium_version,
        "os":                  _os_label(),
        "tls_library":         "BoringSSL",
        "ja4":                 ja4,
        "alpn_present":        alpn_present,
        "captured_at":         t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "client_type":         config["client_type"],
    }

# ── Main capture flow ────────────────────────────────────────────────────────

def capture(runtime_name: str, linux: bool = False) -> dict:
    """
    Full capture flow for one runtime. Returns the validated catalogue entry.
    Writes output to .capture-tmp/{runtime_name}-{platform}.json.

    Raises SystemExit if:
      - the runtime name is unknown
      - the proxy is unreachable
      - no fingerprint is captured within the timeout
      - a prerequisite tool (go, cargo, node) is not installed
    """
    if runtime_name not in RUNTIME_CONFIGS:
        valid = ", ".join(sorted(RUNTIME_CONFIGS.keys()))
        sys.exit(f"Unknown runtime '{runtime_name}'. Valid names: {valid}")

    config = RUNTIME_CONFIGS[runtime_name]
    runner = config["runner"]

    # Emit a clear warning and continue natively for platform-independent runtimes.
    if linux and not config["linux_supported"]:
        note = _PLATFORM_INDEPENDENT_NOTE.get(config["runtime"], "platform-independent")
        print(f"  NOTE: --linux has no effect for {runtime_name} ({note}). Running natively.")
        linux = False

    platform_label = "linux" if linux else platform.system().lower()
    print(f"[{runtime_name}] capturing ({platform_label}) ...")

    if runner == "curl":
        entry = _capture_curl(config, linux, platform_label)
    elif runner == "node":
        entry = _capture_node(config, linux, platform_label)
    elif runner == "go":
        _check_tool("go", "https://go.dev/dl/")
        entry = _capture_go(config, platform_label)
    elif runner == "rust":
        _check_tool("cargo", "https://rustup.rs/")
        entry = _capture_rust(config, platform_label)
    elif runner == "browser":
        entry = _capture_browser(config, platform_label)
    else:
        sys.exit(f"Internal error: unknown runner type '{runner}'")

    validate_entry(entry)

    CAPTURE_TMP_DIR.mkdir(exist_ok=True)
    tmp_file = CAPTURE_TMP_DIR / f"{runtime_name}-{platform_label}.json"
    tmp_file.write_text(json.dumps(entry, indent=2) + "\n")

    print(f"  runtime:       {entry['runtime']} {entry['runtime_version']}")
    print(f"  http_client:   {entry['http_client']} {entry['http_client_version']}")
    print(f"  ja4:           {entry['ja4']}")
    print(f"  os:            {entry['os']}")
    print(f"  alpn_present:  {entry['alpn_present']}")
    print(f"  tls_library:   {entry['tls_library']}")
    print(f"  written:       {os.path.relpath(tmp_file, PROJECT_ROOT)}")

    return entry


def _check_tool(tool: str, install_url: str) -> None:
    """Exit with a clear message if a required CLI tool is not on PATH."""
    if shutil.which(tool) is None:
        sys.exit(
            f"'{tool}' is required but not found on PATH.\n"
            f"Install it from: {install_url}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture TLS fingerprint for a language runtime.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Available runtimes:\n"
            + "\n".join(
                f"  {name:<22} {cfg['description']}"
                for name, cfg in sorted(RUNTIME_CONFIGS.items())
            )
        ),
    )
    parser.add_argument(
        "--runtime",
        default=None,
        help="Runtime name (e.g. curl, go-net-http, rust-reqwest)",
    )
    parser.add_argument(
        "--linux",
        action="store_true",
        help=(
            "Run request inside a Docker container to capture the Linux/OpenSSL fingerprint. "
            "Only meaningful for curl and node-* (emits a warning for Go, Rust, browser)."
        ),
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available runtime names and exit.",
    )
    args = parser.parse_args()

    if args.list:
        print("Available runtimes:")
        for name, cfg in sorted(RUNTIME_CONFIGS.items()):
            linux_note = "" if cfg["linux_supported"] else " (platform-independent)"
            print(f"  {name:<22} {cfg['description']}{linux_note}")
        return

    if not args.runtime:
        parser.error("--runtime is required (or use --list to see available runtimes)")

    capture(args.runtime, linux=args.linux)


if __name__ == "__main__":
    main()
