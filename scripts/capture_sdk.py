"""
capture_sdk.py — Automated SDK fingerprint capture harness.

Captures the TLS fingerprint of a given AI SDK by routing a HTTPS request
through the local proxy and extracting the JA4 hash from the NDJSON log.

The proxy must be running before capture. Start it with: make up

Usage
-----
  python3 scripts/capture_sdk.py --sdk openai-python
  python3 scripts/capture_sdk.py --sdk httpx --linux

Makefile integration
--------------------
  make capture-sdk SDK=openai-python
  make capture-sdk-linux SDK=openai-python
  make capture-all
  make capture-all-linux
  make merge-catalogue

Harness flow
------------
  1. Look up SDK in SDK_CONFIGS (error + list valid names if unknown)
  2. Create temp venv, pip-install the package
  3. Record T = datetime.now(utc) before the request fires
  4. Run the SDK request → HTTPS to localhost:8443
  5. Poll fingerprints.ndjson (via docker compose exec) for entry where ts >= T
  6. Auto-detect: pip show → sdk_version, ssl.OPENSSL_VERSION → tls_library,
     platform info → python_version and os
  7. Construct and validate entry against catalogue/schema.json
  8. Write entry to .capture-tmp/{sdk}-{platform}.json
  9. Print summary line

Linux variant (--linux flag)
-----------------------------
  The request runs inside a python:3.11 Docker container so the TLS fingerprint
  reflects OpenSSL (Linux stack) rather than LibreSSL (macOS stack).
  The harness itself still runs on the host and reads the proxy NDJSON via
  docker compose exec.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
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

# Proxy endpoint — /health always responds quickly regardless of backend routing.
# Override port with CAPTURE_PROXY_PORT env var (e.g. prod uses 443 instead of 8443).
_capture_port    = os.getenv("CAPTURE_PROXY_PORT", "8443")
PROXY_URL        = f"https://localhost:{_capture_port}"
# Reachable from inside a Docker container on the same host (macOS + Linux).
LINUX_PROXY_URL  = f"https://host.docker.internal:{_capture_port}"

# ── SDK dispatch table ──────────────────────────────────────────────────────
#
# Each entry:
#   runtime       language runtime label written to the catalogue
#   http_client   HTTP client label written to the catalogue
#   package       pip install target (used for pip show version lookup)
#   request_code  Python one-liner (str.format receives `url=...`)
#   env_vars      env vars injected into the subprocess environment

SDK_CONFIGS: dict[str, dict] = {
    "openai-python": {
        "runtime": "python",
        "http_client": "openai",
        "package": "openai",
        "request_code": (
            "import openai, os; "
            "openai.OpenAI(base_url='{url}', api_key=os.environ['OPENAI_API_KEY'])"
            ".models.list()"
        ),
        "env_vars": {"OPENAI_API_KEY": "sk-dummy-00000000"},
    },
    "anthropic-python": {
        "runtime": "python",
        "http_client": "anthropic",
        "package": "anthropic",
        "request_code": (
            "import anthropic, os; "
            "anthropic.Anthropic(base_url='{url}', api_key=os.environ['ANTHROPIC_API_KEY'])"
            ".messages.create("
            "model='claude-3-haiku-20240307', max_tokens=1, "
            "messages=[{'role': 'user', 'content': 'hi'}]"
            ")"
        ),
        "env_vars": {"ANTHROPIC_API_KEY": "sk-ant-dummy-0000"},
    },
    "httpx": {
        "runtime": "python",
        "http_client": "httpx",
        "package": "httpx",
        "request_code": "import httpx; httpx.get('{url}', verify=False)",
        "env_vars": {},
    },
    "requests": {
        "runtime": "python",
        "http_client": "requests",
        "package": "requests",
        "request_code": "import requests; requests.get('{url}', verify=False)",
        "env_vars": {},
    },
    "langchain-openai": {
        "runtime": "python",
        "http_client": "langchain-openai",
        "package": "langchain-openai",
        "request_code": (
            "from langchain_openai import ChatOpenAI; "
            "ChatOpenAI(base_url='{url}', api_key='sk-dummy-00000000').invoke('hi')"
        ),
        "env_vars": {"OPENAI_API_KEY": "sk-dummy-00000000"},
    },
    "cohere": {
        "runtime": "python",
        "http_client": "cohere",
        "package": "cohere",
        "request_code": (
            "import cohere; "
            "cohere.ClientV2(api_key='dummy', base_url='{url}').chat("
            "model='command-r', messages=[{'role': 'user', 'content': 'hi'}])"
        ),
        "env_vars": {},
    },
    "llama-index-core": {
        "runtime": "python",
        "http_client": "httpx",  # llama-index delegates to httpx for HTTP transport
        "package": "llama-index-core",
        "request_code": "import httpx; httpx.get('{url}', verify=False)",
        "env_vars": {},
    },
}

# ── NDJSON helpers ──────────────────────────────────────────────────────────

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
    We record T immediately before firing the SDK request, so any entry with
    ts >= T was produced by that request (or one that arrived concurrently).
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
    Raises ImportError if jsonschema is not installed.
    """
    try:
        import jsonschema
    except ImportError:
        raise ImportError("jsonschema is required: pip install jsonschema")
    if schema is None:
        schema = load_schema()
    jsonschema.validate(entry, schema)

# ── Venv helpers (macOS / host capture) ────────────────────────────────────

def _create_venv_and_install(venv_dir: str, package: str) -> str:
    """
    Create a fresh venv at venv_dir, install the target package plus jsonschema.
    Returns the path to the venv Python executable.
    """
    venv_python = os.path.join(venv_dir, "bin", "python")
    subprocess.run(
        [sys.executable, "-m", "venv", venv_dir],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [venv_python, "-m", "pip", "install", package, "jsonschema", "--quiet"],
        check=True,
        capture_output=True,
    )
    return venv_python


def _get_sdk_version(venv_python: str, package: str) -> str:
    result = subprocess.run(
        [venv_python, "-m", "pip", "show", package],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return "unknown"


def _get_tls_library_from_venv(venv_python: str) -> str:
    result = subprocess.run(
        [venv_python, "-c", "import ssl; print(ssl.OPENSSL_VERSION)"],
        capture_output=True, text=True,
    )
    return result.stdout.strip() or "unknown"


def _get_python_version_from_venv(venv_python: str) -> str:
    result = subprocess.run(
        [venv_python, "-c", "import platform; print(platform.python_version())"],
        capture_output=True, text=True,
    )
    return result.stdout.strip() or "unknown"

# ── Linux Docker helpers ────────────────────────────────────────────────────

def _run_request_linux(package: str, request_code: str, env_vars: dict) -> None:
    """
    Run the SDK request inside a python:3.11 Docker container.
    The container connects to the proxy via host.docker.internal:8443.
    Uses --add-host=host.docker.internal:host-gateway for cross-platform support.
    """
    env_flags: list[str] = []
    for k, v in env_vars.items():
        env_flags += ["-e", f"{k}={v}"]

    install_cmd = f"pip install {shlex.quote(package)} --quiet"
    run_cmd = f"{install_cmd} && python3 -c {json.dumps(request_code)}"

    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "--add-host=host.docker.internal:host-gateway",
            *env_flags,
            "python:3.11",
            "bash", "-c", run_cmd,
        ],
        capture_output=True,
        cwd=PROJECT_ROOT,
    )
    if result.returncode != 0:
        print(
            f"  WARNING: docker run exited {result.returncode} — "
            f"fingerprint may not have been captured.\n"
            f"  stderr: {result.stderr.decode(errors='replace').strip()[:300]}"
        )


def _get_linux_metadata(package: str) -> tuple[str, str, str]:
    """
    Return (sdk_version, python_version, tls_library) by running a single
    docker container that installs the package and prints metadata as JSON.
    """
    meta_script = (
        "import subprocess, sys, ssl, platform, json; "
        f"r = subprocess.run([sys.executable, '-m', 'pip', 'show', {package!r}], "
        "capture_output=True, text=True); "
        "version = next((l.split(':',1)[1].strip() for l in r.stdout.splitlines() "
        "if l.startswith('Version:')), 'unknown'); "
        "print(json.dumps({'sdk_version': version, "
        "'python_version': platform.python_version(), "
        "'tls_library': ssl.OPENSSL_VERSION}))"
    )
    result = subprocess.run(
        [
            "docker", "run", "--rm", "python:3.11",
            "bash", "-c",
            f"pip install {shlex.quote(package)} --quiet && python3 -c {json.dumps(meta_script)}",
        ],
        capture_output=True,
        text=True,
    )
    try:
        meta = json.loads(result.stdout.strip())
        return (
            meta.get("sdk_version", "unknown"),
            meta.get("python_version", "unknown"),
            meta.get("tls_library", "unknown"),
        )
    except (json.JSONDecodeError, KeyError):
        return ("unknown", "unknown", "unknown")

# ── Main capture flow ───────────────────────────────────────────────────────

def capture(sdk_name: str, linux: bool = False) -> dict:
    """
    Full capture flow for one SDK. Returns the validated catalogue entry dict.
    Writes output to .capture-tmp/{sdk_name}-{platform}.json.

    Raises SystemExit if the SDK name is unknown, the proxy is unreachable,
    or no fingerprint is captured within the timeout.
    """
    if sdk_name not in SDK_CONFIGS:
        valid = ", ".join(sorted(SDK_CONFIGS.keys()))
        sys.exit(f"Unknown SDK '{sdk_name}'. Valid names: {valid}")

    config = SDK_CONFIGS[sdk_name]
    package = config["package"]
    env_vars = config["env_vars"]
    runtime = config["runtime"]
    http_client = config["http_client"]

    proxy_url = LINUX_PROXY_URL if linux else PROXY_URL
    request_code = config["request_code"].format(url=proxy_url)
    platform_label = "linux" if linux else platform.system().lower()

    print(f"[{sdk_name}] capturing ({platform_label}) ...")

    venv_dir: str | None = None
    try:
        if linux:
            t = datetime.now(tz=timezone.utc)
            _run_request_linux(package, request_code, env_vars)
            http_client_version, runtime_version, tls_library = _get_linux_metadata(package)
            os_label = "Linux"
        else:
            venv_dir = tempfile.mkdtemp(prefix=f"cap_{sdk_name.replace('-', '_')}_")
            venv_python = _create_venv_and_install(venv_dir, package)
            t = datetime.now(tz=timezone.utc)
            subprocess.run(
                [venv_python, "-c", request_code],
                env={**os.environ, **env_vars},
                capture_output=True,
            )
            http_client_version = _get_sdk_version(venv_python, package)
            runtime_version     = _get_python_version_from_venv(venv_python)
            tls_library         = _get_tls_library_from_venv(venv_python)
            os_label = f"{platform.system()} {platform.mac_ver()[0] or platform.release()}".strip()
    finally:
        if venv_dir:
            shutil.rmtree(venv_dir, ignore_errors=True)

    # Poll the proxy NDJSON for the fingerprint we just triggered
    fingerprint = wait_for_fingerprint(t)

    ja4  = fingerprint.get("ja4", "")
    alpn = fingerprint.get("alpn") or []
    alpn_present = bool(alpn)

    entry: dict = {
        "runtime":             runtime,
        "runtime_version":     runtime_version,
        "http_client":         http_client,
        "http_client_version": http_client_version,
        "os":                  os_label,
        "tls_library":         tls_library,
        "ja4":                 ja4,
        "alpn_present":        alpn_present,
        "captured_at":         t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "client_type":         "agent",  # All Python AI SDK captures are AI agents.
    }

    validate_entry(entry)

    CAPTURE_TMP_DIR.mkdir(exist_ok=True)
    tmp_file = CAPTURE_TMP_DIR / f"{sdk_name}-{platform_label}.json"
    tmp_file.write_text(json.dumps(entry, indent=2) + "\n")

    print(f"  runtime:       {runtime} {runtime_version}")
    print(f"  http_client:   {http_client} {http_client_version}")
    print(f"  ja4:           {ja4}")
    print(f"  os:            {os_label}")
    print(f"  alpn_present:  {alpn_present}")
    print(f"  tls_library:   {tls_library}")
    print(f"  written:       {os.path.relpath(tmp_file, PROJECT_ROOT)}")

    return entry


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture TLS fingerprint for an AI SDK.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available SDKs: {', '.join(sorted(SDK_CONFIGS))}",
    )
    parser.add_argument("--sdk", required=True, help="SDK name (e.g. openai-python)")
    parser.add_argument(
        "--linux",
        action="store_true",
        help="Run request inside python:3.11 Docker container (OpenSSL/Linux fingerprint)",
    )
    args = parser.parse_args()
    capture(args.sdk, linux=args.linux)


if __name__ == "__main__":
    main()
