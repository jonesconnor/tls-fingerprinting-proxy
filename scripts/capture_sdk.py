"""
capture_sdk.py — Trigger one HTTPS request through the proxy to capture a TLS fingerprint.

Run this with each SDK you want to fingerprint. The proxy logs the JA4 hash
to /data/fingerprints/fingerprints.ndjson. After running, use `make capture-fingerprint`
to pull the latest entry and copy it into catalogue/ai-sdk-fingerprints.json.

Usage
-----
  # Default: uses urllib (no extra dependencies)
  python3 scripts/capture_sdk.py

  # Swap in the SDK under test by editing the REQUEST_FN below, e.g.:
  #   import openai; client = openai.OpenAI(base_url=TARGET_URL); client.models.list()
  #   import anthropic; anthropic.Anthropic(base_url=TARGET_URL).messages.create(...)
  #   import httpx; httpx.get(TARGET_URL, verify=False)
  #   import requests; requests.get(TARGET_URL, verify=False)

Workflow
--------
  1. Edit REQUEST_FN to use the SDK under test
  2. python3 scripts/capture_sdk.py
  3. make capture-fingerprint          # prints the latest NDJSON entry
  4. Copy the entry into catalogue/ai-sdk-fingerprints.json with sdk/sdk_version/etc. filled in
  5. docker compose restart proxy      # reload catalogue
"""

import ssl
import urllib.request

# Proxy endpoint for fingerprint capture — the /health path avoids any backend
# content-negotiation logic and always returns quickly.
TARGET_URL = "https://localhost:8443/health"


def _default_request():
    """urllib — uses the system TLS stack (LibreSSL on macOS, OpenSSL on Linux)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(TARGET_URL, context=ctx) as r:
        return r.read()


# ── Swap this to the SDK under test ──────────────────────────────────────────
REQUEST_FN = _default_request
# Examples:
#   import httpx
#   REQUEST_FN = lambda: httpx.get(TARGET_URL, verify=False).content
#
#   import requests
#   REQUEST_FN = lambda: requests.get(TARGET_URL, verify=False).content
#
#   import openai
#   client = openai.OpenAI(base_url=TARGET_URL, api_key="dummy")
#   REQUEST_FN = lambda: client.models.list()
# ─────────────────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    print(f"Sending request to {TARGET_URL} ...")
    try:
        result = REQUEST_FN()
        print(f"Response: {result[:200]}")
        print("\nFingerprint captured. Run `make capture-fingerprint` to inspect it.")
    except Exception as e:
        print(f"Request failed: {e}")
        print("Is the proxy stack running? Try: make up")
