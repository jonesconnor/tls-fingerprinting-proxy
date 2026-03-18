.PHONY: certs build up down logs test-curl test-python test-node clean

# ── Setup ──────────────────────────────────────────────────────────────────

certs:
	@echo "Generating self-signed TLS cert..."
	@bash certs/gen.sh

build:
	docker compose build

# ── Run ────────────────────────────────────────────────────────────────────

up: certs
	docker compose up -d
	@echo ""
	@echo "  Proxy:   https://localhost:8443/"
	@echo "  Logs:    make logs"
	@echo "  Test:    make test-curl"

down:
	docker compose down

logs:
	docker compose logs -f

# ── Tests (run these while the stack is up) ────────────────────────────────
#
# Each client produces a different TLS fingerprint. Watch the proxy logs
# alongside these commands to see real-time classification.

# curl uses OpenSSL — classified as "tool"
test-curl:
	@echo "--- curl (OpenSSL) ---"
	curl -sk https://localhost:8443/ | python3 -m json.tool 2>/dev/null || curl -sk https://localhost:8443/

# Python urllib — classified as "agent" (Linux OpenSSL) or "agent/macOS" (Apple TLS)
test-python:
	@echo "--- Python urllib ---"
	python3 -c "\
import urllib.request, ssl, json; \
ctx = ssl.create_default_context(); \
ctx.check_hostname = False; \
ctx.verify_mode = ssl.CERT_NONE; \
r = urllib.request.urlopen('https://localhost:8443/debug', context=ctx); \
print(json.dumps(json.loads(r.read()), indent=2))"

# Go-style: use curl with restricted cipher list to simulate Go crypto/tls
test-go-sim:
	@echo "--- Go-like (restricted ciphers) ---"
	curl -sk --ciphers TLS_AES_128_GCM_SHA256 https://localhost:8443/debug | python3 -m json.tool

# Check the debug endpoint — shows all headers the backend received
test-debug:
	@echo "--- Debug headers ---"
	curl -sk https://localhost:8443/debug | python3 -m json.tool

# ── Utilities ──────────────────────────────────────────────────────────────

clean:
	docker compose down --rmi local --volumes
	rm -f certs/proxy.crt certs/proxy.key
