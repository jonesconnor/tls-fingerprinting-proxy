.PHONY: certs build up down logs test-curl test-python test-node dump-logs query-logs clean

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

# ── Log inspection ─────────────────────────────────────────────────────────
#
# dump-logs: tail the live fingerprint log and pretty-print each record
# query-logs TYPE=agent: filter records by client_type (browser|agent|tool|headless|unknown)

dump-logs:
	@docker compose exec proxy sh -c \
	  'tail -n 50 /data/fingerprints/fingerprints.ndjson 2>/dev/null || echo "No log file yet — run some test clients first."' \
	  | python3 -c "import sys,json; [print(json.dumps(json.loads(l),indent=2)) for l in sys.stdin if l.strip()]" 2>/dev/null \
	  || docker compose exec proxy tail -n 50 /data/fingerprints/fingerprints.ndjson

query-logs:
	@docker compose exec proxy sh -c \
	  'cat /data/fingerprints/fingerprints.ndjson 2>/dev/null || echo "No log file yet."' \
	  | python3 -c "
import sys, json
t = '$(TYPE)'
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        r = json.loads(line)
        if not t or r.get('client_type') == t:
            print(json.dumps(r, indent=2))
    except json.JSONDecodeError:
        pass
"

# ── Utilities ──────────────────────────────────────────────────────────────

clean:
	docker compose down --rmi local --volumes
	rm -f certs/proxy.crt certs/proxy.key
