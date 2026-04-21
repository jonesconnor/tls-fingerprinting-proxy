.PHONY: certs build up down logs test-curl test-python test-node test-agent dump-logs \
        query-logs capture-fingerprint provision-certs up-prod down-prod logs-prod \
        renew-certs clean \
        capture-sdk capture-sdk-linux capture-all capture-all-linux merge-catalogue \
        $(addprefix _capture-macos-,$(_SDKS)) $(addprefix _capture-linux-,$(_SDKS)) \
        capture-runtime capture-runtime-linux capture-all-runtimes capture-all-runtimes-linux \
        capture-all-runtimes-remote fetch-remote clean-capture-tmp \
        setup-playwright \
        $(addprefix _capture-runtime-,$(_RUNTIMES)) \
        $(addprefix _capture-runtime-linux-,$(_LINUX_RUNTIMES))

_SDKS := openai-python anthropic-python httpx requests langchain-openai cohere llama-index-core

# Runtimes captured by capture_runtime.py.
# All runtimes: used for capture-all-runtimes (serialised — avoids TODO-8 race).
_RUNTIMES := curl node-https node-fetch node-axios go-net-http rust-reqwest chrome-playwright
# Linux-variant runtimes only: runtimes where TLS fingerprint differs on Linux.
# Go and Chromium use platform-independent TLS stacks — Linux capture is a no-op.
# Rust (rustls) produces a different JA4 on Linux vs macOS (confirmed by catalogue data).
_LINUX_RUNTIMES := curl node-https node-fetch node-axios rust-reqwest

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

# curl uses OpenSSL — classified as "tool", routed to human backend
test-curl:
	@echo "--- curl (OpenSSL) ---"
	curl -sk https://localhost:8443/ | python3 -m json.tool 2>/dev/null || curl -sk https://localhost:8443/

# Hit the agent backend directly to verify it returns JSON
test-agent:
	@echo "--- agent backend (direct) ---"
	curl -s http://localhost:8001/ | python3 -m json.tool

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

# ── Fingerprint capture ────────────────────────────────────────────────────

# Print the latest fingerprint log entry (ja4, client_type, detail, alpn).
# Run after scripts/capture_sdk.py to confirm the JA4 was captured.
capture-fingerprint:
	@docker compose exec proxy sh -c \
	  'tail -1 /data/fingerprints/fingerprints.ndjson 2>/dev/null || echo "No log file yet."' \
	  | python3 -c "import sys,json; d=json.loads(sys.stdin.read().strip()); print(json.dumps({k:d.get(k) for k in ['ja4','client_type','detail','alpn']},indent=2))"

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
	  | python3 -c "import sys,json; t='$(TYPE)'; [print(json.dumps(r,indent=2)) for l in sys.stdin if l.strip() for r in [json.loads(l)] if not t or r.get('client_type')==t]"

# ── Production ─────────────────────────────────────────────────────────────
#
# Workflow:
#   1. Buy a domain. Point an A record at your Hetzner server IP.
#   2. make provision-certs DOMAIN=yourhost.com EMAIL=you@example.com
#   3. make up-prod DOMAIN=yourhost.com
#   4. make renew-certs DOMAIN=yourhost.com   (run every ~60 days; LE certs expire at 90)

# Obtain a Let's Encrypt certificate via certbot standalone.
# Port 80 must be reachable from the internet during this step.
provision-certs:
	@test -n "$(DOMAIN)" || (echo "Usage: make provision-certs DOMAIN=yourhost.com EMAIL=you@example.com" && exit 1)
	@test -n "$(EMAIL)"  || (echo "EMAIL is required. Usage: make provision-certs DOMAIN=... EMAIL=..." && exit 1)
	@bash certs/provision.sh $(DOMAIN) $(EMAIL)

# Start the production stack (port 443, Let's Encrypt cert).
# Run provision-certs first if you haven't already.
up-prod:
	@test -n "$(DOMAIN)" || (echo "Usage: make up-prod DOMAIN=yourhost.com" && exit 1)
	@test -f certs/letsencrypt/live/$(DOMAIN)/fullchain.pem || \
	  (echo "No cert found for $(DOMAIN). Run: make provision-certs DOMAIN=$(DOMAIN) EMAIL=you@example.com" && exit 1)
	DOMAIN=$(DOMAIN) docker compose -f docker-compose.prod.yml up -d --build
	@echo ""
	@echo "  Proxy:   https://$(DOMAIN)/"
	@echo "  Logs:    make logs-prod"
	@echo "  Test:    curl https://$(DOMAIN)/debug"

down-prod:
	docker compose -f docker-compose.prod.yml down

logs-prod:
	docker compose -f docker-compose.prod.yml logs -f

# Renew the Let's Encrypt certificate and restart the proxy to pick it up.
# Port 80 must be reachable during renewal (same as provisioning).
renew-certs:
	@test -n "$(DOMAIN)" || (echo "Usage: make renew-certs DOMAIN=yourhost.com" && exit 1)
	docker run --rm \
	  -p 80:80 \
	  -v "$(CURDIR)/certs/letsencrypt:/etc/letsencrypt" \
	  certbot/certbot renew --standalone
	docker compose -f docker-compose.prod.yml restart proxy

# ── SDK fingerprint capture ────────────────────────────────────────────────
#
# Prerequisites: proxy stack must be running (make up).
#
# Single SDK capture (macOS / host Python):
#   make capture-sdk SDK=openai-python
#
# Single SDK capture (Linux OpenSSL via python:3.11 Docker):
#   make capture-sdk-linux SDK=openai-python
#
# Capture all SDKs in parallel, then merge into catalogue:
#   make capture-all          # macOS
#   make capture-all-linux    # Linux
#
# Merge .capture-tmp/*.json into catalogue/ai-sdk-fingerprints.json:
#   make merge-catalogue

capture-sdk:
	@test -n "$(SDK)" || (echo "Usage: make capture-sdk SDK=openai-python" && exit 1)
	uv run --project scripts scripts/capture_sdk.py --sdk '$(SDK)'

capture-sdk-linux:
	@test -n "$(SDK)" || (echo "Usage: make capture-sdk-linux SDK=openai-python" && exit 1)
	uv run --project scripts scripts/capture_sdk.py --sdk '$(SDK)' --linux

# Hidden per-SDK targets used by capture-all / capture-all-linux
$(addprefix _capture-macos-,$(_SDKS)): _capture-macos-%:
	uv run --project scripts scripts/capture_sdk.py --sdk $*

$(addprefix _capture-linux-,$(_SDKS)): _capture-linux-%:
	uv run --project scripts scripts/capture_sdk.py --sdk $* --linux

capture-all:
	$(MAKE) -j 4 $(addprefix _capture-macos-,$(_SDKS))
	$(MAKE) merge-catalogue

capture-all-linux:
	$(MAKE) -j 4 $(addprefix _capture-linux-,$(_SDKS))
	$(MAKE) merge-catalogue

merge-catalogue:
	uv run --project scripts scripts/merge_catalogue.py

# ── Language-runtime fingerprint capture ──────────────────────────────────
#
# Captures TLS fingerprints for non-Python runtimes: curl, Node.js (https,
# fetch, axios), Go net/http, Rust reqwest, and Chrome headless (Playwright).
#
# Each runtime uses a different TLS stack, which produces a distinct JA4.
# This is the core research contribution — SDK-level variance is small;
# runtime-level variance is where the interesting signal lives.
#
# Prerequisites: proxy stack must be running (make up).
#
# Single runtime capture (native / macOS):
#   make capture-runtime RUNTIME=curl
#   make capture-runtime RUNTIME=go-net-http
#   make capture-runtime RUNTIME=rust-reqwest
#
# Linux variant (only meaningful for curl and node-*):
#   make capture-runtime-linux RUNTIME=curl
#   make capture-runtime-linux RUNTIME=node-axios
#
# Capture all runtimes, serialised (avoids NDJSON attribution race):
#   make capture-all-runtimes          # all native
#   make capture-all-runtimes-linux    # Linux-variant runtimes only
#
# First-time Playwright setup (downloads ~200 MB Chromium binaries, once):
#   make setup-playwright
#
# Merge results into catalogue:
#   make merge-catalogue

RUNTIME ?= curl

capture-runtime:             ## Capture TLS fingerprint for one runtime (native)
	@test -n "$(RUNTIME)" || (echo "Usage: make capture-runtime RUNTIME=curl" && exit 1)
	uv run --project scripts scripts/capture_runtime.py --runtime '$(RUNTIME)'

capture-runtime-linux:       ## Linux-variant capture: make capture-runtime-linux RUNTIME=curl
	@test -n "$(RUNTIME)" || (echo "Usage: make capture-runtime-linux RUNTIME=curl" && exit 1)
	uv run --project scripts scripts/capture_runtime.py --runtime '$(RUNTIME)' --linux

# Hidden per-runtime targets used by capture-all-runtimes.
# Serialised (-j 1) to avoid the NDJSON concurrent-capture race (TODO-8):
# each worker records T before the request and polls for the first NDJSON
# entry with ts >= T — under concurrency, a different worker's handshake
# could be attributed to the wrong runtime.
$(addprefix _capture-runtime-,$(_RUNTIMES)): _capture-runtime-%:
	uv run --project scripts scripts/capture_runtime.py --runtime $*

$(addprefix _capture-runtime-linux-,$(_LINUX_RUNTIMES)): _capture-runtime-linux-%:
	uv run --project scripts scripts/capture_runtime.py --runtime $* --linux

capture-all-runtimes:        ## Capture all runtimes (serialised) then merge into catalogue
	$(MAKE) clean-capture-tmp
	$(MAKE) -j 1 $(addprefix _capture-runtime-,$(_RUNTIMES))
	$(MAKE) merge-catalogue

capture-all-runtimes-linux:  ## Capture Linux-variant runtimes (curl, node-*) then merge
	$(MAKE) -j 1 $(addprefix _capture-runtime-linux-,$(_LINUX_RUNTIMES))
	$(MAKE) merge-catalogue

setup-playwright:            ## One-time setup: install Playwright + download Chromium (~200 MB)
	uv run --project scripts python3 -c "import sys; sys.path.insert(0,'scripts'); from capture_runtime import _ensure_playwright_env; _ensure_playwright_env()"

# ── Cross-platform capture ─────────────────────────────────────────────────
#
# Captures fingerprints on both this machine and a remote Linux VPS, then
# merges all results into the catalogue in one pass.
#
# Workflow:
#   1. make capture-all-runtimes              # Mac-native fingerprints → .capture-tmp/
#   2. make capture-all-runtimes-remote VPS=user@host
#      → SSH to VPS, run Linux captures there, rsync results back, merge all
#   3. git add catalogue/ai-sdk-fingerprints.json && git commit
#
# The remote repo is expected at ~/tls-fingerprinting-proxy on the VPS.
# Go, Rust, and Chromium produce the same JA4 on both platforms — the merge
# script will warn and skip those duplicates automatically.

VPS ?=

fetch-remote:                ## Rsync .capture-tmp/*.json from VPS into local .capture-tmp/
	@test -n "$(VPS)" || (echo "Usage: make fetch-remote VPS=user@host" && exit 1)
	mkdir -p .capture-tmp
	rsync -avz $(VPS):~/tls-fingerprinting-proxy/.capture-tmp/ .capture-tmp/

capture-all-runtimes-remote: ## Run Linux captures on VPS (assumes stack already running), fetch results, merge
	@test -n "$(VPS)" || (echo "Usage: make capture-all-runtimes-remote VPS=user@host" && exit 1)
	ssh $(VPS) 'export PATH="$$HOME/.local/bin:$$PATH" && cd ~/tls-fingerprinting-proxy && git pull && make clean-capture-tmp && CAPTURE_PROXY_PORT=443 make capture-all-runtimes-linux'
	$(MAKE) fetch-remote VPS=$(VPS)
	$(MAKE) merge-catalogue

# ── Utilities ──────────────────────────────────────────────────────────────

clean:
	docker compose down --rmi local --volumes
	rm -f certs/proxy.crt certs/proxy.key

clean-capture-tmp:           ## Remove intermediate capture files (run before a fresh capture)
	rm -rf .capture-tmp
