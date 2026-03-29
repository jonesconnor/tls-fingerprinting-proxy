# Changelog

All notable changes to this project will be documented in this file.

## [2.7.4] - 2026-03-29

### Added
- `scripts/capture_sdk.py`: automated SDK fingerprint capture harness — creates a temp venv, installs the target SDK, fires a request through the proxy, polls the NDJSON log for the resulting JA4 fingerprint, and writes a validated entry to `.capture-tmp/`
- `scripts/merge_catalogue.py`: merges `.capture-tmp/*.json` entries into `catalogue/ai-sdk-fingerprints.json` with duplicate JA4 detection and atomic writes via `os.replace()`
- `catalogue/schema.json`: JSON Schema for catalogue entry validation (8 required fields, `additionalProperties: false`)
- `scripts/tests/test_harness.py`: 24 unit tests covering NDJSON filtering, schema validation, SDK dispatch table, and catalogue merge logic
- `scripts/pyproject.toml`: pytest configuration for the scripts package
- Makefile targets: `capture-sdk`, `capture-sdk-linux`, `capture-all`, `capture-all-linux`, `merge-catalogue`; parallel execution via `make -j 4`

### Fixed
- `capture_sdk.py`: normalize `Z`-suffix timestamps before `fromisoformat` for Python <3.11 compatibility
- `capture_sdk.py`: update cohere SDK config to v5 API (`ClientV2.chat`) — `Client.generate` was removed in cohere v5
- `capture_sdk.py`: log warning when Linux Docker container exits non-zero instead of silently continuing
- `capture_sdk.py`: apply `shlex.quote()` to package name in both `_run_request_linux` and `_get_linux_metadata` bash commands
- `merge_catalogue.py`: sort output by `sdk` + `os` for deterministic catalogue ordering across runs
- Makefile: quote `$(SDK)` expansion in `capture-sdk` / `capture-sdk-linux` targets

## [2.7.3] - 2026-03-26

### Changed
- Homepage social links: GitHub, LinkedIn, and X now display as icon-only (no text label); mail link unchanged with email written out

## [2.7.2] - 2026-03-25

### Changed
- Default theme changed from dark to light mode on homepage and article page; theme toggle still switches both ways
- Agent service (`/`) response: replaced string `note` field with structured `endpoints` object (`/fingerprint`, `/catalogue`)
- Agent service (`/`) response: added `tagline` field with one-line site description
- Agent service links: corrected LinkedIn URL to full profile slug, added X social link, removed email address from agent response
- Agent healthcheck: replaced `curl` with `python3 urllib.request` (curl not present in `python:3.12-slim`)

## [2.7.1] - 2026-03-25

### Added
- Homepage (`/`) with classification banner, hero section (name, one-liner, social links), writing list, and about section
- Article route at `/writing/tls-fingerprinting` with full design system applied
- `article.html` Jinja2 template with Fraunces/Instrument Sans/JetBrains Mono typography, amber accent, dark/light mode toggle
- `_get_classification()` helper in `app.py` eliminating duplicated proxy header extraction
- Social links (GitHub, LinkedIn, X) with inline SVG icons; plain-text email display

### Changed
- `index.html` rebuilt as homepage template; article content moved to `article.html`
- Agent JSON response at `/writing/tls-fingerprinting` now returns correct `canonical_url` (`/writing/tls-fingerprinting`) instead of `/`
- `_agent_response()` accepts optional `canonical_path` override
- Design system migrated from purple accent to amber (`#e8a020`) per DESIGN.md
- Fonts updated from system stack to Fraunces (display), Instrument Sans (body), JetBrains Mono (UI/data)
