# Changelog

All notable changes to this project will be documented in this file.

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
