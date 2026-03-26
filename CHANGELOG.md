# Changelog

All notable changes to this project will be documented in this file.

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
