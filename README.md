# tls-fingerprinting-proxy
A peek-forward TCP proxy that computes JA4 fingerprint, classifies the client, and forwards the connection to the backend with the classification added as a header.

Detected AI agents and tools are routed to a dedicated agent upstream service that returns JSON and exposes the TLS fingerprint data that identified them:

- `GET /` — structured JSON response including the detected fingerprint profile
- `GET /fingerprint` — TLS fingerprint for any caller (shareable demo URL)
- `GET /catalogue` — the AI SDK fingerprint catalogue as a JSON array
- `GET /compare` — JSON fingerprint comparison against reference clients
- `GET /stats` — traffic statistics as JSON (last 50 requests, hourly breakdown, gap candidates)

Browser clients are served by the backend service:

- `GET /` — homepage with live JA4 fingerprint and client classification
- `GET /compare` — visual fingerprint breakdown comparing visitor profile against reference clients (Chrome, Firefox, Safari, curl, Go, Python)
- `GET /stats` — traffic dashboard with hourly chart, top fingerprints, and catalogue gap candidates
- `GET /debug` — raw headers and full proxy classification as JSON
- `GET /health` — health check
