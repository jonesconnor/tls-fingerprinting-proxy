# tls-fingerprinting-proxy
A peek-forward TCP proxy that computes JA4 fingerprint, classifies the client, and forwards the connection to the backend with the classification added as a header.

Detected AI agents and tools are routed to a dedicated agent upstream service that returns JSON and exposes the TLS fingerprint data that identified them:

- `GET /` — structured JSON response including the detected fingerprint profile
- `GET /fingerprint` — TLS fingerprint for any caller (shareable demo URL)
- `GET /catalogue` — the AI SDK fingerprint catalogue as a JSON array
