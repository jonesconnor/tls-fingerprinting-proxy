"""
logger.py — Persistent NDJSON fingerprint log.

One record per connection, written to a daily-rotating log file under
LOG_DIR (default: /data/fingerprints/). Each record is a self-contained
JSON object on a single line, making the log trivially grep/jq-able.

Record schema
-------------
{
  "ts":              "2026-03-17T12:34:56.789012+00:00",  // UTC ISO-8601
  "client_ip":       "203.0.113.42",
  "ja4":             "t13d1516h2_8daaf6152771_b0da82dd1658",
  "ja4_raw": {
    "a": "t13d1516h2",
    "b_input": "...",
    "c_input": "..."
  },
  "client_type":     "browser",      // browser|headless|agent|tool|unknown
  "detail":          "Chrome / Edge",
  "confidence":      "high",         // high|medium|low
  "signals":         ["grease", "ech", "compress_cert", "tls13"],
  "sni":             "example.com",
  "alpn":            ["h2", "http/1.1"],
  "cipher_count":    16,
  "extension_count": 18,
  "has_grease":      true,
  "has_ech":         true,
  "has_compress_cert": true,
  "tls_versions":    [772, 771]       // 772 = TLS 1.3, 771 = TLS 1.2
}

Rotation
--------
Files rotate at UTC midnight. LOG_RETENTION_DAYS (default: 30) old files
are kept; older ones are deleted automatically.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from classifier import Classification
    from tls_parser import ClientHelloInfo

LOG_DIR            = os.getenv("LOG_DIR",            "/data/fingerprints")
LOG_RETENTION_DAYS = int(os.getenv("LOG_RETENTION_DAYS", "30"))
_LOG_FILE          = "fingerprints.ndjson"


class FingerprintLogger:
    """
    Thread-safe, async-safe NDJSON logger backed by a
    TimedRotatingFileHandler. Instantiate once at startup and call
    .record() for each classified connection.
    """

    def __init__(self) -> None:
        log_dir = Path(LOG_DIR)
        log_dir.mkdir(parents=True, exist_ok=True)

        # Dedicated logger — isolated from the proxy's operational logger so
        # that log level changes to one don't affect the other.
        self._log = logging.getLogger("fingerprints")
        self._log.setLevel(logging.INFO)
        self._log.propagate = False

        if not self._log.handlers:
            handler = logging.handlers.TimedRotatingFileHandler(
                filename=log_dir / _LOG_FILE,
                when="midnight",
                interval=1,
                backupCount=LOG_RETENTION_DAYS,
                encoding="utf-8",
                utc=True,
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._log.addHandler(handler)

        self._log.info  # touch to confirm handler attached
        operational = logging.getLogger("proxy")
        operational.info(f"Fingerprint log: {log_dir / _LOG_FILE} (rotate daily, keep {LOG_RETENTION_DAYS}d)")

    def record(
        self,
        *,
        client_ip: str,
        ja4: str,
        ja4_raw: dict,
        clf: "Classification",
        ch: "ClientHelloInfo",
    ) -> None:
        """Write one NDJSON record for a classified connection."""
        entry = {
            "ts":               datetime.now(timezone.utc).isoformat(),
            "client_ip":        client_ip,
            "ja4":              ja4,
            "ja4_raw":          ja4_raw,
            "client_type":      clf.client_type,
            "detail":           clf.detail,
            "confidence":       clf.confidence,
            "signals":          clf.signals,
            # ClientHello fields
            "sni":              ch.sni,
            "alpn":             ch.alpn_protocols,
            "cipher_count":     len(ch.cipher_suites),
            "extension_count":  len(ch.extension_types),
            "has_grease":       ch.has_grease,
            "has_ech":          ch.has_ech,
            "has_compress_cert": ch.has_compress_cert,
            "tls_versions":     ch.supported_versions,
        }
        self._log.info(json.dumps(entry, default=str))
