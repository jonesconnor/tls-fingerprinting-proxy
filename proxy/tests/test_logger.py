"""
Tests for logger.py — persistent NDJSON fingerprint logging.
"""

import json
import logging

import pytest

import logger as logger_module
from classifier import Classification
from logger import FingerprintLogger
from tls_parser import ClientHelloInfo

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_fingerprint_logger():
    """Clear the 'fingerprints' Python logger handlers between tests."""
    yield
    fp_log = logging.getLogger("fingerprints")
    for handler in fp_log.handlers[:]:
        handler.close()
        fp_log.removeHandler(handler)


@pytest.fixture
def log_dir(tmp_path, monkeypatch):
    """Redirect LOG_DIR to a temp directory for test isolation."""
    monkeypatch.setattr(logger_module, "LOG_DIR", str(tmp_path))
    return tmp_path


def _make_clf(**kwargs) -> Classification:
    defaults = dict(
        client_type="agent",
        confidence="high",
        detail="Python HTTP client - OpenSSL",
        signals=["permissive_ciphers", "tls13"],
    )
    defaults.update(kwargs)
    return Classification(**defaults)


def _make_ch(**kwargs) -> ClientHelloInfo:
    defaults = dict(
        cipher_suites=[0x1301, 0x1302, 0x1303],
        extension_types=[0x0000, 0x000d, 0x002b],
        sni="example.com",
        alpn_protocols=["h2"],
        supported_versions=[0x0304],
        signature_algorithms=[0x0403],
        supported_groups=[0x001d],
        has_grease=False,
        has_ech=False,
        has_compress_cert=False,
    )
    defaults.update(kwargs)
    return ClientHelloInfo(**defaults)


def _write_record(log_dir, **overrides) -> None:
    fp_log = FingerprintLogger()
    fp_log.record(
        client_ip=overrides.get("client_ip", "1.2.3.4"),
        ja4=overrides.get("ja4", "t13d0003h2_aabbccddeeff_aabbccddeeff"),
        ja4_raw=overrides.get("ja4_raw", {"tls_version": "13"}),
        clf=overrides.get("clf", _make_clf()),
        ch=overrides.get("ch", _make_ch()),
    )


# ---------------------------------------------------------------------------
# File creation
# ---------------------------------------------------------------------------

class TestFileCreation:
    def test_creates_log_file_on_first_record(self, log_dir):
        _write_record(log_dir)
        log_file = log_dir / "fingerprints.ndjson"
        assert log_file.exists()

    def test_creates_log_dir_if_missing(self, tmp_path, monkeypatch):
        nested = tmp_path / "a" / "b" / "c"
        monkeypatch.setattr(logger_module, "LOG_DIR", str(nested))
        _write_record(nested)
        assert nested.is_dir()


# ---------------------------------------------------------------------------
# NDJSON format
# ---------------------------------------------------------------------------

class TestNDJSONFormat:
    def test_each_record_is_valid_json(self, log_dir):
        _write_record(log_dir)
        lines = (log_dir / "fingerprints.ndjson").read_text().strip().splitlines()
        assert len(lines) == 1
        json.loads(lines[0])  # raises if invalid

    def test_multiple_records_are_separate_lines(self, log_dir):
        fp_log = FingerprintLogger()
        for _ in range(3):
            fp_log.record(
                client_ip="1.2.3.4",
                ja4="t13d0003h2_aabbccddeeff_aabbccddeeff",
                ja4_raw={},
                clf=_make_clf(),
                ch=_make_ch(),
            )
        lines = (log_dir / "fingerprints.ndjson").read_text().strip().splitlines()
        assert len(lines) == 3
        for line in lines:
            json.loads(line)


# ---------------------------------------------------------------------------
# Record field coverage
# ---------------------------------------------------------------------------

class TestRecordFields:
    REQUIRED_FIELDS = {
        "ts", "client_ip", "ja4", "ja4_raw",
        "client_type", "detail", "confidence", "signals",
        "sni", "alpn", "cipher_count", "extension_count",
        "has_grease", "has_ech", "has_compress_cert", "tls_versions",
    }

    def _read_record(self, log_dir) -> dict:
        _write_record(log_dir)
        line = (log_dir / "fingerprints.ndjson").read_text().strip()
        return json.loads(line)

    def test_all_required_fields_present(self, log_dir):
        record = self._read_record(log_dir)
        assert self.REQUIRED_FIELDS.issubset(record.keys())

    def test_client_ip_is_recorded(self, log_dir):
        fp_log = FingerprintLogger()
        fp_log.record(
            client_ip="203.0.113.99",
            ja4="t13d0003h2_aabbccddeeff_aabbccddeeff",
            ja4_raw={},
            clf=_make_clf(),
            ch=_make_ch(),
        )
        record = json.loads((log_dir / "fingerprints.ndjson").read_text().strip())
        assert record["client_ip"] == "203.0.113.99"

    def test_classification_fields_are_recorded(self, log_dir):
        fp_log = FingerprintLogger()
        fp_log.record(
            client_ip="1.2.3.4",
            ja4="t13d0003h2_aabbccddeeff_aabbccddeeff",
            ja4_raw={},
            clf=_make_clf(client_type="browser", confidence="high", detail="Chrome"),
            ch=_make_ch(),
        )
        record = json.loads((log_dir / "fingerprints.ndjson").read_text().strip())
        assert record["client_type"] == "browser"
        assert record["confidence"] == "high"
        assert record["detail"] == "Chrome"

    def test_cipher_and_extension_counts(self, log_dir):
        fp_log = FingerprintLogger()
        fp_log.record(
            client_ip="1.2.3.4",
            ja4="t13d0003h2_aabbccddeeff_aabbccddeeff",
            ja4_raw={},
            clf=_make_clf(),
            ch=_make_ch(
                cipher_suites=[0x1301, 0x1302, 0x1303],
                extension_types=[0x0000, 0x000d],
            ),
        )
        record = json.loads((log_dir / "fingerprints.ndjson").read_text().strip())
        assert record["cipher_count"] == 3
        assert record["extension_count"] == 2

    def test_boolean_signals_are_recorded(self, log_dir):
        fp_log = FingerprintLogger()
        fp_log.record(
            client_ip="1.2.3.4",
            ja4="t13d0003h2_aabbccddeeff_aabbccddeeff",
            ja4_raw={},
            clf=_make_clf(),
            ch=_make_ch(has_grease=True, has_ech=True, has_compress_cert=False),
        )
        record = json.loads((log_dir / "fingerprints.ndjson").read_text().strip())
        assert record["has_grease"] is True
        assert record["has_ech"] is True
        assert record["has_compress_cert"] is False

    def test_ts_is_iso8601_utc(self, log_dir):
        record = self._read_record(log_dir)
        # ISO-8601 UTC timestamps end with +00:00
        assert record["ts"].endswith("+00:00")
