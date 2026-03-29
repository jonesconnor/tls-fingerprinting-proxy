"""
test_harness.py — Unit tests for the SDK fingerprint capture harness.

These tests cover pure logic only — no Docker, no network, no proxy required.
The capture() and wait_for_fingerprint() functions are not tested here because
they require live infrastructure. The functions under test are importable and
have no side effects when called with controlled inputs.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture_sdk import SDK_CONFIGS, filter_ndjson_after, validate_entry, load_schema
from merge_catalogue import merge_catalogue, load_existing_catalogue


# ── Helpers ─────────────────────────────────────────────────────────────────

SCHEMA_PATH = Path(__file__).resolve().parent.parent.parent / "catalogue" / "schema.json"

VALID_ENTRY = {
    "sdk":            "httpx",
    "sdk_version":    "0.27.0",
    "python_version": "3.11.0",
    "os":             "macOS 15.0",
    "tls_library":    "LibreSSL 3.3.6",
    "ja4":            "t13d1516h2_8daaf6152771_b0da82dd1658",
    "alpn_present":   False,
    "captured_at":    "2026-03-26T12:00:00Z",
}


def _make_entry(**overrides) -> dict:
    return {**VALID_ENTRY, **overrides}


def _make_ndjson_line(ts: str, ja4: str = "t13d1516h2_aaa_bbb", alpn: list | None = None) -> str:
    record = {
        "ts":          ts,
        "client_ip":   "127.0.0.1",
        "ja4":         ja4,
        "client_type": "agent",
        "detail":      "test",
        "confidence":  "high",
        "signals":     [],
        "sni":         "localhost",
        "alpn":        alpn or [],
        "cipher_count": 5,
        "extension_count": 8,
        "has_grease":  False,
        "has_ech":     False,
        "has_compress_cert": False,
        "tls_versions": [772],
    }
    return json.dumps(record)


# ── TestNdjsonFilter ─────────────────────────────────────────────────────────

class TestNdjsonFilter:
    def test_returns_entry_after_timestamp(self):
        t = datetime(2026, 3, 26, 12, 0, 0, tzinfo=timezone.utc)
        ts_after = "2026-03-26T12:00:01+00:00"
        content = _make_ndjson_line(ts_after, ja4="t13d_match")
        result = filter_ndjson_after(content, t)
        assert result is not None
        assert result["ja4"] == "t13d_match"

    def test_ignores_entries_before_timestamp(self):
        t = datetime(2026, 3, 26, 12, 0, 0, tzinfo=timezone.utc)
        ts_before = "2026-03-26T11:59:59+00:00"
        content = _make_ndjson_line(ts_before, ja4="t13d_old")
        result = filter_ndjson_after(content, t)
        assert result is None

    def test_returns_none_when_no_match(self):
        # Empty content — proxy not running / no entries yet
        result = filter_ndjson_after("", datetime.now(tz=timezone.utc))
        assert result is None

    def test_returns_first_match_when_multiple_entries(self):
        t = datetime(2026, 3, 26, 12, 0, 0, tzinfo=timezone.utc)
        line1 = _make_ndjson_line("2026-03-26T11:59:59+00:00", ja4="old")
        line2 = _make_ndjson_line("2026-03-26T12:00:01+00:00", ja4="first_after")
        line3 = _make_ndjson_line("2026-03-26T12:00:02+00:00", ja4="second_after")
        content = "\n".join([line1, line2, line3])
        result = filter_ndjson_after(content, t)
        assert result is not None
        assert result["ja4"] == "first_after"

    def test_skips_malformed_json_lines(self):
        t = datetime(2026, 3, 26, 12, 0, 0, tzinfo=timezone.utc)
        bad_line  = "not valid json {"
        good_line = _make_ndjson_line("2026-03-26T12:00:01+00:00", ja4="after_bad")
        content = "\n".join([bad_line, good_line])
        result = filter_ndjson_after(content, t)
        assert result is not None
        assert result["ja4"] == "after_bad"

    def test_handles_z_suffix_timestamps(self):
        t = datetime(2026, 3, 26, 12, 0, 0, tzinfo=timezone.utc)
        # Some loggers emit "Z" instead of "+00:00"; fromisoformat rejects "Z" on Python < 3.11
        line = _make_ndjson_line("2026-03-26T12:00:01Z", ja4="z_ts")
        result = filter_ndjson_after(line, t)
        assert result is not None
        assert result["ja4"] == "z_ts"

    def test_naive_t_treated_as_utc(self):
        # T without tzinfo should be treated as UTC (not local time)
        t_naive = datetime(2026, 3, 26, 12, 0, 0)  # no tzinfo
        content = _make_ndjson_line("2026-03-26T12:00:01+00:00", ja4="naive_t")
        result = filter_ndjson_after(content, t_naive)
        assert result is not None


# ── TestSchemaValidation ─────────────────────────────────────────────────────

class TestSchemaValidation:
    def test_valid_entry_passes(self):
        schema = load_schema(SCHEMA_PATH)
        validate_entry(VALID_ENTRY, schema)  # should not raise

    def test_missing_ja4_raises(self):
        import jsonschema
        schema = load_schema(SCHEMA_PATH)
        entry = _make_entry()
        del entry["ja4"]
        with pytest.raises(jsonschema.ValidationError):
            validate_entry(entry, schema)

    def test_wrong_type_raises(self):
        import jsonschema
        schema = load_schema(SCHEMA_PATH)
        entry = _make_entry(alpn_present="yes")  # should be bool
        with pytest.raises(jsonschema.ValidationError):
            validate_entry(entry, schema)

    def test_extra_field_raises(self):
        import jsonschema
        schema = load_schema(SCHEMA_PATH)
        entry = _make_entry(extra_field="oops")
        with pytest.raises(jsonschema.ValidationError):
            validate_entry(entry, schema)

    def test_empty_string_ja4_raises(self):
        import jsonschema
        schema = load_schema(SCHEMA_PATH)
        entry = _make_entry(ja4="")
        with pytest.raises(jsonschema.ValidationError):
            validate_entry(entry, schema)


# ── TestSdkDispatchTable ─────────────────────────────────────────────────────

class TestSdkDispatchTable:
    REQUIRED_KEYS = {"package", "request_code", "env_vars"}

    def test_all_sdk_names_resolve_to_valid_config(self):
        for name, config in SDK_CONFIGS.items():
            missing = self.REQUIRED_KEYS - set(config.keys())
            assert not missing, f"{name!r} config missing keys: {missing}"

    def test_all_request_codes_contain_url_placeholder(self):
        for name, config in SDK_CONFIGS.items():
            assert "{url}" in config["request_code"], (
                f"{name!r} request_code missing {{url}} placeholder"
            )

    def test_all_env_vars_are_dicts(self):
        for name, config in SDK_CONFIGS.items():
            assert isinstance(config["env_vars"], dict), (
                f"{name!r} env_vars must be a dict"
            )

    def test_unknown_sdk_raises_system_exit_with_clear_message(self):
        from capture_sdk import capture
        with pytest.raises(SystemExit) as exc_info:
            capture("definitely-not-an-sdk")
        message = str(exc_info.value)
        # Must mention the unknown name and hint at valid options
        assert "definitely-not-an-sdk" in message
        assert any(k in message for k in SDK_CONFIGS)

    def test_openai_dummy_key_format(self):
        # Dummy key must start with "sk-" to pass openai client-side validation
        env = SDK_CONFIGS["openai-python"]["env_vars"]
        assert env.get("OPENAI_API_KEY", "").startswith("sk-")

    def test_anthropic_dummy_key_format(self):
        # Dummy key must start with "sk-ant-" to pass anthropic client-side validation
        env = SDK_CONFIGS["anthropic-python"]["env_vars"]
        assert env.get("ANTHROPIC_API_KEY", "").startswith("sk-ant-")


# ── TestCatalogueAppend ──────────────────────────────────────────────────────

class TestCatalogueAppend:
    def test_appends_to_empty_catalogue(self, tmp_path):
        catalogue = tmp_path / "fingerprints.json"
        catalogue.write_text("[]")
        tmp_dir = tmp_path / "capture-tmp"
        tmp_dir.mkdir()
        entry = _make_entry(ja4="t13d_new_aaa")
        (tmp_dir / "httpx-darwin.json").write_text(json.dumps(entry))

        result = merge_catalogue(tmp_dir=tmp_dir, catalogue_path=catalogue, schema_path=SCHEMA_PATH)

        assert len(result) == 1
        assert result[0]["ja4"] == "t13d_new_aaa"

    def test_duplicate_ja4_warns_and_skips(self, tmp_path, capsys):
        existing_entry = _make_entry(ja4="t13d_existing", sdk="httpx")
        catalogue = tmp_path / "fingerprints.json"
        catalogue.write_text(json.dumps([existing_entry]))

        tmp_dir = tmp_path / "capture-tmp"
        tmp_dir.mkdir()
        duplicate = _make_entry(ja4="t13d_existing", sdk="requests")  # same ja4, different sdk
        (tmp_dir / "requests-darwin.json").write_text(json.dumps(duplicate))

        result = merge_catalogue(tmp_dir=tmp_dir, catalogue_path=catalogue, schema_path=SCHEMA_PATH)

        # Entry count unchanged — duplicate was skipped
        assert len(result) == 1
        assert result[0]["sdk"] == "httpx"  # original preserved

        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "t13d_existing" in captured.out

    def test_existing_entries_preserved(self, tmp_path):
        existing_entry = _make_entry(ja4="t13d_existing_bbb", sdk="requests")
        catalogue = tmp_path / "fingerprints.json"
        catalogue.write_text(json.dumps([existing_entry]))

        tmp_dir = tmp_path / "capture-tmp"
        tmp_dir.mkdir()
        new_entry = _make_entry(ja4="t13d_brand_new_ccc", sdk="httpx")
        (tmp_dir / "httpx-darwin.json").write_text(json.dumps(new_entry))

        result = merge_catalogue(tmp_dir=tmp_dir, catalogue_path=catalogue, schema_path=SCHEMA_PATH)

        ja4s = {e["ja4"] for e in result}
        assert "t13d_existing_bbb" in ja4s
        assert "t13d_brand_new_ccc" in ja4s

    def test_atomic_write_uses_rename(self, tmp_path):
        catalogue = tmp_path / "fingerprints.json"
        catalogue.write_text("[]")

        tmp_dir = tmp_path / "capture-tmp"
        tmp_dir.mkdir()
        entry = _make_entry(ja4="t13d_atomic_ddd")
        (tmp_dir / "httpx-darwin.json").write_text(json.dumps(entry))

        replace_calls: list[tuple] = []
        original_replace = os.replace

        def recording_replace(src, dst):
            replace_calls.append((src, dst))
            return original_replace(src, dst)

        with patch("merge_catalogue.os.replace", side_effect=recording_replace):
            merge_catalogue(tmp_dir=tmp_dir, catalogue_path=catalogue, schema_path=SCHEMA_PATH)

        assert len(replace_calls) == 1
        src, dst = replace_calls[0]
        assert dst == str(catalogue)
        assert src != dst  # wrote to a temp file, then renamed

    def test_invalid_json_in_tmp_is_skipped(self, tmp_path, capsys):
        catalogue = tmp_path / "fingerprints.json"
        catalogue.write_text("[]")

        tmp_dir = tmp_path / "capture-tmp"
        tmp_dir.mkdir()
        (tmp_dir / "broken.json").write_text("not json {{{")

        result = merge_catalogue(tmp_dir=tmp_dir, catalogue_path=catalogue, schema_path=SCHEMA_PATH)

        assert result == []
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_schema_invalid_entry_in_tmp_is_skipped(self, tmp_path, capsys):
        catalogue = tmp_path / "fingerprints.json"
        catalogue.write_text("[]")

        tmp_dir = tmp_path / "capture-tmp"
        tmp_dir.mkdir()
        bad_entry = _make_entry(alpn_present="not-a-bool")  # schema violation
        (tmp_dir / "bad.json").write_text(json.dumps(bad_entry))

        result = merge_catalogue(tmp_dir=tmp_dir, catalogue_path=catalogue, schema_path=SCHEMA_PATH)

        assert result == []
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
