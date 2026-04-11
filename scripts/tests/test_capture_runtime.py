"""
test_capture_runtime.py — Unit tests for the language-runtime fingerprint capture harness.

These tests cover pure logic only — no Docker, no network, no proxy required.
Every function under test is deterministic given controlled inputs.

Tested:
  - NDJSON filter helpers (filter_ndjson_after)
  - Per-runtime metadata parsers (curl, Node.js, Go, Rust)
  - RUNTIME_CONFIGS structural invariants
  - OS label generation
  - Linux flag no-op behaviour for platform-independent runtimes
  - Schema compatibility for each runtime type (canonical entry shapes)

Not tested here (require live infrastructure):
  - capture() end-to-end — needs running Docker stack
  - wait_for_fingerprint() — polls live proxy NDJSON
  - _run_*_linux() variants — spin up Docker containers
  - _ensure_playwright_env() — downloads Chromium binaries
"""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture_runtime import (
    RUNTIME_CONFIGS,
    _parse_curl_version_output,
    _parse_go_version_output,
    _parse_node_metadata,
    _parse_rustc_version_output,
    _get_reqwest_version_from_lock,
    _get_npm_package_version,
    _os_label,
    _scaffold_rust_project,
    filter_ndjson_after,
    load_schema,
    validate_entry,
    capture,
)

# ── Helpers ──────────────────────────────────────────────────────────────────

SCHEMA_PATH = Path(__file__).resolve().parent.parent.parent / "catalogue" / "schema.json"


def _make_ndjson_line(
    ts: str,
    ja4: str = "t13d1516h2_aaa_bbb",
    alpn: list | None = None,
) -> str:
    record = {
        "ts":               ts,
        "client_ip":        "127.0.0.1",
        "ja4":              ja4,
        "client_type":      "tool",
        "detail":           "test",
        "confidence":       "high",
        "signals":          [],
        "sni":              "localhost",
        "alpn":             alpn or [],
        "cipher_count":     5,
        "extension_count":  8,
        "has_grease":       False,
        "has_ech":          False,
        "has_compress_cert": False,
        "tls_versions":     [772],
    }
    return json.dumps(record)


def _make_entry(**overrides) -> dict:
    """Return a valid catalogue entry, with optional field overrides."""
    base = {
        "runtime":             "curl",
        "runtime_version":     "8.4.0",
        "http_client":         "curl",
        "http_client_version": "8.4.0",
        "os":                  "macOS 15.0",
        "tls_library":         "LibreSSL/3.3.6",
        "ja4":                 "t13d1516h2_8daaf6152771_b0da82dd1658",
        "alpn_present":        False,
        "captured_at":         "2026-04-10T12:00:00Z",
    }
    return {**base, **overrides}


# ── TestNdjsonFilter ──────────────────────────────────────────────────────────
#
# These helpers are duplicated from capture_sdk.py. We test the copy here so
# that any divergence between the two files is caught early.

class TestNdjsonFilter:
    def test_returns_entry_after_timestamp(self):
        t = datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc)
        content = _make_ndjson_line("2026-04-10T12:00:01+00:00", ja4="t13d_match")
        result = filter_ndjson_after(content, t)
        assert result is not None
        assert result["ja4"] == "t13d_match"

    def test_ignores_entries_before_timestamp(self):
        t = datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc)
        content = _make_ndjson_line("2026-04-10T11:59:59+00:00", ja4="t13d_old")
        result = filter_ndjson_after(content, t)
        assert result is None

    def test_returns_none_on_empty_content(self):
        result = filter_ndjson_after("", datetime.now(tz=timezone.utc))
        assert result is None

    def test_returns_first_match_among_multiple(self):
        t = datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc)
        lines = "\n".join([
            _make_ndjson_line("2026-04-10T11:59:59+00:00", ja4="before"),
            _make_ndjson_line("2026-04-10T12:00:01+00:00", ja4="first_after"),
            _make_ndjson_line("2026-04-10T12:00:02+00:00", ja4="second_after"),
        ])
        result = filter_ndjson_after(lines, t)
        assert result is not None
        assert result["ja4"] == "first_after"

    def test_skips_malformed_json_lines(self):
        t = datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc)
        content = "not json {\n" + _make_ndjson_line("2026-04-10T12:00:01+00:00", ja4="ok")
        result = filter_ndjson_after(content, t)
        assert result is not None
        assert result["ja4"] == "ok"

    def test_handles_z_suffix_timestamps(self):
        """Proxy logs use "Z" suffix; fromisoformat rejects it on Python < 3.11."""
        t = datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc)
        content = _make_ndjson_line("2026-04-10T12:00:01Z", ja4="z_ts")
        result = filter_ndjson_after(content, t)
        assert result is not None
        assert result["ja4"] == "z_ts"

    def test_naive_t_treated_as_utc(self):
        """T without tzinfo should be treated as UTC, not local time."""
        t_naive = datetime(2026, 4, 10, 12, 0, 0)  # no tzinfo
        content = _make_ndjson_line("2026-04-10T12:00:01+00:00", ja4="naive_t")
        result = filter_ndjson_after(content, t_naive)
        assert result is not None

    def test_entry_at_exact_timestamp_is_included(self):
        """ts == T is considered a match (>= comparison)."""
        t = datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc)
        content = _make_ndjson_line("2026-04-10T12:00:00+00:00", ja4="exact")
        result = filter_ndjson_after(content, t)
        assert result is not None
        assert result["ja4"] == "exact"

    def test_skips_lines_missing_ts_field(self):
        """Lines without a 'ts' key should be silently skipped."""
        t = datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc)
        no_ts = json.dumps({"ja4": "no-ts", "client_type": "tool"})
        good  = _make_ndjson_line("2026-04-10T12:00:01+00:00", ja4="has-ts")
        result = filter_ndjson_after(f"{no_ts}\n{good}", t)
        assert result is not None
        assert result["ja4"] == "has-ts"

    def test_alpn_field_preserved_in_returned_entry(self):
        """The full entry dict is returned so callers can read alpn and other fields."""
        t = datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc)
        content = _make_ndjson_line(
            "2026-04-10T12:00:01+00:00", ja4="alpn_test", alpn=["h2", "http/1.1"]
        )
        result = filter_ndjson_after(content, t)
        assert result is not None
        assert result["alpn"] == ["h2", "http/1.1"]


# ── TestCurlMetadataParsing ───────────────────────────────────────────────────

class TestCurlMetadataParsing:
    def test_parses_libressl_macos(self):
        output = "curl 8.4.0 (x86_64-apple-darwin23.0) libcurl/8.4.0 LibreSSL/3.3.6 zlib/1.2.11\n"
        version, tls_library = _parse_curl_version_output(output)
        assert version == "8.4.0"
        assert tls_library == "LibreSSL/3.3.6"

    def test_parses_openssl_linux(self):
        output = "curl 7.88.1 (x86_64-pc-linux-gnu) libcurl/7.88.1 OpenSSL/3.0.11 zlib/1.2.13\n"
        version, tls_library = _parse_curl_version_output(output)
        assert version == "7.88.1"
        assert tls_library == "OpenSSL/3.0.11"

    def test_parses_nss(self):
        output = "curl 7.76.1 (x86_64-redhat-linux-gnu) libcurl/7.76.1 NSS/3.67\n"
        version, tls_library = _parse_curl_version_output(output)
        assert tls_library == "NSS/3.67"

    def test_parses_gnutls(self):
        output = "curl 7.74.0 (x86_64-pc-linux-gnu) libcurl/7.74.0 GnuTLS/3.7.1\n"
        version, tls_library = _parse_curl_version_output(output)
        assert tls_library == "GnuTLS/3.7.1"

    def test_returns_unknown_on_empty_output(self):
        version, tls_library = _parse_curl_version_output("")
        assert version == "unknown"
        assert tls_library == "unknown"

    def test_returns_unknown_tls_on_unrecognised_format(self):
        # Real version present but no recognised TLS library token.
        output = "curl 8.0.0 (arm64-apple-darwin) libcurl/8.0.0 zlib/1.2.11\n"
        version, tls_library = _parse_curl_version_output(output)
        assert version == "8.0.0"
        assert tls_library == "unknown"

    def test_handles_multiline_output(self):
        """Only the first line is parsed; subsequent feature lines are ignored."""
        output = (
            "curl 8.4.0 (x86_64-apple-darwin23.0) libcurl/8.4.0 LibreSSL/3.3.6\n"
            "Release-Date: 2023-10-11\n"
            "Protocols: dict file ftp ftps gopher ...\n"
        )
        version, tls_library = _parse_curl_version_output(output)
        assert version == "8.4.0"
        assert tls_library == "LibreSSL/3.3.6"


# ── TestNodeMetadataParsing ───────────────────────────────────────────────────

class TestNodeMetadataParsing:
    def test_strips_v_prefix_from_version(self):
        version, _ = _parse_node_metadata("v20.11.0\n", "3.1.4\n")
        assert version == "20.11.0"

    def test_version_without_v_prefix(self):
        version, _ = _parse_node_metadata("20.11.0", "3.1.4")
        assert version == "20.11.0"

    def test_formats_openssl_tls_library(self):
        _, tls = _parse_node_metadata("v20.11.0", "3.1.4")
        assert tls == "OpenSSL/3.1.4"

    def test_strips_quic_suffix_from_openssl(self):
        """Some Node.js builds append '+quic' to the OpenSSL version."""
        _, tls = _parse_node_metadata("v20.11.0", "3.1.4+quic\n")
        assert tls == "OpenSSL/3.1.4"

    def test_unknown_on_empty_version(self):
        version, _ = _parse_node_metadata("", "3.1.4")
        assert version == "unknown"

    def test_unknown_on_empty_openssl(self):
        _, tls = _parse_node_metadata("v20.11.0", "")
        assert tls == "unknown"

    def test_whitespace_stripped_from_both_fields(self):
        version, tls = _parse_node_metadata("  v18.0.0  ", "  1.1.1w  ")
        assert version == "18.0.0"
        assert tls == "OpenSSL/1.1.1w"


# ── TestGoMetadataParsing ─────────────────────────────────────────────────────

class TestGoMetadataParsing:
    def test_parses_go_version_darwin(self):
        output = "go version go1.22.0 darwin/arm64\n"
        version, tls = _parse_go_version_output(output)
        assert version == "1.22.0"
        assert tls == "go crypto/tls 1.22.0"

    def test_parses_go_version_linux(self):
        output = "go version go1.21.6 linux/amd64\n"
        version, tls = _parse_go_version_output(output)
        assert version == "1.21.6"
        assert tls == "go crypto/tls 1.21.6"

    def test_parses_two_part_version(self):
        """Some releases have major.minor without patch (e.g. go1.21 beta)."""
        output = "go version go1.21 linux/amd64\n"
        version, tls = _parse_go_version_output(output)
        assert version == "1.21"
        assert "1.21" in tls

    def test_returns_unknown_on_empty_output(self):
        version, tls = _parse_go_version_output("")
        assert version == "unknown"
        assert tls == "unknown"

    def test_returns_unknown_on_unexpected_format(self):
        version, tls = _parse_go_version_output("some unexpected output\n")
        assert version == "unknown"

    def test_tls_library_always_references_crypto_tls(self):
        """Crucial: Go does NOT use OpenSSL. The label must be explicit."""
        output = "go version go1.22.0 linux/amd64\n"
        _, tls = _parse_go_version_output(output)
        assert "crypto/tls" in tls
        assert "OpenSSL" not in tls


# ── TestRustMetadataParsing ───────────────────────────────────────────────────

class TestRustMetadataParsing:
    def test_parses_rustc_version(self):
        output = "rustc 1.75.0 (82e1608df 2023-12-21)\n"
        assert _parse_rustc_version_output(output) == "1.75.0"

    def test_returns_unknown_on_empty_output(self):
        assert _parse_rustc_version_output("") == "unknown"

    def test_returns_unknown_on_unexpected_format(self):
        assert _parse_rustc_version_output("cargo 1.75.0") == "unknown"

    def test_extracts_reqwest_version_from_cargo_lock(self, tmp_path):
        """Simulates a real Cargo.lock fragment."""
        lock = tmp_path / "Cargo.lock"
        lock.write_text(
            "# This file is automatically @generated by Cargo.\n"
            "version = 3\n\n"
            "[[package]]\n"
            'name = "bitflags"\n'
            'version = "2.4.2"\n\n'
            "[[package]]\n"
            'name = "reqwest"\n'
            'version = "0.12.3"\n'
            'source = "registry+..."\n'
        )
        result = _get_reqwest_version_from_lock(str(tmp_path))
        assert result == "0.12.3"

    def test_returns_unknown_when_reqwest_absent_from_lock(self, tmp_path):
        lock = tmp_path / "Cargo.lock"
        lock.write_text(
            "[[package]]\n"
            'name = "serde"\n'
            'version = "1.0.195"\n'
        )
        result = _get_reqwest_version_from_lock(str(tmp_path))
        assert result == "unknown"

    def test_returns_unknown_when_lock_file_missing(self, tmp_path):
        result = _get_reqwest_version_from_lock(str(tmp_path))
        assert result == "unknown"

    def test_handles_multiple_packages_before_reqwest(self, tmp_path):
        """reqwest should be found even when many other packages precede it."""
        lock = tmp_path / "Cargo.lock"
        packages = ""
        for i in range(20):
            packages += f'[[package]]\nname = "pkg{i}"\nversion = "1.0.{i}"\n\n'
        packages += '[[package]]\nname = "reqwest"\nversion = "0.12.5"\n'
        lock.write_text(packages)
        assert _get_reqwest_version_from_lock(str(tmp_path)) == "0.12.5"


# ── TestNpmPackageVersion ─────────────────────────────────────────────────────

class TestNpmPackageVersion:
    def test_reads_version_from_package_json(self, tmp_path):
        node_modules = tmp_path / "node_modules" / "axios"
        node_modules.mkdir(parents=True)
        (node_modules / "package.json").write_text(json.dumps({"version": "1.6.7"}))
        result = _get_npm_package_version(str(tmp_path), "axios")
        assert result == "1.6.7"

    def test_returns_unknown_when_package_json_missing(self, tmp_path):
        result = _get_npm_package_version(str(tmp_path), "nonexistent")
        assert result == "unknown"

    def test_returns_unknown_on_malformed_json(self, tmp_path):
        node_modules = tmp_path / "node_modules" / "axios"
        node_modules.mkdir(parents=True)
        (node_modules / "package.json").write_text("not json {{{")
        result = _get_npm_package_version(str(tmp_path), "axios")
        assert result == "unknown"

    def test_returns_unknown_when_version_key_absent(self, tmp_path):
        node_modules = tmp_path / "node_modules" / "axios"
        node_modules.mkdir(parents=True)
        (node_modules / "package.json").write_text(json.dumps({"name": "axios"}))
        result = _get_npm_package_version(str(tmp_path), "axios")
        assert result == "unknown"


# ── TestOsLabel ───────────────────────────────────────────────────────────────

class TestOsLabel:
    def test_linux_returns_linux(self):
        with patch("capture_runtime.platform.system", return_value="Linux"):
            assert _os_label() == "Linux"

    def test_darwin_includes_macos_prefix(self):
        with (
            patch("capture_runtime.platform.system", return_value="Darwin"),
            patch("capture_runtime.platform.mac_ver", return_value=("15.0", ("", "", ""), "")),
        ):
            label = _os_label()
            assert label.startswith("macOS")
            assert "15.0" in label

    def test_darwin_without_version_falls_back(self):
        with (
            patch("capture_runtime.platform.system", return_value="Darwin"),
            patch("capture_runtime.platform.mac_ver", return_value=("", ("", "", ""), "")),
        ):
            label = _os_label()
            # Should still produce a non-empty string with macOS in it.
            assert "macOS" in label

    def test_unknown_platform_returns_system_name(self):
        with patch("capture_runtime.platform.system", return_value="FreeBSD"):
            assert _os_label() == "FreeBSD"


# ── TestRuntimeConfigs ────────────────────────────────────────────────────────

class TestRuntimeConfigs:
    REQUIRED_KEYS = {
        "runner", "runtime", "http_client", "client_type", "description",
        "linux_supported", "docker_image",
    }
    NODE_REQUIRED_KEYS = REQUIRED_KEYS | {"npm_package", "script"}

    def test_all_runtimes_have_required_keys(self):
        for name, cfg in RUNTIME_CONFIGS.items():
            required = self.NODE_REQUIRED_KEYS if cfg.get("runner") == "node" else self.REQUIRED_KEYS
            missing = required - set(cfg.keys())
            assert not missing, f"{name!r} config missing keys: {missing}"

    def test_runner_values_are_valid(self):
        valid_runners = {"curl", "node", "go", "rust", "browser"}
        for name, cfg in RUNTIME_CONFIGS.items():
            assert cfg["runner"] in valid_runners, (
                f"{name!r} has unknown runner '{cfg['runner']}'"
            )

    def test_linux_supported_is_boolean(self):
        for name, cfg in RUNTIME_CONFIGS.items():
            assert isinstance(cfg["linux_supported"], bool), (
                f"{name!r} linux_supported must be bool"
            )

    def test_linux_unsupported_runtimes_have_no_docker_image(self):
        """Platform-independent runtimes should not specify a docker_image."""
        for name, cfg in RUNTIME_CONFIGS.items():
            if not cfg["linux_supported"]:
                assert cfg["docker_image"] is None, (
                    f"{name!r} is platform-independent but specifies docker_image"
                )

    def test_linux_supported_runtimes_have_docker_image(self):
        """Runtimes that support Linux capture must specify which Docker image to use."""
        for name, cfg in RUNTIME_CONFIGS.items():
            if cfg["linux_supported"]:
                assert cfg["docker_image"] is not None, (
                    f"{name!r} linux_supported=True but docker_image is None"
                )

    def test_node_scripts_contain_url_placeholder(self):
        for name, cfg in RUNTIME_CONFIGS.items():
            if cfg["runner"] == "node":
                assert "{url}" in cfg["script"], (
                    f"{name!r} script missing {{url}} placeholder"
                )

    def test_descriptions_are_non_empty_strings(self):
        for name, cfg in RUNTIME_CONFIGS.items():
            assert isinstance(cfg["description"], str) and cfg["description"], (
                f"{name!r} description must be a non-empty string"
            )

    def test_runtime_and_http_client_are_non_empty(self):
        for name, cfg in RUNTIME_CONFIGS.items():
            assert cfg["runtime"], f"{name!r} runtime label is empty"
            assert cfg["http_client"], f"{name!r} http_client label is empty"

    def test_go_and_rust_use_platform_independent_runners(self):
        """Confirms our assumptions about which runtimes are platform-independent."""
        assert not RUNTIME_CONFIGS["go-net-http"]["linux_supported"]
        assert not RUNTIME_CONFIGS["rust-reqwest"]["linux_supported"]

    def test_curl_and_node_are_linux_supported(self):
        """These runtimes use system OpenSSL on Linux — linux_supported must be True."""
        assert RUNTIME_CONFIGS["curl"]["linux_supported"]
        assert RUNTIME_CONFIGS["node-https"]["linux_supported"]
        assert RUNTIME_CONFIGS["node-fetch"]["linux_supported"]
        assert RUNTIME_CONFIGS["node-axios"]["linux_supported"]


# ── TestLinuxFlagBehavior ─────────────────────────────────────────────────────

class TestLinuxFlagBehavior:
    """
    For platform-independent runtimes, --linux should emit a clear warning and
    fall back to native execution. We verify this via the capture() function's
    early-exit path (it checks linux_supported before dispatching to a runner).

    We patch the actual runner functions to avoid needing live infrastructure.
    """

    def _run_capture_with_linux_flag(
        self, runtime_name: str, mock_runner_fn: str
    ) -> tuple[bool, str]:
        """
        Call capture(runtime_name, linux=True) with the runner patched.
        Returns (linux_arg_received, printed_output).
        """
        linux_received = []

        def fake_runner(config, platform_label):
            linux_received.append(False)  # capture() normalised linux to False
            return _make_entry(
                runtime=config["runtime"],
                http_client=config["http_client"],
            )

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()

        with (
            patch(f"capture_runtime.{mock_runner_fn}", side_effect=fake_runner),
            patch("capture_runtime.validate_entry"),
            patch("capture_runtime.CAPTURE_TMP_DIR") as mock_tmp,
            redirect_stdout(buf),
        ):
            mock_tmp.__truediv__ = lambda *a: Path("/tmp/fake.json")
            mock_tmp.mkdir = lambda **kw: None
            try:
                capture(runtime_name, linux=True)
            except Exception:
                pass

        return buf.getvalue()

    def test_go_linux_flag_emits_warning(self, capsys):
        with (
            patch("capture_runtime._capture_go", return_value=_make_entry()),
            patch("capture_runtime.validate_entry"),
            patch("capture_runtime.CAPTURE_TMP_DIR") as mock_dir,
            patch("capture_runtime.shutil.which", return_value="/usr/bin/go"),
        ):
            mock_path = Path("/tmp/fake.json")
            mock_dir.__truediv__ = lambda *a: mock_path
            mock_dir.mkdir = lambda **kw: None
            mock_path_instance = mock_path
            with patch.object(mock_path_instance.__class__, "write_text", lambda *a, **kw: None):
                try:
                    capture("go-net-http", linux=True)
                except Exception:
                    pass
        captured = capsys.readouterr()
        assert "NOTE" in captured.out
        assert "platform-independent" in captured.out or "no effect" in captured.out

    def test_rust_linux_flag_emits_warning(self, capsys):
        with (
            patch("capture_runtime._capture_rust", return_value=_make_entry()),
            patch("capture_runtime.validate_entry"),
            patch("capture_runtime.CAPTURE_TMP_DIR") as mock_dir,
            patch("capture_runtime.shutil.which", return_value="/usr/bin/cargo"),
        ):
            mock_dir.__truediv__ = lambda *a: Path("/tmp/fake.json")
            mock_dir.mkdir = lambda **kw: None
            try:
                capture("rust-reqwest", linux=True)
            except Exception:
                pass
        captured = capsys.readouterr()
        assert "NOTE" in captured.out


# ── TestUnknownRuntime ────────────────────────────────────────────────────────

class TestUnknownRuntime:
    def test_exits_with_clear_message_for_unknown_runtime(self):
        with pytest.raises(SystemExit) as exc_info:
            capture("definitely-not-a-runtime")
        message = str(exc_info.value)
        assert "definitely-not-a-runtime" in message
        # Must list at least some valid names so user knows what to use.
        assert any(k in message for k in RUNTIME_CONFIGS)

    def test_exits_mentioning_all_valid_names(self):
        with pytest.raises(SystemExit) as exc_info:
            capture("oops")
        message = str(exc_info.value)
        for name in RUNTIME_CONFIGS:
            assert name in message, f"Valid runtime '{name}' not in error message"


# ── TestRustProjectScaffolding ────────────────────────────────────────────────

class TestRustProjectScaffolding:
    def test_writes_cargo_toml(self, tmp_path):
        _scaffold_rust_project(str(tmp_path), "https://localhost:8443")
        cargo_toml = tmp_path / "Cargo.toml"
        assert cargo_toml.exists()
        content = cargo_toml.read_text()
        assert "reqwest" in content
        assert "blocking" in content

    def test_writes_main_rs_with_url(self, tmp_path):
        url = "https://localhost:8443"
        _scaffold_rust_project(str(tmp_path), url)
        main_rs = tmp_path / "src" / "main.rs"
        assert main_rs.exists()
        content = main_rs.read_text()
        assert url in content

    def test_main_rs_uses_danger_accept_invalid_certs(self, tmp_path):
        """The test harness hits localhost with a self-signed cert."""
        _scaffold_rust_project(str(tmp_path), "https://localhost:8443")
        main_rs = (tmp_path / "src" / "main.rs").read_text()
        assert "danger_accept_invalid_certs" in main_rs

    def test_cargo_toml_specifies_reqwest_blocking_feature(self, tmp_path):
        _scaffold_rust_project(str(tmp_path), "https://localhost:8443")
        content = (tmp_path / "Cargo.toml").read_text()
        # Confirm blocking feature is declared — without it, cargo build will fail.
        assert '"blocking"' in content or "'blocking'" in content

    def test_different_urls_produce_different_main_rs(self, tmp_path):
        url_a = "https://localhost:8443"
        url_b = "https://host.docker.internal:8443"
        tmp_a, tmp_b = tmp_path / "a", tmp_path / "b"
        tmp_a.mkdir(), tmp_b.mkdir()
        _scaffold_rust_project(str(tmp_a), url_a)
        _scaffold_rust_project(str(tmp_b), url_b)
        assert url_a in (tmp_a / "src" / "main.rs").read_text()
        assert url_b in (tmp_b / "src" / "main.rs").read_text()


# ── TestSchemaCompatibility ───────────────────────────────────────────────────
#
# Validates that a well-formed catalogue entry for each runtime type passes
# the shared catalogue schema. This guards against schema drift (e.g. adding
# a required field to schema.json without updating the harness entry dict).

class TestSchemaCompatibility:
    RUNTIME_ENTRIES = {
        "curl": _make_entry(
            runtime="curl", runtime_version="8.4.0",
            http_client="curl", http_client_version="8.4.0",
            tls_library="LibreSSL/3.3.6",
            client_type="tool",
        ),
        "node-https": _make_entry(
            runtime="node", runtime_version="20.11.0",
            http_client="https", http_client_version="20.11.0",
            tls_library="OpenSSL/3.1.4",
            client_type="tool",
        ),
        "node-fetch": _make_entry(
            runtime="node", runtime_version="20.11.0",
            http_client="fetch", http_client_version="20.11.0",
            tls_library="OpenSSL/3.1.4",
            client_type="tool",
        ),
        "node-axios": _make_entry(
            runtime="node", runtime_version="20.11.0",
            http_client="axios", http_client_version="1.6.7",
            tls_library="OpenSSL/3.1.4",
            client_type="tool",
        ),
        "go-net-http": _make_entry(
            runtime="go", runtime_version="1.22.0",
            http_client="net/http", http_client_version="1.22.0",
            tls_library="go crypto/tls 1.22.0",
            client_type="tool",
        ),
        "rust-reqwest": _make_entry(
            runtime="rust", runtime_version="1.75.0",
            http_client="reqwest", http_client_version="0.12.3",
            tls_library="rustls",
            client_type="tool",
        ),
        "chrome-playwright": _make_entry(
            runtime="chromium", runtime_version="120.0.6099.28",
            http_client="chromium", http_client_version="120.0.6099.28",
            tls_library="BoringSSL",
            client_type="headless",
        ),
    }

    @pytest.mark.parametrize("runtime_name", list(RUNTIME_ENTRIES.keys()))
    def test_entry_passes_schema(self, runtime_name):
        """Every runtime's canonical entry shape must pass catalogue/schema.json."""
        schema = load_schema(SCHEMA_PATH)
        entry  = self.RUNTIME_ENTRIES[runtime_name]
        validate_entry(entry, schema)  # raises on failure

    def test_all_runtime_configs_have_a_schema_compatibility_fixture(self):
        """Fail loudly if a new runtime is added to RUNTIME_CONFIGS without a fixture here."""
        missing = set(RUNTIME_CONFIGS.keys()) - set(self.RUNTIME_ENTRIES.keys())
        assert not missing, (
            f"TestSchemaCompatibility has no fixture for: {missing}. "
            "Add a RUNTIME_ENTRIES entry for each new runtime."
        )

    def test_go_entry_tls_library_does_not_reference_openssl(self):
        """Explicitly assert the platform-independence claim is reflected in the entry."""
        entry = self.RUNTIME_ENTRIES["go-net-http"]
        assert "OpenSSL" not in entry["tls_library"]
        assert "crypto/tls" in entry["tls_library"]

    def test_rust_entry_tls_library_is_rustls(self):
        entry = self.RUNTIME_ENTRIES["rust-reqwest"]
        assert entry["tls_library"] == "rustls"

    def test_browser_entry_tls_library_is_boringssl(self):
        entry = self.RUNTIME_ENTRIES["chrome-playwright"]
        assert entry["tls_library"] == "BoringSSL"


# ── TestClientTypeField ───────────────────────────────────────────────────────
#
# Validates that the client_type field is present in RUNTIME_CONFIGS, that
# each runtime declares the correct value, and that entries with client_type
# pass the catalogue schema.

class TestClientTypeField:
    def test_all_runtime_configs_define_client_type(self):
        """Every runtime must declare client_type — it drives proxy routing."""
        for name, cfg in RUNTIME_CONFIGS.items():
            assert "client_type" in cfg, (
                f"{name!r} is missing 'client_type' in RUNTIME_CONFIGS"
            )

    def test_client_type_values_are_valid(self):
        valid = {"agent", "tool", "headless", "browser", "unknown"}
        for name, cfg in RUNTIME_CONFIGS.items():
            assert cfg["client_type"] in valid, (
                f"{name!r} has invalid client_type '{cfg['client_type']}'"
            )

    def test_curl_is_tool(self):
        assert RUNTIME_CONFIGS["curl"]["client_type"] == "tool"

    def test_node_runtimes_are_tool(self):
        for name in ("node-https", "node-fetch", "node-axios"):
            assert RUNTIME_CONFIGS[name]["client_type"] == "tool", (
                f"{name!r} should be 'tool' (baseline Node.js TLS stack, not an AI agent)"
            )

    def test_go_is_tool(self):
        assert RUNTIME_CONFIGS["go-net-http"]["client_type"] == "tool"

    def test_rust_is_tool(self):
        assert RUNTIME_CONFIGS["rust-reqwest"]["client_type"] == "tool"

    def test_browser_is_headless(self):
        assert RUNTIME_CONFIGS["chrome-playwright"]["client_type"] == "headless"

    def test_entry_with_client_type_passes_schema(self):
        """Schema must accept the client_type field (it was absent in the original schema)."""
        schema = load_schema(SCHEMA_PATH)
        entry = _make_entry(client_type="tool")
        validate_entry(entry, schema)

    def test_entry_with_headless_client_type_passes_schema(self):
        schema = load_schema(SCHEMA_PATH)
        entry = _make_entry(client_type="headless")
        validate_entry(entry, schema)

    def test_entry_with_invalid_client_type_fails_schema(self):
        """Schema enum must reject unknown values — no silent misclassification."""
        import jsonschema
        schema = load_schema(SCHEMA_PATH)
        entry = _make_entry(client_type="not-a-real-type")
        with pytest.raises(jsonschema.ValidationError):
            validate_entry(entry, schema)

    def test_entry_without_client_type_still_passes_schema(self):
        """
        client_type is optional — entries captured before the field was added
        must remain valid (backward compatibility).
        """
        schema = load_schema(SCHEMA_PATH)
        entry = {k: v for k, v in _make_entry().items() if k != "client_type"}
        validate_entry(entry, schema)  # must not raise
