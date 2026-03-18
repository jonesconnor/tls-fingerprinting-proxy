"""
Tests for ja4.py — JA4 fingerprint computation.

Tests are grouped into:
  - _alpn_chars helper (boundary cases)
  - compute_ja4 Part A (structure and field encoding)
  - compute_ja4 Part B (cipher suite hash)
  - compute_ja4 Part C (extension + signature algorithm hash)
  - GREASE exclusion
  - compute_ja4_raw (key presence)
"""

import hashlib

from ja4 import _alpn_chars, compute_ja4, compute_ja4_raw


def _sha256_prefix(s: str, n: int = 12) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:n]


# ---------------------------------------------------------------------------
# _alpn_chars
# ---------------------------------------------------------------------------

class TestAlpnChars:
    def test_h2(self):
        assert _alpn_chars("h2") == "h2"

    def test_http11(self):
        # first + last char of "http/1.1"
        assert _alpn_chars("http/1.1") == "h1"

    def test_none(self):
        assert _alpn_chars(None) == "00"

    def test_empty_string(self):
        # empty string has no first/last — treated as falsy
        assert _alpn_chars("") == "00"

    def test_single_char(self):
        # single char is doubled
        assert _alpn_chars("x") == "xx"

    def test_spdy(self):
        assert _alpn_chars("spdy/3.1") == "s1"


# ---------------------------------------------------------------------------
# compute_ja4 — output format
# ---------------------------------------------------------------------------

class TestJA4OutputFormat:
    def test_three_parts(self, make_ch):
        ja4 = compute_ja4(make_ch())
        assert ja4.count("_") == 2

    def test_part_a_length(self, make_ch):
        part_a = compute_ja4(make_ch()).split("_")[0]
        assert len(part_a) == 10

    def test_part_b_is_12_hex_chars(self, make_ch):
        part_b = compute_ja4(make_ch()).split("_")[1]
        assert len(part_b) == 12
        assert all(c in "0123456789abcdef" for c in part_b)

    def test_part_c_is_12_hex_chars(self, make_ch):
        part_c = compute_ja4(make_ch()).split("_")[2]
        assert len(part_c) == 12
        assert all(c in "0123456789abcdef" for c in part_c)


# ---------------------------------------------------------------------------
# compute_ja4 — Part A field encoding
# ---------------------------------------------------------------------------

class TestJA4PartA:
    def test_transport_is_t_for_tcp(self, make_ch):
        assert compute_ja4(make_ch()).split("_")[0][0] == "t"

    def test_tls13_version(self, make_ch):
        ch = make_ch(supported_versions=[0x0304])
        assert compute_ja4(ch).split("_")[0][1:3] == "13"

    def test_tls12_version(self, make_ch):
        ch = make_ch(supported_versions=[0x0303])
        assert compute_ja4(ch).split("_")[0][1:3] == "12"

    def test_tls11_version(self, make_ch):
        ch = make_ch(supported_versions=[0x0302])
        assert compute_ja4(ch).split("_")[0][1:3] == "11"

    def test_sni_present_gives_d(self, make_ch):
        ch = make_ch(sni="example.com")
        assert compute_ja4(ch).split("_")[0][3] == "d"

    def test_no_sni_gives_i(self, make_ch):
        ch = make_ch(sni=None)
        assert compute_ja4(ch).split("_")[0][3] == "i"

    def test_cipher_count_zero_padded(self, make_ch):
        ch = make_ch(cipher_suites=[0x1301, 0x1302, 0x1303])
        assert compute_ja4(ch).split("_")[0][4:6] == "03"

    def test_cipher_count_two_digits(self, make_ch):
        ch = make_ch(cipher_suites=list(range(0x1301, 0x1311)))  # 16 ciphers
        assert compute_ja4(ch).split("_")[0][4:6] == "16"

    def test_cipher_count_capped_at_99(self, make_ch):
        ch = make_ch(cipher_suites=list(range(0x0001, 0x0066)))  # 101 ciphers
        assert compute_ja4(ch).split("_")[0][4:6] == "99"

    def test_extension_count(self, make_ch):
        # default fixture has 3 extensions; SNI(0000) and ALPN(0010) are
        # counted if present — all extension types are counted in part A
        ch = make_ch(extension_types=[0x0000, 0x000d, 0x002b, 0x0017])
        assert compute_ja4(ch).split("_")[0][6:8] == "04"

    def test_alpn_h2(self, make_ch):
        ch = make_ch(alpn_protocols=["h2"])
        assert compute_ja4(ch).split("_")[0][8:] == "h2"

    def test_alpn_http11(self, make_ch):
        ch = make_ch(alpn_protocols=["http/1.1"])
        assert compute_ja4(ch).split("_")[0][8:] == "h1"

    def test_alpn_absent(self, make_ch):
        ch = make_ch(alpn_protocols=[])
        assert compute_ja4(ch).split("_")[0][8:] == "00"

    def test_alpn_uses_first_protocol(self, make_ch):
        # when multiple protocols are advertised, first one is used
        ch = make_ch(alpn_protocols=["h2", "http/1.1"])
        assert compute_ja4(ch).split("_")[0][8:] == "h2"


# ---------------------------------------------------------------------------
# compute_ja4 — Part B (cipher suite hash)
# ---------------------------------------------------------------------------

class TestJA4PartB:
    def test_part_b_is_sha256_of_sorted_ciphers(self, make_ch):
        ch = make_ch(cipher_suites=[0x1303, 0x1301, 0x1302])
        part_b = compute_ja4(ch).split("_")[1]
        expected = _sha256_prefix("1301,1302,1303")
        assert part_b == expected

    def test_cipher_order_does_not_affect_part_b(self, make_ch):
        ch_asc  = make_ch(cipher_suites=[0x1301, 0x1302, 0x1303])
        ch_desc = make_ch(cipher_suites=[0x1303, 0x1302, 0x1301])
        assert compute_ja4(ch_asc).split("_")[1] == compute_ja4(ch_desc).split("_")[1]


# ---------------------------------------------------------------------------
# compute_ja4 — Part C (extension + signature algorithm hash)
# ---------------------------------------------------------------------------

class TestJA4PartC:
    def test_sni_and_alpn_excluded_from_part_c(self, make_ch):
        # SNI (0x0000) and ALPN (0x0010) are excluded from the Part C hash;
        # only 0x000d remains, so ext_str = "000d"
        ch = make_ch(
            extension_types=[0x0000, 0x0010, 0x000d],
            signature_algorithms=[0x0403],
        )
        part_c = compute_ja4(ch).split("_")[2]
        expected = _sha256_prefix("000d_0403")
        assert part_c == expected

    def test_part_c_includes_sig_algs_in_original_order(self, make_ch):
        ch = make_ch(
            extension_types=[0x000d],
            signature_algorithms=[0x0804, 0x0403],  # not sorted
        )
        part_c = compute_ja4(ch).split("_")[2]
        expected = _sha256_prefix("000d_0804,0403")
        assert part_c == expected

    def test_empty_sig_algs(self, make_ch):
        ch = make_ch(
            extension_types=[0x000d],
            signature_algorithms=[],
        )
        part_c = compute_ja4(ch).split("_")[2]
        expected = _sha256_prefix("000d_")
        assert part_c == expected


# ---------------------------------------------------------------------------
# GREASE exclusion
# ---------------------------------------------------------------------------

class TestGREASEExclusion:
    GREASE = 0x0a0a

    def test_grease_cipher_excluded_from_count(self, make_ch):
        # 3 real ciphers + 1 GREASE cipher → count should be 03
        ch = make_ch(cipher_suites=[0x1301, 0x1302, 0x1303, self.GREASE])
        assert compute_ja4(ch).split("_")[0][4:6] == "03"

    def test_grease_extension_excluded_from_count(self, make_ch):
        # 3 real extensions + 1 GREASE → count should be 03
        ch = make_ch(extension_types=[0x0000, 0x000d, 0x002b, self.GREASE])
        assert compute_ja4(ch).split("_")[0][6:8] == "03"

    def test_grease_does_not_affect_hash(self, make_ch):
        # A fingerprint with GREASE values should hash identically to one without
        ch_plain = make_ch(
            cipher_suites=[0x1301, 0x1302],
            extension_types=[0x000d],
        )
        ch_grease = make_ch(
            cipher_suites=[0x1301, 0x1302, self.GREASE],
            extension_types=[0x000d, self.GREASE],
            has_grease=True,
        )
        assert compute_ja4(ch_plain) == compute_ja4(ch_grease)


# ---------------------------------------------------------------------------
# compute_ja4_raw — key presence
# ---------------------------------------------------------------------------

class TestJA4Raw:
    EXPECTED_KEYS = {
        "tls_version", "tls_version_raw", "sni",
        "cipher_suites", "cipher_suites_sorted", "num_ciphers",
        "extension_types_ordered", "extension_types_for_hash", "num_extensions",
        "alpn_protocols", "alpn_chars",
        "signature_algorithms", "supported_groups",
        "has_grease", "has_ech", "has_compress_certificate", "parse_error",
    }

    def test_all_keys_present(self, make_ch):
        raw = compute_ja4_raw(make_ch())
        assert self.EXPECTED_KEYS == set(raw.keys())

    def test_cipher_suites_sorted_is_sorted(self, make_ch):
        ch = make_ch(cipher_suites=[0x1303, 0x1301, 0x1302])
        raw = compute_ja4_raw(ch)
        assert raw["cipher_suites_sorted"] == ["1301", "1302", "1303"]

    def test_num_ciphers_excludes_grease(self, make_ch):
        ch = make_ch(cipher_suites=[0x1301, 0x1302, 0x0a0a])
        raw = compute_ja4_raw(ch)
        assert raw["num_ciphers"] == 2
