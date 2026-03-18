"""
Shared test fixtures.
"""

import pytest

from tls_parser import ClientHelloInfo


@pytest.fixture
def make_ch():
    """
    Factory fixture for ClientHelloInfo. Call with keyword overrides:

        ch = make_ch(has_grease=True, cipher_suites=[0x1301])
    """
    def _make(**kwargs) -> ClientHelloInfo:
        defaults = dict(
            cipher_suites=[0x1301, 0x1302, 0x1303],
            extension_types=[0x0000, 0x000d, 0x002b],
            sni="example.com",
            alpn_protocols=["h2"],
            supported_versions=[0x0304],
            signature_algorithms=[0x0403, 0x0804],
            supported_groups=[0x001d, 0x0017],
            has_grease=False,
            has_ech=False,
            has_compress_cert=False,
            legacy_version=0x0303,
        )
        defaults.update(kwargs)
        return ClientHelloInfo(**defaults)

    return _make
