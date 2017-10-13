import pytest
from warcprox.dedup import CdxServerDedup


def test_cdx():
    # TODO add mocking of CDX Server response
    # TODO check found and not found cases
    cdx_server = CdxServerDedup(cdx_url="https://web.archive.org/cdx/search/cdx")
    res = cdx_server.lookup(digest_key="B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A",
                            url="http://example.com")
