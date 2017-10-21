import mock
from warcprox.dedup import CdxServerDedup


def test_cdx_dedup():
    # Mock CDX Server responses to simulate found, not found and errors.
    with mock.patch('warcprox.dedup.CdxServerDedup.http_pool.request') as request:
        url = "http://example.com"
        # not found case
        result = mock.Mock()
        result.status = 200
        result.data = b'20170101020405 test'
        request.return_value = result
        cdx_server = CdxServerDedup(cdx_url="dummy-cdx-server-url")
        res = cdx_server.lookup(digest_key="B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A",
                                url=url)
        assert res is None

        # found case
        result = mock.Mock()
        result.status = 200
        result.data = b'20170203040503 B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A'
        request.return_value = result
        cdx_server = CdxServerDedup(cdx_url="dummy-cdx-server-url")
        res = cdx_server.lookup(digest_key="B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A",
                                url=url)
        assert res["date"] == b"2017-02-03T04:05:03Z"

        # invalid CDX result status code
        result = mock.Mock()
        result.status = 400
        result.data = b'20170101020405 B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A'
        request.return_value = result
        cdx_server = CdxServerDedup(cdx_url="dummy-cdx-server-url")
        res = cdx_server.lookup(digest_key="B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A",
                                url=url)
        assert res is None
        # invalid CDX result content
        result = mock.Mock()
        result.status = 200
        result.data = b'InvalidExceptionResult'
        request.return_value = result
        cdx_server = CdxServerDedup(cdx_url="dummy-cdx-server-url")
        res = cdx_server.lookup(digest_key="B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A",
                                url=url)
        assert res is None
