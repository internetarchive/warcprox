import datetime
import mock
import pytest
from warcprox.dedup import CdxServerDedup, DedupableMixin


def test_cdx_dedup():
    # Mock CDX Server responses to simulate found, not found and errors.
    url = "http://example.com"
    # not found case
    result = mock.Mock()
    result.status = 200
    result.data = b'20170101020405 test'
    cdx_server = CdxServerDedup(cdx_url="dummy-cdx-server-url")
    cdx_server.http_pool.request = mock.MagicMock(return_value=result)
    res = cdx_server.lookup(digest_key="B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A",
                            url=url)
    assert res is None

    # found case
    result = mock.Mock()
    result.status = 200
    result.data = b'20170203040503 B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A'
    cdx_server = CdxServerDedup(cdx_url="dummy-cdx-server-url")
    cdx_server.http_pool.request = mock.MagicMock(return_value=result)
    res = cdx_server.lookup(digest_key="B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A",
                            url=url)
    assert res["date"] == b"2017-02-03T04:05:03Z"

    # invalid CDX result status code
    result = mock.Mock()
    result.status = 400
    result.data = b'20170101020405 B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A'
    cdx_server = CdxServerDedup(cdx_url="dummy-cdx-server-url")
    cdx_server.http_pool.request = mock.MagicMock(return_value=result)
    res = cdx_server.lookup(digest_key="B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A",
                            url=url)
    assert res is None

    # invalid CDX result content
    result = mock.Mock()
    result.status = 200
    result.data = b'InvalidExceptionResult'
    cdx_server = CdxServerDedup(cdx_url="dummy-cdx-server-url")
    cdx_server.http_pool.request = mock.MagicMock(return_value=result)
    res = cdx_server.lookup(digest_key="B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A",
                            url=url)
    assert res is None


@pytest.mark.parametrize("dedup_offset,black_out_period, in_black_out", [
    (3600, 60, False),
    (30, 60, True),
    (25, 0, False)
    ])
def test_black_out(dedup_offset, black_out_period, in_black_out):
    """Test DedupableMixin.in_black_out method correctness.
    """
    opts = mock.Mock()
    opts.dedup_min_text_size = 0
    opts.dedup_min_binary_size = 0
    opts.dedup_only_with_bucket = False
    opts.black_out_period = black_out_period
    dedupable_mixin = DedupableMixin(opts)

    dt = datetime.datetime.utcnow() - datetime.timedelta(seconds=dedup_offset)
    dedup_info = dict(url='http://example.com',
                      date=dt.strftime('%Y-%m-%dT%H:%M:%SZ').encode('utf-8'))
    assert dedupable_mixin.in_black_out(dedup_info) == in_black_out
