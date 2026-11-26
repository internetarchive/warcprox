import pytest
from warcprox.warcproxy import is_local_address

@pytest.mark.parametrize('ip', [
    '127.0.0.1', '127.0.0.2', '127.255.255.254', '0.0.0.0',
    '::1', '::', '::ffff:127.0.0.1', '::ffff:7f00:2', '::ffff:0.0.0.0',
])
def test_localhost_addresses(ip):
    assert is_local_address(ip)

@pytest.mark.parametrize('ip', [
    '93.184.216.34', '10.0.0.1', '192.168.1.1', '2606:2800:220:1::',
    '::ffff:93.184.216.34', 'fe80::1%lo', 'not-an-ip', '',
])
def test_non_localhost_addresses(ip):
    assert not is_local_address(ip)
