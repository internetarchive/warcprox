# vim:set sw=4 et:
import pytest

def pytest_addoption(parser):
    parser.addoption('--rethinkdb-servers', dest='rethinkdb_servers',
            help='rethink db servers for dedup, e.g. db0.foo.org,db0.foo.org:38015,db1.foo.org')

@pytest.fixture(scope="module")
def rethinkdb_servers(request):
    return request.config.getoption("--rethinkdb-servers")

