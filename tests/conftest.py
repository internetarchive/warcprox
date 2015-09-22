# vim:set sw=4 et:
import pytest

def pytest_addoption(parser):
    parser.addoption('--rethinkdb-servers', dest='rethinkdb_servers',
            help='rethink db servers for dedup, e.g. db0.foo.org,db0.foo.org:38015,db1.foo.org')
    parser.addoption('--rethinkdb-big-table',
            dest='rethinkdb_big_table', action='store_true', default=False,
            help='use a big rethinkdb table called "captures", instead of a small table called "dedup"; table is suitable for use as index for playback (ignored unless --rethinkdb-servers is specified)')

@pytest.fixture(scope="module")
def rethinkdb_servers(request):
    return request.config.getoption("--rethinkdb-servers")

@pytest.fixture(scope="module")
def rethinkdb_big_table(request):
    return request.config.getoption("--rethinkdb-big-table")


