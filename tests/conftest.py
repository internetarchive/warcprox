#
# tests/conftest.py - command line options for warcprox tests
#
# Copyright (C) 2015-2016 Internet Archive
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.
#

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


