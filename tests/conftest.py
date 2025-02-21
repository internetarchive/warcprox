'''
tests/conftest.py - command line options for warcprox tests

Copyright (C) 2015-2017 Internet Archive

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
USA.
'''

import pytest

def pytest_addoption(parser):
    parser.addoption(
            '--rethinkdb-dedup-url', dest='rethinkdb_dedup_url', help=(
                'rethinkdb dedup url, e.g. rethinkdb://db0.foo.org,'
                'db1.foo.org:38015/my_warcprox_db/my_dedup_table'))
    parser.addoption(
            '--rethinkdb-big-table-url', dest='rethinkdb_big_table_url', help=(
                'rethinkdb big table url (table will be populated with '
                'various capture information and is suitable for use as '
                'index for playback), e.g. rethinkdb://db0.foo.org,'
                'db1.foo.org:38015/my_warcprox_db/captures'))
    parser.addoption(
            '--rethinkdb-trough-db-url', dest='rethinkdb_trough_db_url', help=(
                '🐷   url pointing to trough configuration rethinkdb database, '
                'e.g. rethinkdb://db0.foo.org,db1.foo.org:38015'
                '/trough_configuration'))

