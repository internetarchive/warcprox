#!/usr/bin/env python
'''
tests/test_ensure_rethinkdb_tables.py - automated tests of
ensure-rethinkdb-tables utility

Copyright (C) 2017 Internet Archive

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

import warcprox.main
import pytest
import socket
import doublethink
import logging
import sys

logging.basicConfig(
        stream=sys.stdout, level=logging.TRACE,
        format='%(asctime)s %(process)d %(levelname)s %(threadName)s '
        '%(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')

def rethinkdb_is_running():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('127.0.0.1', 28015))
        return True
    except:
        return False

if_rethinkdb = pytest.mark.skipif(
        not rethinkdb_is_running(),
        reason='rethinkdb not listening at 127.0.0.1:28015')

@if_rethinkdb
def test_individual_options():
    rr = doublethink.Rethinker(['127.0.0.1'])

    try:
        warcprox.main.ensure_rethinkdb_tables([
            'warcprox-ensure-rethinkdb-tables',
            '--rethinkdb-stats-url=rethinkdb://127.0.0.1/db0/stats'])
        assert rr.db('db0').table_list().run() == ['stats']
    finally:
        rr.db_drop('db0').run()

    try:
        warcprox.main.ensure_rethinkdb_tables([
            'warcprox-ensure-rethinkdb-tables',
            '--rethinkdb-services-url=rethinkdb://127.0.0.1/db1/services'])
        assert rr.db('db1').table_list().run() == ['services']
    finally:
        rr.db_drop('db1').run()

    try:
        warcprox.main.ensure_rethinkdb_tables([
            'warcprox-ensure-rethinkdb-tables',
            '--rethinkdb-dedup-url=rethinkdb://127.0.0.1/db2/dedup'])
        assert rr.db('db2').table_list().run() == ['dedup']
    finally:
        rr.db_drop('db2').run()

    try:
        warcprox.main.ensure_rethinkdb_tables([
            'warcprox-ensure-rethinkdb-tables',
            '--rethinkdb-big-table-url=rethinkdb://127.0.0.1/db3/captures'])
        assert rr.db('db3').table_list().run() == ['captures']
    finally:
        rr.db_drop('db3').run()

    try:
        warcprox.main.ensure_rethinkdb_tables([
            'warcprox-ensure-rethinkdb-tables',
            '--rethinkdb-trough-db-url=rethinkdb://127.0.0.1/db4'])
        assert rr.db('db4').table_list().run() == ['services']
                # ['assignment', 'lock', 'schema', 'services']
    finally:
        rr.db_drop('db4').run()

@if_rethinkdb
def test_combos():
    rr = doublethink.Rethinker(['127.0.0.1'])

    try:
        warcprox.main.ensure_rethinkdb_tables([
            'warcprox-ensure-rethinkdb-tables',
            '--rethinkdb-stats-url=rethinkdb://127.0.0.1/db00/stats',
            '--rethinkdb-trough-db-url=rethinkdb://127.0.0.1/db01',
            ])
        assert rr.db('db00').table_list().run() == ['stats']
        assert rr.db('db01').table_list().run() == ['services']
        # ['assignment', 'lock', 'schema', 'services']
    finally:
        rr.db_drop('db00').run()
        rr.db_drop('db01').run()
