'''
tests_misc.py - tests for doublethink miscellany

Copyright (C) 2017 Internet Archive

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import doublethink
import logging
import sys
import pytest
import rethinkdb as r
from doublethink import parse_rethinkdb_url

logging.basicConfig(
        stream=sys.stderr, level=logging.INFO, format=(
            '%(asctime)s %(process)d %(levelname)s %(threadName)s '
            '%(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s'))

def test_parse_rethinkdb_url():
    assert parse_rethinkdb_url('rethinkdb://foo/bar/baz') == (['foo'], 'bar', 'baz')
    assert parse_rethinkdb_url('rethinkdb://foo/bar') == (['foo'], 'bar', None)
    assert parse_rethinkdb_url('rethinkdb://foo') == (['foo'], None, None)
    assert parse_rethinkdb_url('rethinkdb://foo,goo/bar/baz') == (['foo', 'goo'], 'bar', 'baz')
    assert parse_rethinkdb_url('rethinkdb://foo,goo/bar') == (['foo', 'goo'], 'bar', None)
    assert parse_rethinkdb_url('rethinkdb://foo,goo') == (['foo', 'goo'], None, None)
    assert parse_rethinkdb_url('rethinkdb://foo,goo:38015/bar/baz') == (['foo', 'goo:38015'], 'bar', 'baz')
    assert parse_rethinkdb_url('rethinkdb://foo,goo:38015/bar') == (['foo', 'goo:38015'], 'bar', None)
    assert parse_rethinkdb_url('rethinkdb://foo,goo:38015') == (['foo', 'goo:38015'], None, None)
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://foo,goo/')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://foo,goo:38015/')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://foo,goo:38015/bar/')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://foo,goo:38015/bar/baz/')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://foo,goo/bar/baz/')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://foo/bar/baz/')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://foo/bar/')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://foo/')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('http://foo/bar/baz')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://foo,goo/bar/')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb:///a')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb:///a/b')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://a,/')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://,b/')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://foo/bar/baz/quux')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://foo/bar/baz/quux')
    # we don't support rethinkdb auth
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://u@foo/bar/baz')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://u:p@foo/bar/baz')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://foo,u@goo/bar/baz')
    with pytest.raises(ValueError):
        parse_rethinkdb_url('rethinkdb://foo,u:p@goo/bar/baz')
