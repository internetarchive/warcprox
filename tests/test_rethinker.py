'''
tests_rethinker.py - unit tests for doublethink connection manager

Copyright (C) 2015-2017 Internet Archive

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
import types
import gc
import pytest
import rethinkdb as r
import datetime

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
        format="%(asctime)s %(process)d %(levelname)s %(threadName)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s")

class RethinkerForTesting(doublethink.Rethinker):
    def __init__(self, *args, **kwargs):
        super(RethinkerForTesting, self).__init__(*args, **kwargs)

    def _random_server_connection(self):
        self.last_conn = super(RethinkerForTesting, self)._random_server_connection()
        # logging.info("self.last_conn=%s", self.last_conn)
        return self.last_conn

@pytest.fixture(scope="module")
def rr():
    rr = RethinkerForTesting()
    try:
        rr.db_drop("doublethink_test_db").run()
    except r.errors.ReqlOpFailedError:
        pass
    result = rr.db_create("doublethink_test_db").run()
    assert not rr.last_conn.is_open()
    assert result["dbs_created"] == 1
    return RethinkerForTesting(db="doublethink_test_db")

@pytest.fixture(scope="module")
def my_table(rr):
    assert rr.table_list().run() == []
    result = rr.table_create("my_table").run()
    assert not rr.last_conn.is_open()
    assert result["tables_created"] == 1

def test_rethinker(rr, my_table):
    assert rr.table("my_table").index_create("foo").run() == {"created": 1}
    assert not rr.last_conn.is_open()

    result = rr.table("my_table").insert(({"foo":i,"bar":"repeat"*i} for i in range(2000))).run()
    assert not rr.last_conn.is_open()
    assert len(result["generated_keys"]) == 2000
    assert result["inserted"] == 2000

    result = rr.table("my_table").run()
    assert rr.last_conn.is_open() # should still be open this time
    assert isinstance(result, types.GeneratorType)
    n = 0
    for x in result:
        n += 1
        pass
    # connection should be closed after finished iterating over results
    assert not rr.last_conn.is_open()
    assert n == 2000

    result = rr.table("my_table").run()
    assert rr.last_conn.is_open() # should still be open this time
    assert isinstance(result, types.GeneratorType)
    next(result)
    result = None
    gc.collect()
    # connection should be closed after result is garbage-collected
    assert not rr.last_conn.is_open()

    result = rr.table("my_table").run()
    assert rr.last_conn.is_open() # should still be open this time
    assert isinstance(result, types.GeneratorType)
    result = None
    gc.collect()
    # connection should be closed after result is garbage-collected
    assert not rr.last_conn.is_open()

def test_too_many_errors(rr):
    with pytest.raises(r.errors.ReqlOpFailedError):
        rr.table_create("too_many_replicas", replicas=99).run()
    with pytest.raises(r.errors.ReqlOpFailedError):
        rr.table_create("too_many_shards", shards=99).run()

def test_slice(rr, my_table):
    """Tests RethinkerWrapper.__getitem__()"""
    result = rr.table("my_table")[5:10].run()
    assert rr.last_conn.is_open() # should still be open this time
    assert isinstance(result, types.GeneratorType)
    n = 0
    for x in result:
        n += 1
        pass
    # connection should be closed after finished iterating over results
    assert not rr.last_conn.is_open()
    assert n == 5

def test_utcnow():
    now_notz = datetime.datetime.utcnow()  # has no timezone :(
    assert not now_notz.tzinfo

    now_tz = doublethink.utcnow() # solution to that problem
    assert now_tz.tzinfo

    ## .timestamp() was added in python 3.3
    if hasattr(now_tz, 'timestamp'):
        assert now_tz.timestamp() - now_notz.timestamp() < 0.1

    ## XXX TypeError: can't subtract offset-naive and offset-aware datetimes
    # assert abs((now_tz - now_notz).total_seconds()) <  0.1

    ## XXX what else can we test without jumping through hoops?

