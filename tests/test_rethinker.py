'''
tests_rethinker.py - unit tests for doublethink

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
import time
import socket
import os
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

def test_service_registry(rr):
    svcreg = doublethink.ServiceRegistry(rr)
    assert svcreg.available_service("yes-such-role") == None
    assert svcreg.available_services("yes-such-role") == []
    assert svcreg.available_services() == []
    svc0 = {
        "role": "yes-such-role",
        "load": 100.0,
        "heartbeat_interval": 0.4,
    }
    svc1 = {
        "role": "yes-such-role",
        "load": 200.0,
        "heartbeat_interval": 0.4,
    }
    svc0 = svcreg.heartbeat(svc0)
    svc1 = svcreg.heartbeat(svc1)
    assert "id" in svc0
    assert "id" in svc1
    assert svc0["id"] != svc1["id"]

    assert svc0["host"] == socket.gethostname()
    assert svc1["host"] == socket.gethostname()

    assert "pid" in svc0
    assert "pid" in svc1
    assert svc0["pid"] == os.getpid()
    assert svc1["pid"] == os.getpid()
    assert "first_heartbeat" in svc0
    assert "first_heartbeat" in svc1
    assert "last_heartbeat" in svc0
    assert "last_heartbeat" in svc1

    time.sleep(0.2)
    assert svcreg.available_service("no-such-role") == None
    assert svcreg.available_services("no-such-role") == []
    # svc0 has less load
    assert svcreg.available_service("yes-such-role")["id"] == svc0["id"]
    assert len(svcreg.available_services("yes-such-role")) == 2
    assert len(svcreg.available_services()) == 2

    svc1["load"] = 50.0
    svc1 = svcreg.heartbeat(svc1)
    time.sleep(0.2)
    assert svcreg.available_service("no-such-role") == None
    # now svc1 has less load
    assert svcreg.available_service("yes-such-role")["id"] == svc1["id"]
    assert len(svcreg.available_services("yes-such-role")) == 2
    assert len(svcreg.available_services()) == 2

    svc1["load"] = 200.0
    svc1 = svcreg.heartbeat(svc1)
    time.sleep(0.2)
    assert svcreg.available_service("no-such-role") == None
    # now svc0 has less load again
    assert svcreg.available_service("yes-such-role")["id"] == svc0["id"]
    assert len(svcreg.available_services("yes-such-role")) == 2
    assert len(svcreg.available_services()) == 2

    svc1 = svcreg.heartbeat(svc1)
    time.sleep(0.2)
    svc1 = svcreg.heartbeat(svc1)
    time.sleep(0.7)
    assert svcreg.available_service("no-such-role") == None
    # now it's been too long since the last heartbeat from svc0
    assert svcreg.available_service("yes-such-role")["id"] == svc1["id"]
    assert len(svcreg.available_services("yes-such-role")) == 1
    assert len(svcreg.available_services()) == 1

    svcreg.unregister(svc1["id"])
    time.sleep(0.2)
    assert svcreg.available_service("no-such-role") == None
    assert svcreg.available_service("yes-such-role") == None
    assert svcreg.available_services("yes-such-role") == []
    assert svcreg.available_services() == []

    svc0 = {
        "role": "yes-such-role",
        "load": 100.0,
        "heartbeat_interval": 0.4,
    }
    svc1 = {
        "role": "yes-such-role",
        "load": 200.0,
        "heartbeat_interval": 0.4,
    }
    svc0 = svcreg.heartbeat(svc0)
    svc1 = svcreg.heartbeat(svc1)
    assert len(svcreg.available_services("yes-such-role")) == 2
    assert len(svcreg.available_services()) == 2
    svcreg.unregister(svc0["id"])
    svcreg.unregister(svc1["id"])

    svc0 = {
        "role": "yes-such-role",
        "load": 100.0,
        "heartbeat_interval": 0.4,
    }
    svc1 = {
        "role": "yes-such-role",
        "load": 200.0,
        "heartbeat_interval": 0.4,
    }
    svc2 = {
        "role": "another-such-role",
        "load": 200.0,
        "heartbeat_interval": 0.4,
    }
    svc3 = {
        "role": "yet-another-such-role",
        "load": 200.0,
        "heartbeat_interval": 0.4,
    }
    svc0 = svcreg.heartbeat(svc0)
    svc1 = svcreg.heartbeat(svc1)
    svc2 = svcreg.heartbeat(svc2)
    svc3 = svcreg.heartbeat(svc3)
    assert len(svcreg.available_services("yes-such-role")) == 2
    assert len(svcreg.available_services()) == 4

def test_svcreg_heartbeat_server_down(rr):
    class MockRethinker:
        def table(self, *args, **kwargs):
            raise Exception('catch me if you can')

    class SortOfFakeServiceRegistry(doublethink.ServiceRegistry):
        def __init__(self, rethinker):
            self.rr = rethinker
            # self._ensure_table() # not doing this here

    # no such rethinkdb server
    rr = MockRethinker()
    svcreg = SortOfFakeServiceRegistry(rr)
    svc0 = {
        "role": "role-foo",
        "load": 100.0,
        "heartbeat_interval": 0.4,
    }
    # no exception thrown
    svc0 = svcreg.heartbeat(svc0)

    # check that status_info was *not* updated
    assert not 'id' in svc0
    assert not 'last_heartbeat' in svc0
    assert not 'first_heartbeat' in svc0
    assert not 'host' in svc0
    assert not 'pid' in svc0

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

def test_orm(rr):
    class SomeDoc(doublethink.Document):
        table = 'some_doc'

    SomeDoc.table_create(rr)
    SomeDoc.table_ensure(rr)
    with pytest.raises(Exception):
        SomeDoc.table_create(rr)

    # test that overriding Document.table works
    assert 'some_doc' in rr.table_list().run()
    assert not 'somedoc' in rr.table_list().run()

    d = SomeDoc(rr, d={
        'a': 'b',
        'c': {'d': 'e'},
        'f': ['g', 'h'],
        'i': ['j', {'k': 'l'}]})
    d.save()

    assert d._updates == {}
    d.m = 'n'
    assert d._updates == {'m': 'n'}
    d['c']['o'] = 'p'
    assert d._updates == {'m': 'n', 'c': {'d': 'e', 'o': 'p'}}
    d.f[0] = 'q'
    assert d._updates == {'m': 'n', 'c': {'d': 'e', 'o': 'p'}, 'f': ['q', 'h']}
    d['i'][1]['k'] = 's'
    assert d._updates == {
            'm': 'n',
            'c': {'d': 'e', 'o': 'p'},
            'f': ['q', 'h'],
            'i': ['j', {'k': 's'}]}

    del d['i']
    assert d._deletes == {'i'}
    assert d._updates == {'m': 'n', 'c': {'d': 'e', 'o': 'p'}, 'f': ['q', 'h']}

    d.i = 't'
    assert d._deletes == set()
    assert d._updates == {
            'm': 'n', 'c': {'d': 'e', 'o': 'p'}, 'f': ['q', 'h'], 'i': 't'}

    # list manipulations
    d.f.append(['sublist'])
    assert d._updates == {
            'm': 'n', 'c': {'d': 'e', 'o': 'p'},
            'f': ['q', 'h', ['sublist']], 'i': 't'}

    with pytest.raises(TypeError):
        d.f[2].clear()

    result = d.f.pop()
    assert result == ['sublist']
    assert d._updates == {
            'm': 'n', 'c': {'d': 'e', 'o': 'p'},
            'f': ['q', 'h'], 'i': 't'}

    del d.f[0]
    assert d._updates == {
            'm': 'n', 'c': {'d': 'e', 'o': 'p'},
            'f': ['h'], 'i': 't'}

    d.f.insert(0, 'u')
    assert d._updates == {
            'm': 'n', 'c': {'d': 'e', 'o': 'p'},
            'f': ['u', 'h'], 'i': 't'}

    d.f.extend(('v', {'w': 'x'}))
    assert d._updates == {
            'm': 'n', 'c': {'d': 'e', 'o': 'p'},
            'f': ['u', 'h', 'v', {'w': 'x'}], 'i': 't'}

    # check that stuff added by extend() is watched properly
    d.f[3]['y'] = 'z'
    assert d._updates == {
            'm': 'n', 'c': {'d': 'e', 'o': 'p'},
            'f': ['u', 'h', 'v', {'w': 'x', 'y': 'z'}], 'i': 't'}

    d.f.remove('h')
    assert d._updates == {
            'm': 'n', 'c': {'d': 'e', 'o': 'p'},
            'f': ['u', 'v', {'w': 'x', 'y': 'z'}], 'i': 't'}

    # more nested field dict operations
    del d['c']['d']
    assert d._updates == {
            'm': 'n', 'c': {'o': 'p'},
            'f': ['u', 'v', {'w': 'x', 'y': 'z'}], 'i': 't'}

    d['c'].clear()
    assert d._updates == {
            'm': 'n', 'c': {},
            'f': ['u', 'v', {'w': 'x', 'y': 'z'}], 'i': 't'}

    assert d['c'].setdefault('aa') is None
    assert d._updates == {
            'm': 'n', 'c': {'aa': None},
            'f': ['u', 'v', {'w': 'x', 'y': 'z'}], 'i': 't'}

    d['c'].setdefault('aa', 'bb') is None
    assert d._updates == {
            'm': 'n', 'c': {'aa': None},
            'f': ['u', 'v', {'w': 'x', 'y': 'z'}], 'i': 't'}

    d['c'].setdefault('cc', 'dd') == 'dd'
    assert d._updates == {
            'm': 'n', 'c': {'aa': None, 'cc': 'dd'},
            'f': ['u', 'v', {'w': 'x', 'y': 'z'}], 'i': 't'}

    d['c'].setdefault('cc') == 'dd'
    assert d._updates == {
            'm': 'n', 'c': {'aa': None, 'cc': 'dd'},
            'f': ['u', 'v', {'w': 'x', 'y': 'z'}], 'i': 't'}

    d['c'].setdefault('cc', 'ee') == 'dd'
    assert d._updates == {
            'm': 'n', 'c': {'aa': None, 'cc': 'dd'},
            'f': ['u', 'v', {'w': 'x', 'y': 'z'}], 'i': 't'}

    assert d['c'].pop('cc') == 'dd'
    assert d._updates == {
            'm': 'n', 'c': {'aa': None},
            'f': ['u', 'v', {'w': 'x', 'y': 'z'}], 'i': 't'}

    assert d['f'][2].popitem()
    assert d._updates['f'][2] in ({'w':'x'}, {'y':'z'})

    d.save()
    assert d._updates == {}
    assert d._deletes == set()

    d_copy = SomeDoc.load(rr, d.id)
    assert d == d_copy
    d['zuh'] = 'toot'
    d.save()
    assert d != d_copy
    d_copy.refresh()
    assert d == d_copy

    # top level dict operations
    with pytest.raises(TypeError):
        d.clear()

    with pytest.raises(TypeError):
        d.pop('m')

    with pytest.raises(TypeError):
        d.popitem()

    with pytest.raises(TypeError):
        d.update({'x':'y'})

    assert d.setdefault('ee') is None
    assert d._updates == {'ee': None}

    d.setdefault('ee', 'ff') is None
    assert d._updates == {'ee': None}

    d.setdefault('gg', 'hh') == 'hh'
    assert d._updates == {'ee': None, 'gg': 'hh'}

    d.setdefault('gg') == 'hh'
    assert d._updates == {'ee': None, 'gg': 'hh'}

    d.setdefault('gg', 'ii') == 'hh'
    assert d._updates == {'ee': None, 'gg': 'hh'}

    d.save()
    assert d._updates == {}
    assert d._deletes == set()

    d_copy = SomeDoc.load(rr, d.id)
    assert d == d_copy
    d['yuh'] = 'soot'
    d.save()
    assert d != d_copy
    d_copy.refresh()
    assert d == d_copy

def test_orm_pk(rr):
    class NonstandardPrimaryKey(doublethink.Document):
        @classmethod
        def table_create(cls, rethinker):
            rethinker.table_create(cls.table, primary_key='not_id').run()

    with pytest.raises(Exception):
        NonstandardPrimaryKey.load(rr, 'no_such_thing')

    NonstandardPrimaryKey.table_ensure(rr)

    # new empty doc
    f = NonstandardPrimaryKey(rr, {})
    f.save()
    assert f.pk_value
    assert 'not_id' in f
    assert f.not_id == f.pk_value
    assert len(f.keys()) == 1

    with pytest.raises(KeyError):
        NonstandardPrimaryKey.load(rr, 'no_such_thing')

    # new doc with (only) primary key
    d = NonstandardPrimaryKey(rr, {'not_id': 1})
    assert d.not_id == 1
    assert d.pk_value == 1
    d.save()

    d_copy = NonstandardPrimaryKey.load(rr, 1)
    assert d == d_copy

    # new doc with something in it
    e = NonstandardPrimaryKey(rr, {'some_field': 'something'})
    with pytest.raises(KeyError):
        e['not_id']
    assert e.not_id is None
    assert e.get('not_id') is None
    e.save()
    assert e.not_id

    e_copy = NonstandardPrimaryKey.load(rr, e.not_id)
    assert e == e_copy
    e_copy['blah'] = 'toot'
    e_copy.save()

    e.refresh()
    assert e['blah'] == 'toot'
    assert e == e_copy


