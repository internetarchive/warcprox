'''
tests_orm.py - unit tests for doublethink ORM

Copyright (C) 2015-2023 Internet Archive

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
import rethinkdb as rdb

r = rdb.RethinkDB()

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

    d.m = 'n'
    d['c']['o'] = 'p'
    d.f[0] = 'q'
    d['i'][1]['k'] = 's'
    del d['i']
    d.i = 't'
    # list manipulations
    d.f.append(['sublist'])
    result = d.f.pop()
    assert result == ['sublist']
    del d.f[0]
    d.f.insert(0, 'u')
    d.f.extend(('v', {'w': 'x'}))
    d.f[3]['y'] = 'z'
    d.f.remove('h')
    del d['c']['d']
    d['c'].clear()
    assert d['c'].setdefault('aa') is None
    d['c'].setdefault('aa', 'bb') is None
    d['c'].setdefault('cc', 'dd') == 'dd'
    d['c'].setdefault('cc') == 'dd'
    d['c'].setdefault('cc', 'ee') == 'dd'
    assert d['c'].pop('cc') == 'dd'
    assert d['f'][2].popitem()
    d.save()

    d_copy = SomeDoc.load(rr, d.id)
    assert d == d_copy
    d['zuh'] = 'toot'
    d.save()
    assert d != d_copy
    d_copy.refresh()
    assert d == d_copy

    assert d.setdefault('ee') is None
    d.setdefault('ee', 'ff') is None
    d.setdefault('gg', 'hh') == 'hh'
    d.setdefault('gg') == 'hh'
    d.setdefault('gg', 'ii') == 'hh'
    d.save()

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
    with pytest.raises(Exception):
        NonstandardPrimaryKey.load(rr, 'no_such_thing')

    NonstandardPrimaryKey.table_ensure(rr)

    assert NonstandardPrimaryKey.load(rr, None) is None
    assert NonstandardPrimaryKey.load(rr, 'no_such_thing') is None

    # new empty doc
    f = NonstandardPrimaryKey(rr, {})
    f.save()
    assert f.pk_value
    assert 'not_id' in f
    assert f.not_id == f.pk_value
    assert len(f.keys()) == 1

    assert NonstandardPrimaryKey.load(rr, 'no_such_thing') is None

    # new doc with (only) primary key
    d = NonstandardPrimaryKey(rr)
    d.not_id = 1
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

def test_default_values(rr):
    class Person(doublethink.Document):
        def populate_defaults(self):
            if not "age" in self:
                self.age = 0  # born today

    Person.table_ensure(rr)
    p = Person(rr, {})
    assert p.age == 0
    assert not p.id
    p.save()
    assert p.id
    assert p.age == 0

    p.age = 50
    assert p.age == 50
    p.save()
    assert p.age == 50

    q = Person.load(rr, p.id)
    assert q.age == 50
    q.save()
    assert q.age == 50
    q.refresh()
    assert q.age == 50

def test_dumb_bug_fixed(rr):
    class Foo(doublethink.Document):
        pass
    Foo.table_ensure(rr)
    f = Foo(rr, {})
    f.id = 1
    f.blah = 'toot'
    f.save()
    assert list(rr.table(Foo.table).order_by('id').run()) == [
            {'id': 1, 'blah': 'toot'}]

    g = Foo(rr, {})
    g.id = 2
    g.blah = 'moof'
    g.save()
    assert list(rr.table(Foo.table).order_by('id').run()) == [
            {'blah': 'toot', 'id': 1}, {'blah': 'moof', 'id': 2}]

    del f['blah']
    f.save()
    assert list(rr.table(Foo.table).order_by('id').run()) == [
            {'id': 1}, {'blah': 'moof', 'id': 2}]

