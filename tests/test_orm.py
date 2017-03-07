'''
tests_orm.py - unit tests for doublethink ORM

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
import pytest
import rethinkdb as r

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

def test_default_values(rr):
    class Person(doublethink.Document):
        def populate_defaults(self):
            if not "age" in self:
                self.age = 0  # born today

    Person.table_ensure(rr)
    p = Person(rr, {})
    assert not "age" in p
    assert p.age is None
    p.save()
    assert p.age == 0
    assert p.id

    p.age = 50
    p.save()

    q = Person.load(rr, p.id)
    assert q.age == 50
    q.save()
    assert q.age == 50
    q.refresh()
    assert q.age == 50

