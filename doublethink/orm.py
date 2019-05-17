'''
doublethink/orm.py - rethinkdb ORM

Copyright (C) 2017-2019 Internet Archive

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

import rethinkdb as r
import logging
import doublethink

class classproperty(object):
    def __init__(self, fget):
        self.fget = fget
    def __get__(self, owner_self, owner_cls):
        return self.fget(owner_cls)

class Document(dict):
    '''
    Base class for ORM.

    You should subclass this class for each of your rethinkdb tables. You can
    add custom functionality in your subclass if appropriate.

    Call save() to persist changes to the model.

    This class subclasses dict. Thus attributes can be accessed with
    `doc['foo']` or `doc.get('foo')`, depending on what you want to happen if
    the attribute is missing. In addition, this class overrides `__getattr__`
    to point to `dict.get`, so that first level attributes can be accessed as
    if they were member variables, e.g. `doc.foo`. If there is no attribute
    foo, `doc.foo` returns None. (XXX is this definitely what we want?)

    The default table name is the class name, lowercased. Subclasses can
    specify different table name like so:

        class Something(doublethink.Document):
            table = 'my_table_name'
    '''
    @classproperty
    def table(cls):
        return cls.__name__.lower()

    @classmethod
    def load(cls, rr, pk):
        '''
        Retrieves a document from the database, by primary key.
        '''
        if pk is None:
            return None
        d = rr.table(cls.table).get(pk).run()
        if d is None:
            return None
        doc = cls(rr, d)
        return doc

    @classmethod
    def table_create(cls, rr):
        '''
        Creates the table. Subclasses may want to override this method to do
        more things, such as creating secondary indexes.
        '''
        rr.table_create(cls.table).run()

    @classmethod
    def table_ensure(cls, rr):
        '''
        Creates the table if it doesn't exist.
        '''
        dbs = rr.db_list().run()
        if not rr.dbname in dbs:
            logging.info('creating rethinkdb database %s', repr(rr.dbname))
            rr.db_create(rr.dbname).run()
        tables = rr.table_list().run()
        if not cls.table in tables:
            logging.info(
                    'creating rethinkdb table %s in database %s',
                    repr(cls.table), repr(rr.dbname))
            cls.table_create(rr)

    def __init__(self, rr, d={}):
        '''
        Sets initial values from `d`, then calls `self.populate_defaults()`.

        Args:
            rr (doublethink.Rethinker): rethinker
            d (dict): initial value

        If you want to create a new document, and set the primary key yourself,
        do not call `doc = MyDocument(rr, d={'id': 'my_id', ...})`. The
        assumption is that if the primary key is set in the constructor, the
        document already exists in the database. Thus a call to `doc.save()`
        may not save anything. Do this instead:

            doc = MyDocument(rr, d={'id': 'my_id', ...})
            doc.id = 'my_id'
            # ...whatever else...
            doc.save()
        '''
        dict.__setattr__(self, 'rr', rr)
        self._pk = None
        self.update(d or {})
        self.populate_defaults()

    def __setitem__(self, key, value):
        # keys starting with underscore are not part of the document
        if key[:1] == '_':
            dict.__setattr__(self, key, value)
        else:
            dict.__setitem__(self, key, value)

    __setattr__ = __setitem__
    __getattr__ = dict.get

    @property
    def pk_field(self):
        '''
        Name of the primary key field as retrieved from rethinkdb table
        metadata, 'id' by default. Should not be overridden. Override
        `table_create` if you want to use a nonstandard field as the primary
        key.
        '''
        if not self._pk:
            try:
                pk = self.rr.db('rethinkdb').table('table_config').filter({
                    'db': self.rr.dbname, 'name': self.table}).get_field(
                            'primary_key')[0].run()
                self._pk = pk
            except Exception as e:
                raise Exception(
                        'problem determining primary key for table %s.%s: %s',
                        self.rr.dbname, self.table, e)
        return self._pk

    @property
    def pk_value(self):
        '''
        Value of primary key field.
        '''
        return getattr(self, self.pk_field)

    def populate_defaults(self):
        '''
        This method is called by `__init__()`. Subclasses should override it to
        populate default values if appropriate.
        '''
        pass

    def save(self):
        '''Persist changes to rethinkdb.'''
        query = self.rr.table(self.table).insert(self, conflict='replace')
        result = query.run()
        if sorted([result['inserted'], result['replaced'], result['unchanged']]) != [0,0,1]:
            raise Exception(
                    'unexpected result %s from rethinkdb query %s' % (
                        result, query))
        if 'generated_keys' in result:
            self[self.pk_field] = result['generated_keys'][0]

    def refresh(self):
        '''
        Refresh the document from the database.
        '''
        d = self.rr.table(self.table).get(self.pk_value).run()
        self.clear()
        self.update(d)

