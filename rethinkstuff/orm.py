'''
rethinkstuff/orm.py - rethinkdb ORM

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

import rethinkdb as r
import logging
import rethinkstuff

class WatchedDict(dict):
    def __init__(self, d, callback, field):
        self.callback = callback
        self.field = field
        for key in d:
            dict.__setitem__(self, key, watch(
                d[key], callback=self.callback, field=self.field))

    def __setitem__(self, key, value):
        self.callback(self.field)
        return dict.__setitem__(self, key, watch(
            value, callback=self.callback, field=self.field))

    def __delitem__(self, key):
        self.callback(self.field)
        return dict.__delitem__(self, key)

    def clear(self):
        self.callback(self.field)
        return dict.clear(self)

    def pop(self, *args):
        self.callback(self.field)
        return dict.pop(self, *args)

    def popitem(self):
        self.callback(self.field)
        return dict.popitem()

    def setdefault(self, *args):
        self.callback(self.field)
        if len(args) == 2:
            return dict.setdefault(self, args[0], watch(
                args[1], callback=self.callback, field=self.field))
        else:
            return dict.setdefault(self, *args)

    def update(self, *args, **kwargs):
        # looks a little tricky
        raise Exception('not implemented')

class WatchedList(list):
    def __init__(self, l, callback, field):
        self.callback = callback
        self.field = field
        for item in l:
            list.append(self, watch(item, callback=callback, field=self.field))

    def __setitem__(self, index, value):
        self.callback(self.field)
        return list.__setitem__(self, index, watch(
            value, callback=self.callback, field=self.field))

    def __delitem__(self, index):
        self.callback(self.field)
        return list.__delitem__(self, index)

    def append(self, value):
        self.callback(self.field)
        return list.append(self, watch(
            value, callback=self.callback, field=self.field))

    def extend(self, value):
        self.callback(self.field)
        return list.extend(self, watch(
            list(value), callback=self.callback, field=self.field))

    def insert(self, index, value):
        self.callback(self.field)
        return list.insert(self, index, watch(
            value, callback=self.callback, field=self.field))

    def remove(self, value):
        self.callback(self.field)
        return list.remove(self, value)

    def pop(self, index=-1):
        self.callback(self.field)
        return list.pop(self, index)

    def clear(self):
        self.callback(self.field)
        return list.clear(self)

    def sort(self, key=None, reverse=False):
        self.callback(self.field)
        return list.sort(self, key, reverse)

    def reverse(self):
        self.callback(self.field)
        return list.reverse(self)

def watch(obj, callback, field):
    if isinstance(obj, dict):
        return WatchedDict(obj, callback, field)
    elif isinstance(obj, list):
        return WatchedList(obj, callback, field)
    else:
        return obj


class classproperty(object):
    def __init__(self, fget):
        self.fget = fget
    def __get__(self, owner_self, owner_cls):
        return self.fget(owner_cls)

class Document(dict, object):
    '''
    Base class for ORM.

    You should subclass this class for each of your rethinkdb tables. You can
    add custom functionality in your subclass if appropriate.

    This class keeps track of changes made to the object and any nested fields.
    After you have made some changes, call update() to persist them to the
    database.

    Changes in nested fields result in updates to their first-level ancestor
    field. For example, if your document starts as {'a': {'b': 'c'}}, then
    you run d['a']['x'] = 'y', then the update will replace the whole 'a'
    field. Nested field updates get too complicated any other way.
    '''

    @classproperty
    def table(cls):
        '''
        Returns default table name, which is the class name, lowercased.

        Subclasses can override this default more simply:

            class Something(rethinkstuff.Document):
                table = 'my_table_name'
        '''
        return cls.__name__.lower()

    @classmethod
    def load(cls, rethinker, pk):
        '''
        Retrieve an instance from the database.
        '''
        doc = cls(rethinker)
        doc[doc.pk_field] = pk
        doc.refresh()
        return doc

    @classmethod
    def table_create(cls, rethinker):
        '''
        Creates the table.

        Can be run on an instance of the class: `my_doc.table_create
        Subclasses may want to override this method to do more things, such as
        creating indexes.
        '''
        rethinker.table_create(cls.table).run()

    def __init__(self, rethinker, d={}):
        self._r = rethinker
        self._pk = None
        self._clear_updates()
        for k in d:
            self[k] = watch(d[k], callback=self._updated, field=k)

    def _clear_updates(self):
        self._updates = {}
        self._deletes = set()

    def __setitem__(self, key, value):
        # keys starting with underscore are not part of the document
        if key[:1] == '_':
            dict.__setattr__(self, key, value)
        else:
            dict.__setitem__(
                    self, key, watch(value, callback=self._updated, field=key))
            self._updated(key)

    __setattr__ = __setitem__
    __getattr__ = dict.__getitem__

    def __delitem__(self, key):
        dict.__delitem__(self, key)
        self._deletes.add(key)
        if key in self._updates:
            del self._updates[key]

    # XXX probably need the other stuff like in WatchedDict

    def _updated(self, field):
        # callback for all updates
        self._updates[field] = self[field]
        if field in self._deletes:
            self._deletes.remove(field)

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
                pk = self._r.db('rethinkdb').table('table_config').filter({
                    'db': self._r.dbname, 'name': self.table}).get_field(
                            'primary_key')[0].run()
                self._pk = pk
            except Exception as e:
                raise Exception(
                        'problem determining primary key for table %s.%s: %s',
                        self._r.dbname, self.table, e)
        return self._pk

    @property
    def pk_value(self):
        '''
        Value of primary key field.
        '''
        return getattr(self, self.pk_field)

    def save(self):
        '''
        Saves 
        '''
        should_insert = False
        try:
            self.pk_value  # raise KeyError if unset
            if self._updates:
                # r.literal() to replace, not merge with, nested fields
                updates = {field: r.literal(self._updates[field])
                           for field in self._updates}
                query = self._r.table(self.table).get(
                        self.pk_value).update(updates)
                result = query.run()
                if result['skipped']:  # primary key not found
                    should_insert = True
                elif result['errors'] or result['deleted']:
                    raise Exception(
                            'unexpected result %s from rethinkdb query %s' % (
                                result, query))
            if not should_insert and self._deletes:
                self._r.table(self.table).replace(
                        r.row.without(self._deletes)).run()
                if result['errors']:   # primary key not found
                    should_insert = True
                elif not result['replaced'] == 0:
                    raise Exception(
                            'unexpected result %s from rethinkdb query %s' % (
                                result, query))
        except KeyError:
            should_insert = True

        if should_insert:
            query = self._r.table(self.table).insert(self)
            result = query.run()
            if result['inserted'] != 1:
                    raise Exception(
                            'unexpected result %s from rethinkdb query %s' % (
                                result, query))
            if 'generated_keys' in result:
                dict.__setitem__(
                        self, self.pk_field, result['generated_keys'][0])

        self._clear_updates()

    def refresh(self):
        '''
        Refresh from the database.
        '''
        d = self._r.table(self.table).get(self.pk_value).run()
        if d is None:
            raise KeyError
        for k in d:
            dict.__setitem__(
                    self, k, watch(d[k], callback=self._updated, field=k))

