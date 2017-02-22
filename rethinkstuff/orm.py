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

    The primary key must be `id`, the rethinkdb default. (XXX we could find out
    what the primary key is from the "table_config" system table.)
    '''
    def __init__(self, rethinker, d={}):
        dict.__setattr__(self, '_r', rethinker)
        for k in d:
            dict.__setitem__(
                    self, k, watch(d[k], callback=self._updated, field=k))
        self._clear_updates()

    def _clear_updates(self):
        dict.__setattr__(self, '_updates', {})
        dict.__setattr__(self, '_deletes', set())

    def __setitem__(self, key, value):
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

    # XXX do we need the other stuff like in WatchedDict?

    def _updated(self, field):
        # callback for all updates
        self._updates[field] = self[field]
        if field in self._deletes:
            self._deletes.remove(field)

    @property
    def table(self):
        '''
        Name of the rethinkdb table.

        Defaults to the name of the class, lowercased. Can be overridden.
        '''
        return self.__class__.__name__.lower()

    def table_create(self):
        '''
        Creates the table.

        Subclasses may want to override this method to do more things, such as
        creating indexes.
        '''
        self._r.table_create(self.table).run()

    def insert(self):
        result = self._r.table(self.table).insert(self).run()
        if 'generated_keys' in result:
            dict.__setitem__(self, 'id', result['generated_keys'][0])
        self._clear_updates()

    def update(self):
        # hmm, masks dict.update()
        if self._updates:
            # r.literal() to replace, not merge with, nested fields
            updates = {
                    field: r.literal(
                        self._updates[field]) for field in self._updates}
            self._r.table(self.table).get(self.id).update(updates).run()
        if self._deletes:
            self._r.table(self.table).replace(
                    r.row.without(self._deletes)).run()
        self._clear_updates()

    def refresh(self):
        '''
        Refresh from the database.
        '''
        d = self._r.table(self.table).get(self.id).run()
        for k in d:
            dict.__setitem__(
                    self, k, watch(d[k], callback=self._updated, field=k))


