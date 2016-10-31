'''
rethinkstuff/__init__.py - rethinkdb connection-manager-ish thing and service
registry thing

Copyright (C) 2015-2016 Internet Archive

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
import random
import time
import types
import socket
import os
import datetime

try:
    UTC = datetime.timezone.utc
except:
    UTC = r.make_timezone("00:00")

def utcnow():
    """Convenience function to get timezone-aware UTC datetime. RethinkDB
    requires timezone-aware datetime for its native time type, and
    unfortunately datetime.datetime.utcnow() is not timezone-aware. Also python
    2 doesn't come with a timezone implementation."""
    return datetime.datetime.now(UTC)

class RethinkerWrapper(object):
    logger = logging.getLogger('rethinkstuff.RethinkerWrapper')
    def __init__(self, rethinker, wrapped):
        self.rethinker = rethinker
        self.wrapped = wrapped

    def __getattr__(self, name):
        delegate = getattr(self.wrapped, name)
        return self.rethinker.wrap(delegate)

    def __getitem__(self, key):
        return self.rethinker.wrap(self.wrapped.__getitem__)(key)

    def __repr__(self):
        return '<RethinkerWrapper{}>'.format(repr(self.wrapped))

    def run(self, db=None):
        self.wrapped.run  # raise AttributeError early
        while True:
            conn = self.rethinker._random_server_connection()
            is_iter = False
            try:
                result = self.wrapped.run(conn, db=db or self.rethinker.dbname)
                if hasattr(result, '__next__'):
                    is_iter = True
                    def gen():
                        try:
                            yield  # empty yield, see comment below
                            for x in result:
                                yield x
                        finally:
                            result.close()
                            conn.close()
                    g = gen()
                    # Start executing the generator, leaving off after the
                    # empty yield. If we didn't do this, and the caller never
                    # started the generator, the finally block would never run
                    # and the connection would stay open.
                    next(g)
                    return g
                else:
                    return result
            except r.ReqlTimeoutError as e:
                time.sleep(0.5)
            finally:
                if not is_iter:
                    conn.close(noreply_wait=False)

class Rethinker(object):
    '''
    >>> r = Rethinker(db='my_db')
    >>> doc = r.table('my_table').get(1).run()
    '''
    logger = logging.getLogger('rethinkstuff.Rethinker')

    def __init__(self, servers=['localhost'], db=None):
        if isinstance(servers, str):
            self.servers = [servers]
        else:
            self.servers = servers
        self.dbname = db

    # https://github.com/rethinkdb/rethinkdb-example-webpy-blog/blob/master/model.py
    # "Best practices: Managing connections: a connection per request"
    def _random_server_connection(self):
        while True:
            server = random.choice(self.servers)
            try:
                try:
                    host, port = server.split(':')
                    return r.connect(host=host, port=port)
                except ValueError:
                    return r.connect(host=server)
            except Exception as e:
                self.logger.error(
                        'will keep trying after failure connecting to '
                        'rethinkdb server at %s: %s', server, e)
                time.sleep(0.5)

    def wrap(self, delegate):
        if isinstance(delegate, (types.FunctionType, types.MethodType)):
            def wrapper(*args, **kwargs):
                result = delegate(*args, **kwargs)
                if result is not None:
                    return RethinkerWrapper(self, result)
                else:
                    return None
            return wrapper
        else:
            return delegate

    def __getattr__(self, name):
        delegate = getattr(r, name)
        return self.wrap(delegate)

class ServiceRegistry(object):
    '''
    status_info is dict, should have at least these fields
    {
        'id': ...,   # generated by rethinkdb
        'role': 'brozzler-worker',
        'load': 0.5, # load score
        'heartbeat_interval': 20.0,
        'host': 'wbgrp-svc999.us.archive.org',           # set in svcreg.heartbeat() as a fallback
        'pid': 1234,                                     # set in svcreg.heartbeat() as a fallback
        'first_heartbeat': '2015-10-30T03:39:40.080814', # set in svcreg.heartbeat()
        'last_heartbeat': '2015-10-30T05:54:35.422866',  # set in svcreg.heartbeat()
        ... plus anything else you want...
    }
    '''

    logger = logging.getLogger('rethinkstuff.ServiceRegistry')

    def __init__(self, rethinker):
        self.r = rethinker
        self._ensure_table()

    def _ensure_table(self):
        dbs = self.r.db_list().run()
        if not self.r.dbname in dbs:
            self.logger.info('creating rethinkdb database %s', repr(self.r.dbname))
            self.r.db_create(self.r.dbname).run()
        tables = self.r.table_list().run()
        if not 'services' in tables:
            self.logger.info("creating rethinkdb table 'services' in database %s", repr(self.r.dbname))
            self.r.table_create('services', shards=1, replicas=min(3, len(self.r.servers))).run()
            # self.r.table('sites').index_create...?

    def heartbeat(self, status_info):
        '''
        Returns updated status info on success, un-updated status info on
        failure.
        '''
        updated_status_info = dict(status_info)
        updated_status_info['last_heartbeat'] = r.now()
        if not 'first_heartbeat' in updated_status_info:
            updated_status_info['first_heartbeat'] = updated_status_info['last_heartbeat']
        if not 'host' in updated_status_info:
            updated_status_info['host'] = socket.gethostname()
        if not 'pid' in updated_status_info:
            updated_status_info['pid'] = os.getpid()
        try:
            result = self.r.table('services').insert(
                    updated_status_info, conflict='replace',
                    return_changes=True).run()
            return result['changes'][0]['new_val'] # XXX check
        except:
            self.logger.error('error updating service registry', exc_info=True)
            return status_info

    def unregister(self, id):
        result = self.r.table('services').get(id).delete().run()
        if result != {'deleted':1,'errors':0,'inserted':0,'replaced':0,'skipped':0,'unchanged':0}:
            self.logger.warn('unexpected result attempting to delete id=%s from rethinkdb services table: %s', id, result)

    def available_service(self, role):
        try:
            result = self.r.table('services').filter({"role":role}).filter(
                lambda svc: r.now().sub(svc["last_heartbeat"]) < 3 * svc["heartbeat_interval"]   #.default(20.0)
            ).order_by("load")[0].run()
            return result
        except r.ReqlNonExistenceError:
            return None

    def available_services(self, role=None):
        try:
            query = self.r.table('services')
            if role:
                query = query.filter({"role":role})
            query = query.filter(
                lambda svc: r.now().sub(svc["last_heartbeat"]) < 3 * svc["heartbeat_interval"]   #.default(20.0)
            ).order_by("load")
            result = query.run()
            return result
        except r.ReqlNonExistenceError:
            return []

