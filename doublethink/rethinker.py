'''
doublethink/rethinker.py - rethinkdb connection-manager

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

import rethinkdb as r
import logging
import random
import time
import types

class RethinkerWrapper(object):
    logger = logging.getLogger('doublethink.RethinkerWrapper')
    def __init__(self, rr, wrapped):
        self.rr = rr
        self.wrapped = wrapped

    def __getattr__(self, name):
        delegate = getattr(self.wrapped, name)
        return self.rr.wrap(delegate)

    def __getitem__(self, key):
        return self.rr.wrap(self.wrapped.__getitem__)(key)

    def __repr__(self):
        return '<RethinkerWrapper{}>'.format(repr(self.wrapped))

    def run(self, db=None):
        self.wrapped.run  # raise AttributeError early
        while True:
            conn = self.rr._random_server_connection()
            is_iter = False
            try:
                result = self.wrapped.run(conn, db=db or self.rr.dbname)
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
    >>> rr = Rethinker(db='my_db')
    >>> doc = rr.table('my_table').get(1).run()
    '''
    logger = logging.getLogger('doublethink.Rethinker')

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

