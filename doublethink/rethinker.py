'''
doublethink/rethinker.py - rethinkdb connection-manager

Copyright (C) 2015-2018 Internet Archive

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
import re

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

    def _result_iter(self, conn, result):
        error_count = 0
        try:
            yield  # empty yield, see comment below
            while True:
                try:
                    yield next(result)
                except StopIteration:
                    break
                except r.ReqlOpFailedError as e:
                    if e.args and re.match(
                            '^Cannot perform.*replica.*', e.args[0]):
                        if error_count < 20:
                            error_count += 1
                            self.logger.warning(
                                    'will keep trying after potentially '
                                    'recoverable error (%s/20): %s',
                                    error_count, e)
                            time.sleep(0.5)
                        else:
                            raise
                    else:
                        raise
        finally:
            result.close()
            conn.close()

    def run(self, db=None, **kwargs):
        self.wrapped.run  # raise AttributeError early
        while True:
            conn = self.rr._random_server_connection()
            is_iter = False
            try:
                result = self.wrapped.run(
                        conn, db=db or self.rr.dbname, **kwargs)
                if hasattr(result, '__next__'):
                    is_iter = True
                    g = self._result_iter(conn, result)
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
            except r.ReqlOpFailedError as e:
                if e.args and re.match(
                        '^Cannot perform.*replica.*', e.args[0]):
                    self.logger.warning(
                            'will keep trying after potentially recoverable '
                            'error: %s', e)
                    time.sleep(0.5)
                else:
                    raise
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
        self.last_error = {} # {server: time}

    # https://github.com/rethinkdb/rethinkdb-example-webpy-blog/blob/master/model.py
    # "Best practices: Managing connections: a connection per request"
    def _random_server_connection(self):
        retry_wait = 0.01
        while True:
            server = random.choice(self._server_whitelist())
            try:
                try:
                    host, port = server.split(':')
                    return r.connect(host=host, port=port)
                except ValueError:
                    return r.connect(host=server)
            except Exception as e:
                self.last_error[server] = time.time()
                self.logger.warning(
                        'will keep trying after failure connecting to '
                        'rethinkdb server at %s: %s (sleeping for %s sec)',
                        server, e, retry_wait)
                time.sleep(retry_wait)
                retry_wait = min(retry_wait * 2, 10.0)

    # https://en.wikipedia.org/wiki/Penalty_(ice_hockey)#Major_penalty
    PENALTY_BOX_TIME = 300
    def _server_whitelist(self):
        '''
        Returns list of servers that have not errored in the last five minutes.
        If all servers have errored in the last five minutes, returns list with
        one item, the server that errored least recently.
        '''
        whitelist = []
        for server in self.servers:
            if (server not in self.last_error
                    or self.last_error[server] < time.time() - self.PENALTY_BOX_TIME):
                whitelist.append(server)
        if not whitelist:
            whitelist.append(sorted(
                self.last_error.items(), key=lambda kv: kv[1])[0][0])
        return whitelist

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

