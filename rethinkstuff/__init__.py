from __future__ import absolute_import
import rethinkdb as r
import logging
import random
import time
import types

class RethinkerWrapper:
    logger = logging.getLogger('rethinkstuff.RethinkerWrapper')
    def __init__(self, rethinker, wrapped):
        self.rethinker = rethinker
        self.wrapped = wrapped

    def __getattr__(self, name):
        delegate = getattr(self.wrapped, name)
        return self.rethinker.wrap(delegate)

    def run(self, db=None):
        self.wrapped.run  # raise AttributeError early
        while True:
            conn = self.rethinker._random_server_connection()
            is_iter = False
            try:
                result = self.wrapped.run(conn, db=db or self.rethinker.dbname)
                if hasattr(result, "__next__"):
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
    """
    >>> r = Rethinker(db="my_db")
    >>> doc = r.table("my_table").get(1).run()
    """
    logger = logging.getLogger('rethinkstuff.Rethinker')

    def __init__(self, servers=['localhost'], db=None):
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
                self.logger.error('will keep trying to get a connection after failure connecting to %s', server, exc_info=True)
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

