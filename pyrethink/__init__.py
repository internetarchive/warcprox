from __future__ import absolute_import
import rethinkdb as r
import logging
import random
import time

class Rethinker:
    logger = logging.getLogger('pyrethink.Rethinker')

    def __init__(self, servers=['localhost'], db=None):
        self.servers = servers
        self.db = db

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

    def run(self, query):
        while True:
            with self._random_server_connection() as conn:
                try:
                    return query.run(conn, db=self.db)
                except (r.ReqlAvailabilityError, r.ReqlTimeoutError) as e:
                    self.logger.error('will retry rethinkdb query/operation %s which failed like so:', exc_info=True)

    def results_iter(self, query):
        """Generator for query results that closes the connection after
        iterating over the results, for proper support of cursors, which fetch
        from the server more than once."""
        success = False
        while not success:
            with self._random_server_connection() as conn:
                try:
                    results = query.run(conn, db=self.db)
                    success = True
                    for result in results:
                        yield result
                    if hasattr(results, 'close'):
                        results.close()
                except (r.ReqlAvailabilityError, r.ReqlTimeoutError) as e:
                    self.logger.error('will retry rethinkdb query/operation %s which failed like so:', exc_info=True)

