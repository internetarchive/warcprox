# vim:set sw=4 et:

from __future__ import absolute_import

import logging
from hanzo import warctools
import rethinkdb
r = rethinkdb
import random

class RethinkCaptures:
    logger = logging.getLogger("warcprox.dedup.RethinkDedupDb")

    def __init__(self, servers=["localhost"], db="warcprox", table="captures", shards=3, replicas=3):
        self.servers = servers
        self.db = db
        self.table = table
        self.shards = shards
        self.replicas = replicas
        self._ensure_db_table()

    # https://github.com/rethinkdb/rethinkdb-example-webpy-blog/blob/master/model.py
    # "Best practices: Managing connections: a connection per request"
    def _random_server_connection(self):
        server = random.choice(self.servers)
        try:
            host, port = server.split(":")
            return r.connect(host=host, port=port)
        except ValueError:
            return r.connect(host=server)

    def _ensure_db_table(self):
        with self._random_server_connection() as conn:
            dbs = r.db_list().run(conn)
            if not self.db in dbs:
                self.logger.info("creating rethinkdb database %s", repr(self.db))
                r.db_create(self.db).run(conn)
            tables = r.db(self.db).table_list().run(conn)
            if not self.table in tables:
                self.logger.info("creating rethinkdb table %s in database %s", repr(self.table), repr(self.db))
                r.db(db).table_create(table, shards=3, replicas=3).run(conn)
                r.db(db).table(table).index_create("abbr_canon_surt_timesamp", [r.row["abbr_canon_surt"], r.row["timestamp"]]).run(conn)
                r.db(db).table(table).index_create("sha1_warc_type", [r.row["sha1base32"], r.row["warc_type"]]).run(conn)
                # r.db(self.db).table_create(self.table, primary_key="canon_surt", shards=self.shards, replicas=self.replicas).run(conn)
                # r.db(self.db).table(self.table).index_create("timestamp").run(conn)
                # r.db(self.db).table(self.table).index_create("sha1base32").run(conn)

