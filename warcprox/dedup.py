# vim:set sw=4 et:

from __future__ import absolute_import

try:
    import dbm.gnu as dbm_gnu
except ImportError:
    try:
        import gdbm as dbm_gnu
    except ImportError:
        import anydbm as dbm_gnu

import logging
import os
import json
from hanzo import warctools
import warcprox
import rethinkdb
r = rethinkdb
import random

class DedupDb(object):
    logger = logging.getLogger("warcprox.dedup.DedupDb")

    def __init__(self, dbm_file='./warcprox-dedup.db', options=warcprox.Options()):
        if os.path.exists(dbm_file):
            self.logger.info('opening existing deduplication database {}'.format(dbm_file))
        else:
            self.logger.info('creating new deduplication database {}'.format(dbm_file))

        self.db = dbm_gnu.open(dbm_file, 'c')
        self.options = options

    def close(self):
        self.db.close()

    def sync(self):
        try:
            self.db.sync()
        except:
            pass

    def save(self, key, response_record):
        record_id = response_record.get_header(warctools.WarcRecord.ID).decode('latin1')
        url = response_record.get_header(warctools.WarcRecord.URL).decode('latin1')
        date = response_record.get_header(warctools.WarcRecord.DATE).decode('latin1')

        py_value = {'id':record_id, 'url':url, 'date':date}
        json_value = json.dumps(py_value, separators=(',',':'))

        self.db[key] = json_value.encode('utf-8')
        self.logger.debug('dedup db saved %s:%s', key, json_value)

    def lookup(self, key):
        result = None
        if key in self.db:
            json_result = self.db[key]
            result = json.loads(json_result.decode('utf-8'))
            result['id'] = result['id'].encode('latin1')
            result['url'] = result['url'].encode('latin1')
            result['date'] = result['date'].encode('latin1')
        self.logger.debug('dedup db lookup of key=%s returning %s', key, result)
        return result

    def notify(self, recorded_url, records):
        if (records[0].get_header(warctools.WarcRecord.TYPE) == warctools.WarcRecord.RESPONSE
                and recorded_url.response_recorder.payload_size() > 0):
            key = warcprox.digest_str(recorded_url.response_recorder.payload_digest, 
                    self.options.base32)
            self.save(key, records[0])


def decorate_with_dedup_info(dedup_db, recorded_url, base32=False):
    if recorded_url.response_recorder and recorded_url.response_recorder.payload_digest:
        key = warcprox.digest_str(recorded_url.response_recorder.payload_digest, base32)
        recorded_url.dedup_info = dedup_db.lookup(key)

class RethinkDedupDb:
    logger = logging.getLogger("warcprox.dedup.RethinkDedupDb")

    def __init__(self, servers=["localhost"], db="warcprox", table="dedup", shards=3, replicas=3, options=warcprox.Options()):
        self.servers = servers
        self.db = db
        self.table = table
        self.shards = shards
        self.replicas = replicas
        self._ensure_db_table()
        self.options = options

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
                r.db(self.db).table_create(self.table, primary_key="key", shards=self.shards, replicas=self.replicas).run(conn)

    def close(self):
        pass

    def sync(self):
        pass

    def save(self, key, response_record):
        k = key.decode("utf-8") if isinstance(key, bytes) else key
        record_id = response_record.get_header(warctools.WarcRecord.ID).decode('latin1')
        url = response_record.get_header(warctools.WarcRecord.URL).decode('latin1')
        date = response_record.get_header(warctools.WarcRecord.DATE).decode('latin1')
        record = {'key':k,'url':url,'date':date,'id':record_id}
        with self._random_server_connection() as conn:
            result = r.db(self.db).table(self.table).insert(record,conflict="replace").run(conn)
            if sorted(result.values()) != [0,0,0,0,0,1] and [result["deleted"],result["skipped"],result["errors"]] != [0,0,0]:
                raise Exception("unexpected result %s saving %s", result, record)
            self.logger.debug('dedup db saved %s:%s', key, record)

    def lookup(self, key):
        k = key.decode("utf-8") if isinstance(key, bytes) else key
        with self._random_server_connection() as conn:
            result = r.db(self.db).table(self.table).get(k).run(conn)
            if result:
                for x in result:
                    result[x] = result[x].encode("utf-8")
            self.logger.debug('dedup db lookup of key=%s returning %s', key, result)
            return result

    def notify(self, recorded_url, records):
        if (records[0].get_header(warctools.WarcRecord.TYPE) == warctools.WarcRecord.RESPONSE
                and recorded_url.response_recorder.payload_size() > 0):
            key = warcprox.digest_str(recorded_url.response_recorder.payload_digest, 
                    self.options.base32)
            self.save(key, records[0])
