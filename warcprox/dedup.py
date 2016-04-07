#
# warcprox/dedup.py - identical payload digest deduplication
#
# Copyright (C) 2013-2016 Internet Archive
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.
#

from __future__ import absolute_import

import logging
import os
import json
from hanzo import warctools
import warcprox
import random

class DedupDb(object):
    logger = logging.getLogger("warcprox.dedup.DedupDb")

    def __init__(self, dbm_file='./warcprox-dedup.db', options=warcprox.Options()):
        try:
            import dbm.gnu as dbm_gnu
        except ImportError:
            try:
                import gdbm as dbm_gnu
            except ImportError:
                import anydbm as dbm_gnu

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

    def save(self, digest_key, response_record, bucket=""):
        record_id = response_record.get_header(warctools.WarcRecord.ID).decode('latin1')
        url = response_record.get_header(warctools.WarcRecord.URL).decode('latin1')
        date = response_record.get_header(warctools.WarcRecord.DATE).decode('latin1')

        key = digest_key + b"|" + bucket.encode("utf-8")

        py_value = {'id':record_id, 'url':url, 'date':date}
        json_value = json.dumps(py_value, separators=(',',':'))

        self.db[key] = json_value.encode('utf-8')
        self.logger.debug('dedup db saved %s:%s', key, json_value)

    def lookup(self, digest_key, bucket=""):
        result = None
        key = digest_key + b"|" + bucket.encode("utf-8")
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
            digest_key = warcprox.digest_str(recorded_url.response_recorder.payload_digest,
                self.options.base32)
            if recorded_url.warcprox_meta and "captures-bucket" in recorded_url.warcprox_meta:
                self.save(digest_key, records[0], bucket=recorded_url.warcprox_meta["captures-bucket"])
            else:
                self.save(digest_key, records[0])


def decorate_with_dedup_info(dedup_db, recorded_url, base32=False):
    if (recorded_url.response_recorder
            and recorded_url.response_recorder.payload_digest
            and recorded_url.response_recorder.payload_size() > 0):
        digest_key = warcprox.digest_str(recorded_url.response_recorder.payload_digest, base32)
        if recorded_url.warcprox_meta and "captures-bucket" in recorded_url.warcprox_meta:
            recorded_url.dedup_info = dedup_db.lookup(digest_key, recorded_url.warcprox_meta["captures-bucket"])
        else:
            recorded_url.dedup_info = dedup_db.lookup(digest_key)

class RethinkDedupDb:
    logger = logging.getLogger("warcprox.dedup.RethinkDedupDb")

    def __init__(self, r, table="dedup", shards=None, replicas=None, options=warcprox.Options()):
        self.r = r
        self.table = table
        self.shards = shards or len(r.servers)
        self.replicas = replicas or min(3, len(r.servers))
        self._ensure_db_table()
        self.options = options

    def _ensure_db_table(self):
        dbs = self.r.db_list().run()
        if not self.r.dbname in dbs:
            self.logger.info("creating rethinkdb database %s", repr(self.r.dbname))
            self.r.db_create(self.r.dbname).run()
        tables = self.r.table_list().run()
        if not self.table in tables:
            self.logger.info("creating rethinkdb table %s in database %s shards=%s replicas=%s",
                             repr(self.table), repr(self.r.dbname), self.shards, self.replicas)
            self.r.table_create(self.table, primary_key="key", shards=self.shards, replicas=self.replicas).run()

    def close(self):
        pass

    def sync(self):
        pass

    def save(self, digest_key, response_record, bucket=""):
        k = digest_key.decode("utf-8") if isinstance(digest_key, bytes) else digest_key
        k = "{}|{}".format(k, bucket)
        record_id = response_record.get_header(warctools.WarcRecord.ID).decode('latin1')
        url = response_record.get_header(warctools.WarcRecord.URL).decode('latin1')
        date = response_record.get_header(warctools.WarcRecord.DATE).decode('latin1')
        record = {'key':k,'url':url,'date':date,'id':record_id}
        result = self.r.table(self.table).insert(record,conflict="replace").run()
        if sorted(result.values()) != [0,0,0,0,0,1] and [result["deleted"],result["skipped"],result["errors"]] != [0,0,0]:
            raise Exception("unexpected result %s saving %s", result, record)
        self.logger.debug('dedup db saved %s:%s', k, record)

    def lookup(self, digest_key, bucket=""):
        k = digest_key.decode("utf-8") if isinstance(digest_key, bytes) else digest_key
        k = "{}|{}".format(k, bucket)
        result = self.r.table(self.table).get(k).run()
        if result:
            for x in result:
                result[x] = result[x].encode("utf-8")
        self.logger.debug('dedup db lookup of key=%s returning %s', k, result)
        return result

    def notify(self, recorded_url, records):
        if (records[0].get_header(warctools.WarcRecord.TYPE) == warctools.WarcRecord.RESPONSE
                and recorded_url.response_recorder.payload_size() > 0):
            digest_key = warcprox.digest_str(recorded_url.response_recorder.payload_digest,
                    self.options.base32)
            if recorded_url.warcprox_meta and "captures-bucket" in recorded_url.warcprox_meta:
                self.save(digest_key, records[0], bucket=recorded_url.warcprox_meta["captures-bucket"])
            else:
                self.save(digest_key, records[0])
