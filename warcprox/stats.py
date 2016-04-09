#
# warcprox/stats.py - keeps statistics on what has been proxied, archived
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
import random
import warcprox
import threading
import rethinkdb as r
import datetime

def _empty_bucket(bucket):
    return {
        "bucket": bucket,
        "total": {
            "urls": 0,
            "wire_bytes": 0,
            # "warc_bytes": 0,
        },
        "new": {
            "urls": 0,
            "wire_bytes": 0,
            # "warc_bytes": 0,
        },
        "revisit": {
            "urls": 0,
            "wire_bytes": 0,
            # "warc_bytes": 0,
        },
    }

class StatsDb:
    logger = logging.getLogger("warcprox.stats.StatsDb")

    def __init__(self, dbm_file='./warcprox-stats.db', options=warcprox.Options()):
        try:
            import dbm.gnu as dbm_gnu
        except ImportError:
            try:
                import gdbm as dbm_gnu
            except ImportError:
                import anydbm as dbm_gnu

        if os.path.exists(dbm_file):
            self.logger.info('opening existing stats database {}'.format(dbm_file))
        else:
            self.logger.info('creating new stats database {}'.format(dbm_file))

        self.db = dbm_gnu.open(dbm_file, 'c')
        self.options = options

    def close(self):
        self.db.close()

    def sync(self):
        try:
            self.db.sync()
        except:
            pass

    def value(self, bucket0="__all__", bucket1=None, bucket2=None):
        # Gdbm wants str/bytes keys in python2, str/unicode keys in python3.
        # This ugliness deals with keys that arrive as unicode in py2.
        b0 = bucket0.encode("utf-8") if bucket0 and not isinstance(bucket0, str) else bucket0
        b1 = bucket1.encode("utf-8") if bucket1 and not isinstance(bucket1, str) else bucket1
        b2 = bucket2.encode("utf-8") if bucket2 and not isinstance(bucket2, str) else bucket2

        if b0 in self.db:
            bucket0_stats = json.loads(self.db[b0].decode("utf-8"))
            if b1:
                if b2:
                    return bucket0_stats[b1][b2]
                else:
                    return bucket0_stats[b1]
            else:
                return bucket0_stats
        else:
            return None

    def notify(self, recorded_url, records):
        self.tally(recorded_url, records)

    def tally(self, recorded_url, records):
        buckets = ["__all__"]

        if (recorded_url.warcprox_meta
                and "stats" in recorded_url.warcprox_meta
                and "buckets" in recorded_url.warcprox_meta["stats"]):
            buckets.extend(recorded_url.warcprox_meta["stats"]["buckets"])
        else:
            buckets.append("__unspecified__")

        for bucket in buckets:
            # Gdbm wants str/bytes keys in python2, str/unicode keys in python3.
            # This ugliness deals with keys that arrive as unicode in py2.
            b = bucket.encode("utf-8") if bucket and not isinstance(bucket, str) else bucket
            if b in self.db:
                bucket_stats = json.loads(self.db[b].decode("utf-8"))
            else:
                bucket_stats = _empty_bucket(b)

            bucket_stats["total"]["urls"] += 1
            bucket_stats["total"]["wire_bytes"] += recorded_url.size

            if records[0].get_header(warctools.WarcRecord.TYPE) == warctools.WarcRecord.REVISIT:
                bucket_stats["revisit"]["urls"] += 1
                bucket_stats["revisit"]["wire_bytes"] += recorded_url.size
            else:
                bucket_stats["new"]["urls"] += 1
                bucket_stats["new"]["wire_bytes"] += recorded_url.size

            self.db[b] = json.dumps(bucket_stats, separators=(',',':')).encode("utf-8")

class RethinkStatsDb:
    """Updates database in batch every 0.5 seconds"""
    logger = logging.getLogger("warcprox.stats.RethinkStatsDb")

    def __init__(self, rethinker, table="stats", shards=None, replicas=None, options=warcprox.Options()):
        self.r = rethinker
        self.table = table
        self.shards = shards or 1  # 1 shard by default because it's probably a small table
        self.replicas = replicas or min(3, len(self.r.servers))
        self._ensure_db_table()
        self.options = options

        self._stop = threading.Event()
        self._batch_lock = threading.RLock()
        with self._batch_lock:
            self._batch = {}

        self._update_batch() # starts repeating timer

    def _update_batch(self):
        with self._batch_lock:
            if len(self._batch) > 0:
                # XXX can this be done in one query?
                # r.db("archiveit_brozzler").table("test00").get_all(*["foo01","foo"])...
                # >>> r.db("archiveit_brozzler").table("test00").get("foo01").replace(lambda old: r.branch(old.eq(None), {"id":"foo01", "a":{"b":88}}, old.merge({"a":{"b":old["a"]["b"].add(3)}}))).run(conn)
                for k in self._batch:
                    result = self.r.table(self.table).get(k).replace(
                            lambda old: r.branch(old.eq(None), self._batch[k], old.merge(
                                {
                                    "total": {
                                        "urls": old["total"]["urls"].add(self._batch[k]["total"]["urls"]),
                                        "wire_bytes": old["total"]["wire_bytes"].add(self._batch[k]["total"]["wire_bytes"]),
                                    },
                                    "new": {
                                        "urls": old["new"]["urls"].add(self._batch[k]["new"]["urls"]),
                                        "wire_bytes": old["new"]["wire_bytes"].add(self._batch[k]["new"]["wire_bytes"]),
                                    },
                                    "revisit": {
                                        "urls": old["revisit"]["urls"].add(self._batch[k]["revisit"]["urls"]),
                                        "wire_bytes": old["revisit"]["wire_bytes"].add(self._batch[k]["revisit"]["wire_bytes"]),
                                    },
                                }
                            ))).run()
                    if not result["inserted"] and not result["replaced"] or sorted(result.values()) != [0,0,0,0,0,1]:
                        raise Exception("unexpected result %s updating stats %s" % (result, self._batch[k]))
                self._batch = {}

        if not self._stop.is_set():
            self._timer = threading.Timer(2.0, self._update_batch)
            self._timer.name = "RethinkStats-batch-update-timer-%s" % datetime.datetime.utcnow().isoformat()
            self._timer.start()
        else:
            self.logger.info("finished")

    def _ensure_db_table(self):
        dbs = self.r.db_list().run()
        if not self.r.dbname in dbs:
            self.logger.info("creating rethinkdb database %s", repr(self.r.dbname))
            self.r.db_create(self.r.dbname).run()
        tables = self.r.table_list().run()
        if not self.table in tables:
            self.logger.info("creating rethinkdb table %s in database %s shards=%s replicas=%s",
                             repr(self.table), repr(self.r.dbname), self.shards, self.replicas)
            self.r.table_create(self.table, primary_key="bucket", shards=self.shards, replicas=self.replicas).run()

    def close(self):
        self.logger.info("closing rethinkdb stats table")
        self._stop.set()
        self._timer.join()

    def sync(self):
        pass

    def value(self, bucket0="__all__", bucket1=None, bucket2=None):
        bucket0_stats = self.r.table(self.table).get(bucket0).run()
        self.logger.debug('stats db lookup of bucket=%s returned %s', bucket0, bucket0_stats)
        if bucket0_stats:
            if bucket1:
                if bucket2:
                    return bucket0_stats[bucket1][bucket2]
                else:
                    return bucket0_stats[bucket1]
        return bucket0_stats

    def _tally(self, buckets, size, is_revisit):
        with self._batch_lock:
            for bucket in buckets:
                bucket_stats = self._batch.setdefault(bucket, _empty_bucket(bucket))

                bucket_stats["total"]["urls"] += 1
                bucket_stats["total"]["wire_bytes"] += size

                if is_revisit:
                    bucket_stats["revisit"]["urls"] += 1
                    bucket_stats["revisit"]["wire_bytes"] += size
                else:
                    bucket_stats["new"]["urls"] += 1
                    bucket_stats["new"]["wire_bytes"] += size

    def _extract_stats_info(self, recorded_url, records):
        buckets = ["__all__"]

        if (recorded_url.warcprox_meta
                and "stats" in recorded_url.warcprox_meta
                and "buckets" in recorded_url.warcprox_meta["stats"]):
            buckets.extend(recorded_url.warcprox_meta["stats"]["buckets"])
        else:
            buckets.append("__unspecified__")

        is_revisit = records[0].get_header(warctools.WarcRecord.TYPE) == warctools.WarcRecord.REVISIT

        return buckets, recorded_url.size, is_revisit

    def tally(self, recorded_url, records):
        self._tally(*self._extract_stats_info(recorded_url, records))

    def notify(self, recorded_url, records):
        self.tally(recorded_url, records)

