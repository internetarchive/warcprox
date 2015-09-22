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
import random
import warcprox

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
    logger = logging.getLogger("warcprox.stats.RethinkStatsDb")

    def __init__(self, r, table="stats", shards=3, replicas=3, options=warcprox.Options()):
        self.r = r
        self.table = table
        self.shards = shards
        self.replicas = replicas
        self._ensure_db_table()
        self.options = options

    def _ensure_db_table(self):
        dbs = self.r.db_list().run()
        if not self.r.db in dbs:
            self.logger.info("creating rethinkdb database %s", repr(self.r.db))
            self.r.db_create(self.r.db).run()
        tables = self.r.table_list().run()
        if not self.table in tables:
            self.logger.info("creating rethinkdb table %s in database %s", repr(self.table), repr(self.r.db))
            self.r.table_create(self.table, primary_key="bucket", shards=self.shards, replicas=self.replicas).run()

    def close(self):
        pass

    def sync(self):
        pass

    def value(self, bucket0="__all__", bucket1=None, bucket2=None):
        # XXX use pluck?
        bucket0_stats = self.r.table(self.table).get(bucket0).run()
        self.logger.debug('stats db lookup of bucket=%s returned %s', bucket0, bucket0_stats)
        if bucket0_stats:
            if bucket1:
                if bucket2:
                    return bucket0_stats[bucket1][bucket2]
                else:
                    return bucket0_stats[bucket1]
        return bucket0_stats

    def tally(self, recorded_url, records):
        buckets = ["__all__"]

        if (recorded_url.warcprox_meta
                and "stats" in recorded_url.warcprox_meta
                and "buckets" in recorded_url.warcprox_meta["stats"]):
            buckets.extend(recorded_url.warcprox_meta["stats"]["buckets"])
        else:
            buckets.append("__unspecified__")

        for bucket in buckets:
            bucket_stats = self.value(bucket) or _empty_bucket(bucket)

            bucket_stats["total"]["urls"] += 1
            bucket_stats["total"]["wire_bytes"] += recorded_url.size

            if records[0].get_header(warctools.WarcRecord.TYPE) == warctools.WarcRecord.REVISIT:
                bucket_stats["revisit"]["urls"] += 1
                bucket_stats["revisit"]["wire_bytes"] += recorded_url.size
            else:
                bucket_stats["new"]["urls"] += 1
                bucket_stats["new"]["wire_bytes"] += recorded_url.size

            self.logger.debug("saving %s", bucket_stats)
            result = self.r.table(self.table).insert(bucket_stats, conflict="replace").run()
            if sorted(result.values()) != [0,0,0,0,0,1] or [result["deleted"],result["skipped"],result["errors"]] != [0,0,0]:
                raise Exception("unexpected result %s saving %s", result, record)

    def notify(self, recorded_url, records):
        self.tally(recorded_url, records)

