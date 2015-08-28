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
import rethinkdb
r = rethinkdb
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
        if bucket0 in self.db:
            bucket0_stats = json.loads(self.db[bucket0].decode("utf-8"))
            if bucket1:
                if bucket2:
                    return bucket0_stats[bucket1][bucket2]
                else:
                    return bucket0_stats[bucket1]
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
            if bucket in self.db:
                bucket_stats = json.loads(self.db[bucket].decode("utf-8"))
            else:
                bucket_stats = _empty_bucket(bucket) 

            bucket_stats["total"]["urls"] += 1
            bucket_stats["total"]["wire_bytes"] += recorded_url.size

            if records[0].get_header(warctools.WarcRecord.TYPE) == warctools.WarcRecord.REVISIT:
                bucket_stats["revisit"]["urls"] += 1
                bucket_stats["revisit"]["wire_bytes"] += recorded_url.size
            else:
                bucket_stats["new"]["urls"] += 1
                bucket_stats["new"]["wire_bytes"] += recorded_url.size

            self.db[bucket] = json.dumps(bucket_stats, separators=(',',':')).encode("utf-8")

class RethinkStatsDb:
    logger = logging.getLogger("warcprox.stats.RethinkStatsDb")

    def __init__(self, servers=["localhost"], db="warcprox", table="stats", shards=3, replicas=3, options=warcprox.Options()):
        self.r = warcprox.Rethinker(servers, db)
        self.table = table
        self.shards = shards
        self.replicas = replicas
        self._ensure_db_table()
        self.options = options

    def _ensure_db_table(self):
        dbs = self.r.run(r.db_list())
        if not self.r.db in dbs:
            self.logger.info("creating rethinkdb database %s", repr(self.r.db))
            self.r.run(r.db_create(self.r.db))
        tables = self.r.run(r.table_list())
        if not self.table in tables:
            self.logger.info("creating rethinkdb table %s in database %s", repr(self.table), repr(self.r.db))
            self.r.run(r.table_create(self.table, primary_key="bucket", shards=self.shards, replicas=self.replicas))

    def close(self):
        pass

    def sync(self):
        pass

    def value(self, bucket0="__all__", bucket1=None, bucket2=None):
        # XXX use pluck?
        bucket0_stats = self.r.run(r.table(self.table).get(bucket0))
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
            result = self.r.run(r.table(self.table).insert(bucket_stats, conflict="replace"))
            if sorted(result.values()) != [0,0,0,0,0,1] or [result["deleted"],result["skipped"],result["errors"]] != [0,0,0]:
                raise Exception("unexpected result %s saving %s", result, record)

    def notify(self, recorded_url, records):
        self.tally(recorded_url, records)

