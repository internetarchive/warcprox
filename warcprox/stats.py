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

class StatsDb:
    logger = logging.getLogger("warcprox.stats.StatsDb")

    def __init__(self, dbm_file='./warcprox-stats.db'):
        if os.path.exists(dbm_file):
            self.logger.info('opening existing stats database {}'.format(dbm_file))
        else:
            self.logger.info('creating new stats database {}'.format(dbm_file))

        self.db = dbm_gnu.open(dbm_file, 'c')

    def close(self):
        self.db.close()

    def sync(self):
        try:
            self.db.sync()
        except:
            pass

    def _empty_bucket(self):
        return {
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
                bucket_stats = self._empty_bucket() 

            bucket_stats["total"]["urls"] += 1
            bucket_stats["total"]["wire_bytes"] += recorded_url.size

            if records[0].get_header(warctools.WarcRecord.TYPE) == warctools.WarcRecord.REVISIT:
                bucket_stats["revisit"]["urls"] += 1
                bucket_stats["revisit"]["wire_bytes"] += recorded_url.size
            else:
                bucket_stats["new"]["urls"] += 1
                bucket_stats["new"]["wire_bytes"] += recorded_url.size

            self.db[bucket] = json.dumps(bucket_stats, separators=(',',':')).encode("utf-8")

