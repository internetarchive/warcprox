'''
warcprox/stats.py - keeps statistics on what has been archived

Copyright (C) 2013-2017 Internet Archive

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
USA.
'''

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
import urlcanon
import sqlite3
import copy

def _empty_bucket(bucket):
    return {
        "bucket": bucket,
        "total": {
            "urls": 0,
            "wire_bytes": 0,
        },
        "new": {
            "urls": 0,
            "wire_bytes": 0,
        },
        "revisit": {
            "urls": 0,
            "wire_bytes": 0,
        },
    }

def summy_merge(e, f):
    if isinstance(e, (int, float)) and isinstance(f, (int, float)):
        return e + f
    elif (e is not None and not hasattr(e, 'keys')) or (
            f is not None and not hasattr(f, 'keys')):
        return e or f
    else:
        result = {}
        all_keys = set(e.keys()).union(f.keys())
        for k in all_keys:
            m = e.get(k)
            n = f.get(k)
            if m is None and isinstance(n, (int, float)):
                m = 0
            elif n is None and isinstance(m, (int, float)):
                n = 0
            else:
                m = m or {}
                n = n or {}
            result[k] = summy_merge(m, n)
        return result

class StatsDb:
    logger = logging.getLogger("warcprox.stats.StatsDb")

    def __init__(self, file='./warcprox.sqlite', options=warcprox.Options()):
        self.file = file
        self.options = options
        self._lock = threading.RLock()

    def start(self):
        with self._lock:
            if os.path.exists(self.file):
                self.logger.info(
                        'opening existing stats database %s', self.file)
            else:
                self.logger.info(
                        'creating new stats database %s', self.file)

            conn = sqlite3.connect(self.file)
            conn.execute(
                    'create table if not exists buckets_of_stats ('
                    '  bucket varchar(300) primary key,'
                    '  stats varchar(4000)'
                    ');')
            conn.commit()
            conn.close()

        self.logger.info('created table buckets_of_stats in %s', self.file)

    def stop(self):
        pass

    def close(self):
        pass

    def sync(self):
        pass

    def value(self, bucket0="__all__", bucket1=None, bucket2=None):
        conn = sqlite3.connect(self.file)
        cursor = conn.execute(
                'select stats from buckets_of_stats where bucket = ?',
                (bucket0,))
        result_tuple = cursor.fetchone()
        conn.close()
        if result_tuple:
            bucket0_stats = json.loads(result_tuple[0])
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

    def buckets(self, recorded_url):
        '''
        Unravels bucket definitions in Warcprox-Meta header. Each bucket
        definition can either be a string, which signifies the name of the
        bucket, or a dict. If a dict it is expected to have at least an item
        with key 'bucket' whose value is the name of the bucket. The other
        currently recognized item is 'tally-domains', which if supplied should
        be a list of domains. This instructs warcprox to additionally tally
        substats of the given bucket by domain. Host stats are stored in the
        stats table under the key '{parent-bucket}:{domain(normalized)}'.

        Example Warcprox-Meta header (a real one will likely have other
        sections besides 'stats'):

        Warcprox-Meta: {'stats':{'buckets':['bucket1',{'bucket':'bucket2','tally-domains':['foo.bar.com','192.168.10.20'}]}}
        '''
        buckets = ["__all__"]
        if (recorded_url.warcprox_meta
                and "stats" in recorded_url.warcprox_meta
                and "buckets" in recorded_url.warcprox_meta["stats"]):
            for bucket in recorded_url.warcprox_meta["stats"]["buckets"]:
                if isinstance(bucket, dict):
                    if not 'bucket' in bucket:
                        self.logger.warn(
                                'ignoring invalid stats bucket in '
                                'warcprox-meta header %s', bucket)
                        continue
                    buckets.append(bucket['bucket'])
                    if bucket.get('tally-domains'):
                        url = urlcanon.semantic(recorded_url.url)
                        for domain in bucket['tally-domains']:
                            domain = urlcanon.normalize_host(domain).decode('ascii')
                            if urlcanon.url_matches_domain(url, domain):
                                buckets.append(
                                        '%s:%s' % (bucket['bucket'], domain))
                else:
                    buckets.append(bucket)
        else:
            buckets.append("__unspecified__")

        return buckets

    def tally(self, recorded_url, records):
        with self._lock:
            conn = sqlite3.connect(self.file)

            for bucket in self.buckets(recorded_url):
                cursor = conn.execute(
                        'select stats from buckets_of_stats where bucket=?',
                        (bucket,))

                result_tuple = cursor.fetchone()
                cursor.close()
                if result_tuple:
                    bucket_stats = json.loads(result_tuple[0])
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

                json_value = json.dumps(bucket_stats, separators=(',',':'))
                conn.execute(
                        'insert or replace into buckets_of_stats '
                        '(bucket, stats) values (?, ?)', (bucket, json_value))
                conn.commit()

            conn.close()

class RethinkStatsDb(StatsDb):
    """Updates database in batch every 2.0 seconds"""
    logger = logging.getLogger("warcprox.stats.RethinkStatsDb")

    def __init__(self, rethinker, table="stats", shards=None, replicas=None, options=warcprox.Options()):
        self.rr = rethinker
        self.table = table
        self.shards = shards or 1  # 1 shard by default because it's probably a small table
        self.replicas = replicas or min(3, len(self.rr.servers))
        self._ensure_db_table()
        self.options = options

        self._stop = threading.Event()
        self._batch_lock = threading.RLock()
        with self._batch_lock:
            self._batch = {}
        self._timer = None

    def start(self):
        """Starts batch update repeating timer."""
        self._update_batch() # starts repeating timer

    def _bucket_batch_update_reql(self, bucket, batch):
        return self.rr.table(self.table).get(bucket).replace(
            lambda old: r.branch(
                old.eq(None), batch[bucket], old.merge({
                    "total": {
                        "urls": old["total"]["urls"].add(
                            batch[bucket]["total"]["urls"]),
                        "wire_bytes": old["total"]["wire_bytes"].add(
                            batch[bucket]["total"]["wire_bytes"]),
                        },
                    "new": {
                        "urls": old["new"]["urls"].add(
                            batch[bucket]["new"]["urls"]),
                        "wire_bytes": old["new"]["wire_bytes"].add(
                            batch[bucket]["new"]["wire_bytes"]),
                        },
                    "revisit": {
                        "urls": old["revisit"]["urls"].add(
                            batch[bucket]["revisit"]["urls"]),
                        "wire_bytes": old["revisit"]["wire_bytes"].add(
                            batch[bucket]["revisit"]["wire_bytes"]),
                        },
                })))

    def _update_batch(self):
        with self._batch_lock:
            batch_copy = copy.deepcopy(self._batch)
            self._batch = {}
        try:
            if len(batch_copy) > 0:
                # XXX can all the buckets be done in one query?
                for bucket in batch_copy:
                    result = self._bucket_batch_update_reql(
                            bucket, batch_copy).run()
                    if (not result["inserted"] and not result["replaced"]
                            or sorted(result.values()) != [0,0,0,0,0,1]):
                        raise Exception(
                                "unexpected result %s updating stats %s" % (
                                    result, batch_copy[bucket]))
        except Exception as e:
            self.logger.error("problem updating stats", exc_info=True)
            # now we need to restore the stats that didn't get saved to the
            # batch so that they are saved in the next call to _update_batch()
            with self._batch_lock:
                self._batch = summy_merge(self._batch, batch_copy)
        finally:
           if not self._stop.is_set():
               self._timer = threading.Timer(2.0, self._update_batch)
               self._timer.name = "RethinkStats-batch-update-timer-%s" % (
                       datetime.datetime.utcnow().isoformat())
               self._timer.start()
           else:
               self.logger.info("finished")

    def _ensure_db_table(self):
        dbs = self.rr.db_list().run()
        if not self.rr.dbname in dbs:
            self.logger.info(
                    "creating rethinkdb database %r", self.rr.dbname)
            self.rr.db_create(self.rr.dbname).run()
        tables = self.rr.table_list().run()
        if not self.table in tables:
            self.logger.info(
                    "creating rethinkdb table %r in database %r shards=%r "
                    "replicas=%r", self.table, self.rr.dbname, self.shards,
                    self.replicas)
            self.rr.table_create(
                    self.table, primary_key="bucket", shards=self.shards,
                    replicas=self.replicas).run()

    def close(self):
        self.stop()

    def stop(self):
        self.logger.info("stopping rethinkdb stats table batch updates")
        self._stop.set()
        if self._timer:
            self._timer.join()

    def sync(self):
        pass

    def value(self, bucket0="__all__", bucket1=None, bucket2=None):
        bucket0_stats = self.rr.table(self.table).get(bucket0).run()
        self.logger.debug(
                'stats db lookup of bucket=%s returned %s',
                bucket0, bucket0_stats)
        if bucket0_stats:
            if bucket1:
                if bucket2:
                    return bucket0_stats[bucket1][bucket2]
                else:
                    return bucket0_stats[bucket1]
        return bucket0_stats

    def tally(self, recorded_url, records):
        buckets = self.buckets(recorded_url)
        is_revisit = records[0].get_header(
                warctools.WarcRecord.TYPE) == warctools.WarcRecord.REVISIT
        with self._batch_lock:
            for bucket in buckets:
                bucket_stats = self._batch.setdefault(
                        bucket, _empty_bucket(bucket))

                bucket_stats["total"]["urls"] += 1
                bucket_stats["total"]["wire_bytes"] += recorded_url.size

                if is_revisit:
                    bucket_stats["revisit"]["urls"] += 1
                    bucket_stats["revisit"]["wire_bytes"] += recorded_url.size
                else:
                    bucket_stats["new"]["urls"] += 1
                    bucket_stats["new"]["wire_bytes"] += recorded_url.size

    def notify(self, recorded_url, records):
        self.tally(recorded_url, records)

