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
from hanzo import warctools
import collections
import doublethink
import json
import logging
import os
from rethinkdb import RethinkDB; r = RethinkDB()
import sqlite3
import threading
import time
import urlcanon
import warcprox

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

def unravel_buckets(url, warcprox_meta):
    '''
    Unravels bucket definitions in Warcprox-Meta header. Each bucket
    definition can either be a string, which signifies the name of the
    bucket, or a dict. If a dict it is expected to have at least an item
    with key 'bucket' whose value is the name of the bucket. The other
    currently recognized item is 'tally-domains', which if supplied should
    be a list of domains. This instructs warcprox to additionally tally
    substats of the given bucket by domain. Host stats are stored in the
    stats table under the key '{parent-bucket}:{domain(normalized)}'.

    Returns:
        list of strings

    Example Warcprox-Meta header (a real one will likely have other
    sections besides 'stats'):

    Warcprox-Meta: {"stats":{"buckets":["bucket1",{"bucket":"bucket2","tally-domains":["foo.bar.com","192.168.10.20"}]}}

    In this case the return value would be
    ["bucket1","bucket2","bucket2:foo.bar.com","bucket2:192.168.10.20"]
    '''
    buckets = ["__all__"]
    if (warcprox_meta and "stats" in warcprox_meta
            and "buckets" in warcprox_meta["stats"]):
        for bucket in warcprox_meta["stats"]["buckets"]:
            if isinstance(bucket, dict):
                if not 'bucket' in bucket:
                    self.logger.warning(
                            'ignoring invalid stats bucket in '
                            'warcprox-meta header %s', bucket)
                    continue
                buckets.append(bucket['bucket'])
                if bucket.get('tally-domains'):
                    canon_url = urlcanon.semantic(url)
                    for domain in bucket['tally-domains']:
                        domain = urlcanon.normalize_host(domain).decode('ascii')
                        if urlcanon.url_matches_domain(canon_url, domain):
                            buckets.append(
                                    '{}:{}'.format(bucket['bucket'], domain))
            else:
                buckets.append(bucket)
    else:
        buckets.append("__unspecified__")

    return buckets

class StatsProcessor(warcprox.BaseBatchPostfetchProcessor):
    logger = logging.getLogger("warcprox.stats.StatsProcessor")

    def _startup(self):
        if os.path.exists(self.options.stats_db_file):
            self.logger.info(
                    'opening existing stats database %s',
                    self.options.stats_db_file)
        else:
            self.logger.info(
                    'creating new stats database %s',
                    self.options.stats_db_file)

        conn = sqlite3.connect(self.options.stats_db_file)
        conn.execute(
                'create table if not exists buckets_of_stats ('
                '  bucket varchar(300) primary key,'
                '  stats varchar(4000)'
                ');')
        conn.commit()
        conn.close()

        self.logger.info(
                'created table buckets_of_stats in %s',
                self.options.stats_db_file)

    def _process_batch(self, batch):
        batch_buckets = self._tally_batch(batch)
        self._update_db(batch_buckets)
        logging.trace('updated stats from batch of %s', len(batch))

    def _update_db(self, batch_buckets):
        conn = sqlite3.connect(self.options.stats_db_file)
        for bucket in batch_buckets:
            bucket_stats = batch_buckets[bucket]

            cursor = conn.execute(
                    'select stats from buckets_of_stats where bucket=?',
                    (bucket,))
            result_tuple = cursor.fetchone()
            cursor.close()

            if result_tuple:
                old_bucket_stats = json.loads(result_tuple[0])

                bucket_stats['total']['urls'] += old_bucket_stats['total']['urls']
                bucket_stats['total']['wire_bytes'] += old_bucket_stats['total']['wire_bytes']
                bucket_stats['revisit']['urls'] += old_bucket_stats['revisit']['urls']
                bucket_stats['revisit']['wire_bytes'] += old_bucket_stats['revisit']['wire_bytes']
                bucket_stats['new']['urls'] += old_bucket_stats['new']['urls']
                bucket_stats['new']['wire_bytes'] += old_bucket_stats['new']['wire_bytes']

            json_value = json.dumps(bucket_stats, separators=(',',':'))
            conn.execute(
                    'insert or replace into buckets_of_stats '
                    '(bucket, stats) values (?, ?)', (bucket, json_value))
            conn.commit()
        conn.close()

    def _tally_batch(self, batch):
        batch_buckets = {}
        for recorded_url in batch:
            if isinstance(recorded_url, warcprox.warcproxy.FailedUrl):
                continue
            for bucket in self.buckets(recorded_url):
                bucket_stats = batch_buckets.get(bucket)
                if not bucket_stats:
                    bucket_stats = _empty_bucket(bucket)
                    batch_buckets[bucket] = bucket_stats

                bucket_stats["total"]["urls"] += 1
                bucket_stats["total"]["wire_bytes"] += recorded_url.size

                if recorded_url.warc_records:
                    if recorded_url.warc_records[0].type == b'revisit':
                        bucket_stats["revisit"]["urls"] += 1
                        bucket_stats["revisit"]["wire_bytes"] += recorded_url.size
                    else:
                        bucket_stats["new"]["urls"] += 1
                        bucket_stats["new"]["wire_bytes"] += recorded_url.size
        return batch_buckets

    def value(self, bucket0="__all__", bucket1=None, bucket2=None):
        conn = sqlite3.connect(self.options.stats_db_file)
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

    def buckets(self, recorded_url):
        return unravel_buckets(recorded_url.url, recorded_url.warcprox_meta)

class RethinkStatsProcessor(StatsProcessor):
    logger = logging.getLogger("warcprox.stats.RethinkStatsProcessor")

    def __init__(self, options=warcprox.Options()):
        StatsProcessor.__init__(self, options)

        parsed = doublethink.parse_rethinkdb_url(options.rethinkdb_stats_url)
        self.rr = doublethink.Rethinker(
                servers=parsed.hosts, db=parsed.database)
        self.table = parsed.table
        self.replicas = min(3, len(self.rr.servers))

    def _startup(self):
        self._ensure_db_table()

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
                    "replicas=%r", self.table, self.rr.dbname, 1,
                    self.replicas)
            self.rr.table_create(
                    self.table, primary_key="bucket", shards=1,
                    replicas=self.replicas).run()

    def _update_db(self, batch_buckets):
        # XXX can all the buckets be done in one query?
        for bucket in batch_buckets:
            result = self._bucket_batch_update_reql(
                    bucket, batch_buckets[bucket]).run()
            if (not result['inserted'] and not result['replaced']
                    or sorted(result.values()) != [0,0,0,0,0,1]):
                self.logger.error(
                        'unexpected result {} updating stats {}'.format(
                            result, batch_buckets[bucket]))

    def _bucket_batch_update_reql(self, bucket, new):
        return self.rr.table(self.table).get(bucket).replace(
            lambda old: r.branch(
                old.eq(None), new, old.merge({
                    'total': {
                        'urls': old['total']['urls'].add(new['total']['urls']),
                        'wire_bytes': old['total']['wire_bytes'].add(
                            new['total']['wire_bytes']),
                        },
                    'new': {
                        'urls': old['new']['urls'].add(new['new']['urls']),
                        'wire_bytes': old['new']['wire_bytes'].add(
                            new['new']['wire_bytes']),
                        },
                    'revisit': {
                        'urls': old['revisit']['urls'].add(
                            new['revisit']['urls']),
                        'wire_bytes': old['revisit']['wire_bytes'].add(
                            new['revisit']['wire_bytes']),
                        },
                })))

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

class RunningStats:
    '''
    In-memory stats for measuring overall warcprox performance.
    '''
    def __init__(self):
        self.urls = 0
        self.warc_bytes = 0
        self._lock = threading.RLock()
        self.first_snap_time = time.time()
        # snapshot every minute since the beginning of time
        self.minute_snaps = [(self.first_snap_time, 0, 0)]
        # snapshot every 10 seconds for the last 2 minutes (fill with zeroes)
        self.ten_sec_snaps = collections.deque()
        for i in range(0, 13):
            self.ten_sec_snaps.append(
                    (self.first_snap_time - 120 + i * 10, 0, 0))

    def notify(self, recorded_url, records):
        if isinstance(recorded_url, warcprox.warcproxy.FailedUrl):
            return
        with self._lock:
            self.urls += 1
            if records:
                self.warc_bytes += records[-1].offset + records[-1].length - records[0].offset

    def snap(self):
        now = time.time()
        last_snap_time = self.minute_snaps[-1][0]
        need_minute_snap = (now - self.first_snap_time) // 60 > (self.minute_snaps[-1][0] - self.first_snap_time) // 60
        need_ten_sec_snap = (now - self.ten_sec_snaps[0][0]) // 10 > (self.ten_sec_snaps[-1][0] - self.ten_sec_snaps[0][0]) // 10
        if need_minute_snap:
            self.minute_snaps.append((now, self.urls, self.warc_bytes))
        if need_ten_sec_snap:
            self.ten_sec_snaps.popleft()
            self.ten_sec_snaps.append((now, self.urls, self.warc_bytes))

    def _closest_ten_sec_snap(self, t):
        # it's a deque so iterating over it is faster than indexed lookup
        closest_snap = (0, 0, 0)
        for snap in self.ten_sec_snaps:
            if abs(t - snap[0]) < abs(t - closest_snap[0]):
                closest_snap = snap
        return closest_snap

    def _closest_minute_snap(self, t):
        minutes_ago = int((time.time() - t) / 60)
        # jump to approximately where we expect the closest snap
        i = max(0, len(self.minute_snaps) - minutes_ago)
        # move back to the last one earlier than `t`
        while self.minute_snaps[i][0] > t and i > 0:
            i -= 1
        closest_snap = self.minute_snaps[i]
        # move forward until we start getting farther away from `t`
        while i < len(self.minute_snaps):
            if abs(t - self.minute_snaps[i][0]) <= abs(t - closest_snap[0]):
                closest_snap = self.minute_snaps[i]
            else:
                break
            i += 1
        return closest_snap

    def current_rates(self, time_period_minutes):
        assert time_period_minutes > 0
        with self._lock:
            now = time.time()
            urls = self.urls
            warc_bytes = self.warc_bytes

        t = now - time_period_minutes * 60
        if time_period_minutes <= 2:
            start_snap = self._closest_ten_sec_snap(t)
        else:
            start_snap = self._closest_minute_snap(t)

        elapsed = now - start_snap[0]
        logging.trace(
                'elapsed=%0.1fs urls=%s warc_bytes=%s', elapsed,
                urls - start_snap[1], warc_bytes - start_snap[2])
        return elapsed, (urls - start_snap[1]) / elapsed, (warc_bytes - start_snap[2]) / elapsed

