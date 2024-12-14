'''
warcprox/dedup.py - identical payload digest deduplication using sqlite db

Copyright (C) 2013-2021 Internet Archive

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
import logging
import os
import json
from hanzo import warctools
import warcprox
import sqlite3
import doublethink
import datetime
import urllib3
from urllib3.exceptions import HTTPError
import collections
from concurrent import futures
from functools import lru_cache

urllib3.disable_warnings()

class DedupableMixin:
    def __init__(self, options=warcprox.Options()):
        self.min_text_size = options.dedup_min_text_size or 0
        self.min_binary_size = options.dedup_min_binary_size or 0
        self.dedup_only_with_bucket = options.dedup_only_with_bucket or False

    def should_dedup(self, recorded_url):
        """Check if we should try to run dedup on resource based on payload
        size compared with min text/binary dedup size options.
        When we use option --dedup-only-with-bucket, `dedup-buckets` is required
        in Warcprox-Meta to perform dedup.
        If recorded_url.do_not_archive is True, we skip dedup. This record will
        not be written to WARC anyway.
        Return Boolean.
        """
        if recorded_url.do_not_archive:
            return False
        if self.dedup_only_with_bucket and "dedup-buckets" not in recorded_url.warcprox_meta:
            return False
        if recorded_url.is_text():
            return recorded_url.response_recorder.payload_size() > self.min_text_size
        else:
            return recorded_url.response_recorder.payload_size() > self.min_binary_size

class DedupLoader(warcprox.BaseStandardPostfetchProcessor, DedupableMixin):
    def __init__(self, dedup_db, options=warcprox.Options()):
        warcprox.BaseStandardPostfetchProcessor.__init__(self, options=options)
        DedupableMixin.__init__(self, options)
        self.dedup_db = dedup_db

    def _process_url(self, recorded_url):
        if isinstance(recorded_url, warcprox.warcproxy.FailedUrl):
            return
        if (recorded_url.response_recorder
                and recorded_url.payload_digest
                and self.should_dedup(recorded_url)):
            digest_key = warcprox.digest_str(recorded_url.payload_digest, self.options.base32)
            if recorded_url.warcprox_meta and "dedup-buckets" in recorded_url.warcprox_meta:
                for bucket, bucket_mode in recorded_url.warcprox_meta["dedup-buckets"].items():
                    recorded_url.dedup_info = self.dedup_db.lookup(
                        digest_key, bucket, recorded_url.url)
                    if recorded_url.dedup_info:
                        # we found an existing capture
                        break
            else:
                recorded_url.dedup_info = self.dedup_db.lookup(
                    digest_key, url=recorded_url.url)

class DedupDb(DedupableMixin):
    logger = logging.getLogger("warcprox.dedup.DedupDb")

    def __init__(
            self, file='./warcprox.sqlite', options=warcprox.Options()):
        DedupableMixin.__init__(self, options)
        self.file = file
        self.options = options

    def start(self):
        if os.path.exists(self.file):
            self.logger.info(
                    'opening existing deduplication database %s',
                    self.file)
        else:
            self.logger.info(
                    'creating new deduplication database %s', self.file)

        conn = sqlite3.connect(self.file)
        conn.execute(
                'create table if not exists dedup ('
                '  key varchar(300) primary key,'
                '  value varchar(4000)'
                ');')
        conn.commit()
        conn.close()

    def loader(self, *args, **kwargs):
        return DedupLoader(self, self.options)

    def storer(self, *args, **kwargs):
        return warcprox.ListenerPostfetchProcessor(self, self.options)

    def save(self, digest_key, response_record, bucket=""):
        record_id = response_record.get_header(warctools.WarcRecord.ID).decode('latin1')
        url = response_record.get_header(warctools.WarcRecord.URL).decode('latin1')
        date = response_record.get_header(warctools.WarcRecord.DATE).decode('latin1')

        key = digest_key.decode('utf-8') + "|" + bucket

        py_value = {'id':record_id, 'url':url, 'date':date}
        json_value = json.dumps(py_value, separators=(',',':'))

        conn = sqlite3.connect(self.file)
        conn.execute(
                'insert or replace into dedup (key, value) values (?, ?)',
                (key, json_value))
        conn.commit()
        conn.close()
        self.logger.debug('dedup db saved %s:%s', key, json_value)

    def lookup(self, digest_key, bucket="", url=None):
        result = None
        key = digest_key.decode('utf-8') + '|' + bucket
        conn = sqlite3.connect(self.file)
        cursor = conn.execute('select value from dedup where key = ?', (key,))
        result_tuple = cursor.fetchone()
        conn.close()
        if result_tuple:
            result = json.loads(result_tuple[0])
            result['id'] = result['id'].encode('latin1')
            result['url'] = result['url'].encode('latin1')
            result['date'] = result['date'].encode('latin1')
        self.logger.debug('dedup db lookup of key=%s returning %s', key, result)
        return result

    def notify(self, recorded_url, records):
        if (records and records[0].type == b'response'
                and self.should_dedup(recorded_url)):
            digest_key = warcprox.digest_str(
                    recorded_url.payload_digest, self.options.base32)
            if recorded_url.warcprox_meta and "dedup-buckets" in recorded_url.warcprox_meta:
                for bucket, bucket_mode in recorded_url.warcprox_meta["dedup-buckets"].items():
                    if not bucket_mode == "ro":
                        self.save(
                                digest_key, records[0],
                                bucket=bucket)
            else:
                self.save(digest_key, records[0])

class RethinkDedupDb(DedupDb, DedupableMixin):
    logger = logging.getLogger("warcprox.dedup.RethinkDedupDb")

    def __init__(self, options=warcprox.Options()):
        DedupableMixin.__init__(self, options)
        parsed = doublethink.parse_rethinkdb_url(options.rethinkdb_dedup_url)
        self.rr = doublethink.Rethinker(
                servers=parsed.hosts, db=parsed.database)
        self.table = parsed.table
        self._ensure_db_table()
        self.options = options

    def _ensure_db_table(self):
        dbs = self.rr.db_list().run()
        if not self.rr.dbname in dbs:
            self.logger.info("creating rethinkdb database %r", self.rr.dbname)
            self.rr.db_create(self.rr.dbname).run()
        tables = self.rr.table_list().run()
        if not self.table in tables:
            self.logger.info(
                    "creating rethinkdb table %r in database %r shards=%r "
                    "replicas=%r", self.table, self.rr.dbname,
                    len(self.rr.servers), min(3, len(self.rr.servers)))
            self.rr.table_create(
                    self.table, primary_key="key", shards=len(self.rr.servers),
                    replicas=min(3, len(self.rr.servers))).run()

    def start(self):
        pass

    def save(self, digest_key, response_record, bucket=""):
        k = digest_key.decode("utf-8") if isinstance(digest_key, bytes) else digest_key
        k = "{}|{}".format(k, bucket)
        record_id = response_record.get_header(warctools.WarcRecord.ID).decode('latin1')
        url = response_record.get_header(warctools.WarcRecord.URL).decode('latin1')
        date = response_record.get_header(warctools.WarcRecord.DATE).decode('latin1')
        record = {'key':k,'url':url,'date':date,'id':record_id}
        result = self.rr.table(self.table).insert(
                record, conflict="replace").run()
        if sorted(result.values()) != [0,0,0,0,0,1] and [result["deleted"],result["skipped"],result["errors"]] != [0,0,0]:
            raise Exception("unexpected result %s saving %s", result, record)
        self.logger.debug('dedup db saved %s:%s', k, record)

    def lookup(self, digest_key, bucket="", url=None):
        k = digest_key.decode("utf-8") if isinstance(digest_key, bytes) else digest_key
        k = "{}|{}".format(k, bucket)
        result = self.rr.table(self.table).get(k).run()
        if result:
            for x in result:
                result[x] = result[x].encode("utf-8")
        self.logger.debug('dedup db lookup of key=%s returning %s', k, result)
        return result

    def notify(self, recorded_url, records):
        if (records and records[0].type == b'response'
                and self.should_dedup(recorded_url)):
            digest_key = warcprox.digest_str(
                    recorded_url.payload_digest, self.options.base32)
            if recorded_url.warcprox_meta and "dedup-buckets" in recorded_url.warcprox_meta:
                for bucket, bucket_mode in recorded_url.warcprox_meta["dedup-buckets"].items():
                    if not bucket_mode == 'ro':
                        self.save(digest_key, records[0], bucket=bucket)
            else:
                self.save(digest_key, records[0])

class CdxServerDedup(DedupDb):
    """Query a CDX server to perform deduplication.
    """
    logger = logging.getLogger("warcprox.dedup.CdxServerDedup")
    cookies = None

    def __init__(self, cdx_url="https://web.archive.org/cdx/search",
                 maxsize=400, options=warcprox.Options()):
        """Initialize cdx server connection pool and related parameters.
        Use low timeout value and no retries to avoid blocking warcprox
        operation by a slow CDX server.
        """
        self.cdx_url = cdx_url
        self.options = options
        headers = {'User-Agent': 'warcprox', 'Accept-Encoding': 'gzip, deflate'}
        if options.cdxserver_dedup_cookies:
            headers['Cookie'] = options.cdxserver_dedup_cookies
        self.http_pool = urllib3.PoolManager(maxsize=maxsize, retries=0,
                                             timeout=2.0, headers=headers)
        self.cached_lookup = lru_cache(maxsize=1024)(self.lookup)

    def loader(self, *args, **kwargs):
        return CdxServerDedupLoader(self, self.options)

    def start(self):
        pass

    def save(self, digest_key, response_record, bucket=""):
        """Does not apply to CDX server, as it is obviously read-only.
        """
        pass

    def lookup(self, digest_key, url):
        """Compare `sha1` with SHA1 hash of fetched content (note SHA1 must be
        computed on the original content, after decoding Content-Encoding and
        Transfer-Encoding, if any), if they match, write a revisit record.

        Get only the last item (limit=-1) because Wayback Machine has special
        performance optimisation to handle that. limit < 0 is very inefficient
        in general. Maybe it could be configurable in the future.

        Skip dedup for URLs with session params. These URLs are certainly
        unique and highly volatile, we cannot dedup them.

        :param digest_key: b'sha1:<KEY-VALUE>' (prefix is optional).
            Example: b'sha1:B2LTWWPUOYAH7UIPQ7ZUPQ4VMBSVC36A'
        :param url: Target URL string
        Result must contain:
        {"url": <URL>, "date": "%Y-%m-%dT%H:%M:%SZ"}
        """
        u = url.decode("utf-8") if isinstance(url, bytes) else url
        try:
            if any(s in u for s in ('JSESSIONID=', 'session=', 'sess=')):
                return None
            result = self.http_pool.request('GET', self.cdx_url, fields=dict(
                url=u, fl="timestamp,digest", filter="!mimetype:warc/revisit",
                limit=-1))
            assert result.status == 200
            if isinstance(digest_key, bytes):
                dkey = digest_key
            else:
                dkey = digest_key.encode('utf-8')
            dkey = dkey[5:] if dkey.startswith(b'sha1:') else dkey
            line = result.data.strip()
            if line:
                (cdx_ts, cdx_digest) = line.split(b' ')
                if cdx_digest == dkey:
                    dt = datetime.datetime.strptime(
                            cdx_ts.decode('ascii'), '%Y%m%d%H%M%S')
                    date = dt.strftime('%Y-%m-%dT%H:%M:%SZ').encode('utf-8')
                    return dict(url=url, date=date)
        except (HTTPError, AssertionError, ValueError) as exc:
            self.logger.error('CdxServerDedup request failed for url=%s %s',
                              url, exc)
        return None

    def notify(self, recorded_url, records):
        """Since we don't save anything to CDX server, this does not apply.
        """
        pass

class CdxServerDedupLoader(warcprox.BaseBatchPostfetchProcessor, DedupableMixin):
    def __init__(self, cdx_dedup, options=warcprox.Options()):
        warcprox.BaseBatchPostfetchProcessor.__init__(self, options)
        DedupableMixin.__init__(self, options)
        self.pool = futures.ThreadPoolExecutor(max_workers=options.cdxserver_dedup_max_threads)
        self.batch = set()
        self.cdx_dedup = cdx_dedup

    def _get_process_put(self):
        recorded_url = self.inq.get(block=True, timeout=0.5)
        if (recorded_url.response_recorder
                and recorded_url.payload_digest
                and self.should_dedup(recorded_url)):
            self.batch.add(recorded_url)
            self.pool.submit(self._process_url, recorded_url)
        else:
            if self.outq:
                self.outq.put(recorded_url)

    def _process_url(self, recorded_url):
        try:
            digest_key = warcprox.digest_str(recorded_url.payload_digest,
                                             self.options.base32)
            dedup_info = self.cdx_dedup.cached_lookup(digest_key, recorded_url.url)
            cache_info = self.cdx_dedup.cached_lookup.cache_info()
            if (cache_info.hits + cache_info.misses) % 1000 == 0:
                self.logger.info(self.cdx_dedup.cached_lookup.cache_info())
            if dedup_info:
                recorded_url.dedup_info = dedup_info
        except ValueError as exc:
            self.logger.error('CdxServerDedupLoader _process_url failed for url=%s %s',
                              recorded_url.url, exc)
        finally:
            self.batch.remove(recorded_url)
            if self.outq:
                self.outq.put(recorded_url)

class BatchTroughStorer(warcprox.BaseBatchPostfetchProcessor):
    def __init__(self, trough_dedup_db, options=warcprox.Options()):
        warcprox.BaseBatchPostfetchProcessor.__init__(self, options)
        self.trough_dedup_db = trough_dedup_db

    def _filter_and_bucketize(self, batch):
        '''
        Returns `{bucket: [recorded_url, ...]}`, excluding urls that should not
        have dedup info stored.
        '''
        buckets = collections.defaultdict(list)
        for recorded_url in batch:
            if (recorded_url.warc_records
                    and recorded_url.warc_records[0].type == b'response'
                    and self.trough_dedup_db.should_dedup(recorded_url)):
                if (recorded_url.warcprox_meta
                        and 'dedup-buckets' in recorded_url.warcprox_meta):
                    for bucket, bucket_mode in recorded_url.warcprox_meta["dedup-buckets"].items():
                        if not bucket_mode == 'ro':
                            buckets[bucket].append(recorded_url)
                else:
                    buckets['__unspecified__'].append(recorded_url)
        return buckets

    def _process_batch(self, batch):
        buckets = self._filter_and_bucketize(batch)
        if not buckets:
            return
        fs = {}
        with futures.ThreadPoolExecutor(max_workers=len(buckets)) as pool:
            # send off requests in parallel
            for bucket in buckets:
                future = pool.submit(
                        self.trough_dedup_db.batch_save,
                        buckets[bucket], bucket)
                fs[future] = bucket
            logging.debug(
                    'storing dedup info for %s urls '
                    'in bucket %s', len(buckets[bucket]), bucket)

            # wait for results
            try:
                for future in futures.as_completed(fs, timeout=20):
                    pass
            except futures.TimeoutError as e:
                # the remaining threads actually keep running in this case,
                # there's no way to stop them, but that should be harmless
                logging.warning(
                    'timed out saving dedup info to trough', exc_info=True)

class BatchTroughLoader(warcprox.BaseBatchPostfetchProcessor):
    logger = logging.getLogger("warcprox.dedup.BatchTroughLoader")

    def __init__(self, trough_dedup_db, options=warcprox.Options()):
        warcprox.BaseBatchPostfetchProcessor.__init__(self, options)
        self.trough_dedup_db = trough_dedup_db

    def _startup(self):
        self.trough_dedup_db.start()

    def _filter_and_bucketize(self, batch):
        '''
        Returns `{bucket: [recorded_url, ...]}`, excluding urls that should not
        be looked up.
        '''
        buckets = collections.defaultdict(list)
        discards = []
        # for duplicate checks, see https://webarchive.jira.com/browse/WT-31
        hash_plus_urls = set()
        for recorded_url in batch:
            if not recorded_url.payload_digest:
                discards.append('n/a')
                continue
            payload_hash = warcprox.digest_str(
                        recorded_url.payload_digest, self.options.base32)
            hash_plus_url = b''.join((payload_hash, recorded_url.url))
            if (recorded_url.response_recorder
                    and hash_plus_url not in hash_plus_urls
                    and self.trough_dedup_db.should_dedup(recorded_url)):
                hash_plus_urls.add(hash_plus_url)
                if (recorded_url.warcprox_meta
                        and 'dedup-buckets' in recorded_url.warcprox_meta):
                    for bucket, bucket_mode in recorded_url.warcprox_meta["dedup-buckets"].items():
                        buckets[bucket].append(recorded_url)
                else:
                    buckets['__unspecified__'].append(recorded_url)
            else:
                if hash_plus_url in hash_plus_urls:
                    self.logger.debug(
                        'discarding duplicate and setting do_not_archive for %s, hash %s',
                         recorded_url.url, payload_hash)
                    recorded_url.do_not_archive = True
                discards.append(payload_hash)
        self.logger.debug(
                'len(batch)=%s len(discards)=%s buckets=%s',
                len(batch), len(discards),
                {bucket: len(buckets[bucket]) for bucket in buckets})
        return buckets

    def _build_key_index(self, batch):
        '''
        Builds index of RecordedUrl by digest key.

        Args:
            batch(list): list of RecordedUrl

        Returns:
            dict `{digest_key: [recorded_url, ...]}`
        '''
        key_index = collections.defaultdict(list)
        for recorded_url in batch:
            digest_key = warcprox.digest_str(
                    recorded_url.payload_digest, self.options.base32)
            key_index[digest_key].append(recorded_url)
        return key_index

    def _process_batch(self, batch):
        buckets = self._filter_and_bucketize(batch)
        if not buckets:
            return
        fs = {}
        with futures.ThreadPoolExecutor(max_workers=len(buckets)) as pool:
            # send off the trough requests in parallel
            key_indexes = {}
            for bucket in buckets:
                key_indexes[bucket] = self._build_key_index(buckets[bucket])
                future = pool.submit(
                        self.trough_dedup_db.batch_lookup,
                        key_indexes[bucket].keys(), bucket)
                fs[future] = bucket

            # process results as they come back
            try:
                for future in futures.as_completed(fs, timeout=20):
                    bucket = fs[future]
                    try:
                        key_index = key_indexes[bucket]
                        for entry in future.result():
                            for recorded_url in key_index[entry['digest_key']]:
                                recorded_url.dedup_info = entry
                    except Exception as e:
                        # batch_lookup raised exception or something
                        logging.warning(
                                'problem looking up dedup info for %s urls '
                                'in bucket %s', len(buckets[bucket]), bucket,
                                exc_info=True)

                    if self.logger.isEnabledFor(logging.DEBUG):
                        dups = sorted([e['digest_key'] for e in future.result()])
                        novel = sorted([
                            k for k in key_index.keys() if k not in dups])
                        self.logger.debug(
                                'bucket %s: dups(%s)=%r novel(%s)=%r',
                                bucket, len(dups), dups, len(novel), novel)

            except futures.TimeoutError as e:
                # the remaining threads actually keep running in this case,
                # there's no way to stop them, but that should be harmless
                self.logger.warning(
                    'timed out loading dedup info from trough', exc_info=True)

class TroughDedupDb(DedupDb, DedupableMixin):
    '''
    https://github.com/internetarchive/trough
    '''
    logger = logging.getLogger("warcprox.dedup.TroughDedupDb")

    SCHEMA_ID = 'warcprox-dedup-v1'
    SCHEMA_SQL = ('create table dedup (\n'
                  '    digest_key varchar(100) primary key,\n'
                  '    url varchar(2100) not null,\n'
                  '    date varchar(100) not null,\n'
                  '    id varchar(100));\n') # warc record id
    WRITE_SQL_TMPL = ('insert or ignore into dedup\n'
                      '(digest_key, url, date, id)\n'
                      'values (%s, %s, %s, %s);')

    def __init__(self, options=warcprox.Options()):
        try:
            import trough.client
        except ImportError as e:
            logging.critical(
                    '%s: %s\n\nYou might need to run "pip install '
                    'warcprox[trough]".', type(e).__name__, e)
            sys.exit(1)

        DedupableMixin.__init__(self, options)
        self.options = options
        self._trough_cli = trough.client.TroughClient(
                options.rethinkdb_trough_db_url, promotion_interval=60*60)

    def loader(self, *args, **kwargs):
        return BatchTroughLoader(self, self.options)

    def storer(self, *args, **kwargs):
        return BatchTroughStorer(self, self.options)

    def start(self):
        try:
            self._trough_cli.register_schema(self.SCHEMA_ID, self.SCHEMA_SQL)
        except Exception as e:
            # can happen. hopefully someone else has registered it
            self.logger.critical(
                    'will try to continue after problem registering schema %s',
                    self.SCHEMA_ID, exc_info=True)

    def save(self, digest_key, response_record, bucket='__unspecified__'):
        record_id = response_record.get_header(warctools.WarcRecord.ID)
        url = response_record.get_header(warctools.WarcRecord.URL)
        warc_date = response_record.get_header(warctools.WarcRecord.DATE)
        try:
            self._trough_cli.write(
                   bucket, self.WRITE_SQL_TMPL,
                   (digest_key, url, warc_date, record_id), self.SCHEMA_ID)
        except:
            self.logger.warning(
                    'problem posting dedup data to trough', exc_info=True)

    def batch_save(self, batch, bucket='__unspecified__'):
        sql_tmpl = ('insert or ignore into dedup\n'
                      '(digest_key, url, date, id)\n'
                      'values %s;' % ','.join(
                          '(%s,%s,%s,%s)' for i in range(len(batch))))
        values = []
        for recorded_url in batch:
            values.extend([
                warcprox.digest_str(
                    recorded_url.payload_digest, self.options.base32),
                recorded_url.url,
                recorded_url.warc_records[0].date,
                recorded_url.warc_records[0].id,])
        try:
            self._trough_cli.write(bucket, sql_tmpl, values, self.SCHEMA_ID)
        except:
            self.logger.warning(
                    'problem posting dedup data to trough', exc_info=True)

    def lookup(self, digest_key, bucket='__unspecified__', url=None):
        try:
            results = self._trough_cli.read(
                    bucket, 'select * from dedup where digest_key=%s;',
                    (digest_key,))
        except:
            self.logger.warning(
                    'problem reading dedup data from trough', exc_info=True)
            return None

        if results:
            assert len(results) == 1 # sanity check (digest_key is primary key)
            result = results[0]
            result['id'] = result['id'].encode('ascii')
            result['url'] = result['url'].encode('ascii')
            result['date'] = result['date'].encode('ascii')
            self.logger.debug(
                    'trough lookup of key=%r returning %r', digest_key, result)
            return result
        else:
            return None

    def batch_lookup(self, digest_keys, bucket='__unspecified__'):
        '''Returns [{'digest_key': ..., 'url': ..., 'date': ...}, ...]'''
        sql_tmpl = 'select * from dedup where digest_key in (%s)' % (
                ','.join('%s' for i in range(len(digest_keys))))

        try:
            results = self._trough_cli.read(bucket, sql_tmpl, digest_keys)
        except:
            self.logger.warning(
                    'problem reading dedup data from trough', exc_info=True)
            results = None

        if results is None:
            return []
        self.logger.debug(
            'trough batch lookup of %s keys returned %s results',
            len(digest_keys), len(results))
        assert len(results) >= 0 and len(results) <= len(digest_keys)
        for result in results:
            result['id'] = result.get('id') and result['id'].encode('ascii')
            result['url'] = result['url'].encode('ascii')
            result['date'] = result['date'].encode('ascii')
            result['digest_key'] = result['digest_key'].encode('ascii')
        return results

    def notify(self, recorded_url, records):
        if (records and records[0].type == b'response'
                and self.should_dedup(recorded_url)):
            digest_key = warcprox.digest_str(
                    recorded_url.payload_digest, self.options.base32)
            if recorded_url.warcprox_meta and 'dedup-buckets' in recorded_url.warcprox_meta:
                for bucket, bucket_mode in recorded_url.warcprox_meta["dedup-buckets"].items():
                    if not bucket_mode == 'ro':
                        self.save(
                                digest_key, records[0],
                                bucket=bucket)
            else:
                self.save(digest_key, records[0])
