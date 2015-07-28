# vim:set sw=4 et:

from __future__ import absolute_import

try:
    import queue
except ImportError:
    import Queue as queue

import logging
import threading
import os
import hashlib
import time
import socket
import base64
from datetime import datetime
import hanzo.httptools
from hanzo import warctools
import warcprox

class WarcWriter:
    logger = logging.getLogger("warcprox.warcwriter.WarcWriter")

    # port is only used for warc filename
    def __init__(self, directory='./warcs', rollover_size=1000000000,
            gzip=False, prefix='WARCPROX', port=0,
            digest_algorithm='sha1', base32=False, dedup_db=None,
            playback_index_db=None, rollover_idle_time=None):

        self.rollover_size = rollover_size
        self.rollover_idle_time = rollover_idle_time
        self._last_activity = time.time()

        self.gzip = gzip
        self.digest_algorithm = digest_algorithm
        self.base32 = base32
        self.dedup_db = dedup_db

        self.playback_index_db = playback_index_db

        # warc path and filename stuff
        self.directory = directory
        self.prefix = prefix
        self.port = port

        self._f = None
        self._fpath = None
        self._serial = 0

        if not os.path.exists(directory):
            self.logger.info("warc destination directory {} doesn't exist, creating it".format(directory))
            os.mkdir(directory)

    def _build_response_principal_record(self, recorded_url, warc_date):
        """Builds response or revisit record, whichever is appropriate."""
        if self.dedup_db is not None and recorded_url.response_recorder.payload_digest is not None:
            key = self.digest_str(recorded_url.response_recorder.payload_digest)
            dedup_info = self.dedup_db.lookup(key)

        if dedup_info is not None:
            # revisit record
            recorded_url.response_recorder.tempfile.seek(0)
            if recorded_url.response_recorder.payload_offset is not None:
                response_header_block = recorded_url.response_recorder.tempfile.read(recorded_url.response_recorder.payload_offset)
            else:
                response_header_block = recorded_url.response_recorder.tempfile.read()

            return self.build_warc_record(
                    url=recorded_url.url, warc_date=warc_date,
                    data=response_header_block,
                    warc_type=warctools.WarcRecord.REVISIT,
                    refers_to=dedup_info['i'],
                    refers_to_target_uri=dedup_info['u'],
                    refers_to_date=dedup_info['d'],
                    payload_digest=self.digest_str(recorded_url.response_recorder.payload_digest),
                    profile=warctools.WarcRecord.PROFILE_IDENTICAL_PAYLOAD_DIGEST,
                    content_type=hanzo.httptools.ResponseMessage.CONTENT_TYPE,
                    remote_ip=recorded_url.remote_ip)
        else:
            # response record
            return self.build_warc_record(
                    url=recorded_url.url, warc_date=warc_date,
                    recorder=recorded_url.response_recorder,
                    warc_type=warctools.WarcRecord.RESPONSE,
                    content_type=hanzo.httptools.ResponseMessage.CONTENT_TYPE,
                    remote_ip=recorded_url.remote_ip)

    # returns a tuple (principal_record, ...)
    def build_warc_records(self, recorded_url):
        warc_date = warctools.warc.warc_datetime_str(datetime.utcnow())

        if recorded_url.response_recorder:
            principal_record = self._build_response_principal_record(recorded_url, warc_date)
            request_record = self.build_warc_record(url=recorded_url.url,
                    warc_date=warc_date, data=recorded_url.request_data,
                    warc_type=warctools.WarcRecord.REQUEST,
                    content_type=hanzo.httptools.RequestMessage.CONTENT_TYPE,
                    concurrent_to=principal_record.id)
            return principal_record, request_record
        else:
            principal_record = self.build_warc_record(url=recorded_url.url,
                    warc_date=warc_date, data=recorded_url.request_data,
                    warc_type=recorded_url.custom_type,
                    content_type=recorded_url.content_type)
            return (principal_record,)

    def digest_str(self, hash_obj):
        return hash_obj.name.encode('utf-8') + b':' + (base64.b32encode(hash_obj.digest()) if self.base32 else hash_obj.hexdigest().encode('ascii'))

    def build_warc_record(self, url, warc_date=None, recorder=None, data=None,
        concurrent_to=None, warc_type=None, content_type=None, remote_ip=None,
        profile=None, refers_to=None, refers_to_target_uri=None,
        refers_to_date=None, payload_digest=None):

        if warc_date is None:
            warc_date = warctools.warc.warc_datetime_str(datetime.utcnow())

        record_id = warctools.WarcRecord.random_warc_uuid()

        headers = []
        if warc_type is not None:
            headers.append((warctools.WarcRecord.TYPE, warc_type))
        headers.append((warctools.WarcRecord.ID, record_id))
        headers.append((warctools.WarcRecord.DATE, warc_date))
        headers.append((warctools.WarcRecord.URL, url))
        if remote_ip is not None:
            headers.append((warctools.WarcRecord.IP_ADDRESS, remote_ip))
        if profile is not None:
            headers.append((warctools.WarcRecord.PROFILE, profile))
        if refers_to is not None:
            headers.append((warctools.WarcRecord.REFERS_TO, refers_to))
        if refers_to_target_uri is not None:
            headers.append((warctools.WarcRecord.REFERS_TO_TARGET_URI, refers_to_target_uri))
        if refers_to_date is not None:
            headers.append((warctools.WarcRecord.REFERS_TO_DATE, refers_to_date))
        if concurrent_to is not None:
            headers.append((warctools.WarcRecord.CONCURRENT_TO, concurrent_to))
        if content_type is not None:
            headers.append((warctools.WarcRecord.CONTENT_TYPE, content_type))
        if payload_digest is not None:
            headers.append((warctools.WarcRecord.PAYLOAD_DIGEST, payload_digest))

        if recorder is not None:
            headers.append((warctools.WarcRecord.CONTENT_LENGTH, str(len(recorder)).encode('latin1')))
            headers.append((warctools.WarcRecord.BLOCK_DIGEST,
                self.digest_str(recorder.block_digest)))
            if recorder.payload_digest is not None:
                headers.append((warctools.WarcRecord.PAYLOAD_DIGEST,
                    self.digest_str(recorder.payload_digest)))

            recorder.tempfile.seek(0)
            record = warctools.WarcRecord(headers=headers, content_file=recorder.tempfile)

        else:
            headers.append((warctools.WarcRecord.CONTENT_LENGTH, str(len(data)).encode('latin1')))
            block_digest = hashlib.new(self.digest_algorithm, data)
            headers.append((warctools.WarcRecord.BLOCK_DIGEST,
                self.digest_str(block_digest)))

            content_tuple = content_type, data
            record = warctools.WarcRecord(headers=headers, content=content_tuple)

        return record

    def timestamp17(self):
        now = datetime.utcnow()
        return '{:%Y%m%d%H%M%S}{:03d}'.format(now, now.microsecond//1000)

    def close_writer(self):
        if self._fpath:
            self.logger.info('closing {0}'.format(self._f_finalname))
            self._f.close()
            finalpath = os.path.sep.join([self.directory, self._f_finalname])
            os.rename(self._fpath, finalpath)

            self._fpath = None
            self._f = None

    def _build_warcinfo_record(self, filename):
        warc_record_date = warctools.warc.warc_datetime_str(datetime.utcnow())
        record_id = warctools.WarcRecord.random_warc_uuid()

        headers = []
        headers.append((warctools.WarcRecord.ID, record_id))
        headers.append((warctools.WarcRecord.TYPE, warctools.WarcRecord.WARCINFO))
        headers.append((warctools.WarcRecord.FILENAME, filename.encode('latin1')))
        headers.append((warctools.WarcRecord.DATE, warc_record_date))

        warcinfo_fields = []
        warcinfo_fields.append(b'software: warcprox ' + warcprox.version_bytes)
        hostname = socket.gethostname()
        warcinfo_fields.append('hostname: {}'.format(hostname).encode('latin1'))
        warcinfo_fields.append('ip: {0}'.format(socket.gethostbyname(hostname)).encode('latin1'))
        warcinfo_fields.append(b'format: WARC File Format 1.0')
        # warcinfo_fields.append('robots: ignore')
        # warcinfo_fields.append('description: {0}'.format(self.description))
        # warcinfo_fields.append('isPartOf: {0}'.format(self.is_part_of))
        data = b'\r\n'.join(warcinfo_fields) + b'\r\n'

        record = warctools.WarcRecord(headers=headers, content=(b'application/warc-fields', data))

        return record

    # <!-- <property name="template" value="${prefix}-${timestamp17}-${serialno}-${heritrix.pid}~${heritrix.hostname}~${heritrix.port}" /> -->
    def _writer(self):
        if self._fpath and os.path.getsize(self._fpath) > self.rollover_size:
            self.close_writer()

        if self._f == None:
            self._f_finalname = '{}-{}-{:05d}-{}-{}-{}.warc{}'.format(
                    self.prefix, self.timestamp17(), self._serial, os.getpid(),
                    socket.gethostname(), self.port, '.gz' if self.gzip else '')
            self._fpath = os.path.sep.join([self.directory, self._f_finalname + '.open'])

            self._f = open(self._fpath, 'wb')

            warcinfo_record = self._build_warcinfo_record(self._f_finalname)
            self.logger.debug('warcinfo_record.headers={}'.format(warcinfo_record.headers))
            warcinfo_record.write_to(self._f, gzip=self.gzip)

            self._serial += 1

        return self._f

    def _decode(self, x):
        if isinstance(x, bytes):
            return x.decode("utf-8")
        else:
            return x

    def _final_tasks(self, recorded_url, recordset, recordset_offset):
        if (self.dedup_db is not None
                and recordset[0].get_header(warctools.WarcRecord.TYPE) == warctools.WarcRecord.RESPONSE
                and recorded_url.response_recorder.payload_size() > 0):
            key = self.digest_str(recorded_url.response_recorder.payload_digest)
            self.dedup_db.save(key, recordset[0], recordset_offset)

        if self.playback_index_db is not None:
            self.playback_index_db.save(self._f_finalname, recordset, recordset_offset)

        if recorded_url.response_recorder is not None:
            recorded_url.response_recorder.tempfile.close()

        self._last_activity = time.time()
        
        try:
            payload_digest = recordset[0].get_header(warctools.WarcRecord.PAYLOAD_DIGEST).decode("utf-8")
        except:
            payload_digest = "-"
        mimetype = self._decode(recorded_url.content_type)
        if mimetype:
            n = mimetype.find(";")
            if n >= 0:
                mimetype = mimetype[:n]
        
        # 2015-07-17T22:32:23.672Z     1         58 dns:www.dhss.delaware.gov P http://www.dhss.delaware.gov/dhss/ text/dns #045 20150717223214881+316 sha1:63UTPB7GTWIHAGIK3WWL76E57BBTJGAK http://www.dhss.delaware.gov/dhss/ - {"warcFileOffset":2964,"warcFilename":"ARCHIVEIT-1303-WEEKLY-JOB165158-20150717223222113-00000.warc.gz"}
        self.logger.info("{} {} {} {} {} size={} {} {} offset={}".format(
            self._decode(recorded_url.client_ip),
            self._decode(recorded_url.status), 
            self._decode(recorded_url.method),
            self._decode(recorded_url.url),
            mimetype,
            recorded_url.size,
            self._decode(payload_digest), 
            self._decode(self._f_finalname), 
            recordset_offset))

    def write_records(self, recorded_url):
        recordset = self.build_warc_records(recorded_url)

        writer = self._writer()
        recordset_offset = writer.tell()

        for record in recordset:
            offset = writer.tell()
            record.write_to(writer, gzip=self.gzip)
            self.logger.debug('wrote warc record: warc_type=%s content_length=%s url=%s warc=%s offset=%d',
                    record.get_header(warctools.WarcRecord.TYPE),
                    record.get_header(warctools.WarcRecord.CONTENT_LENGTH),
                    record.get_header(warctools.WarcRecord.URL),
                    self._fpath, offset)

        self._f.flush()

        self._final_tasks(recorded_url, recordset, recordset_offset)

    def maybe_idle_rollover(self):
        if (self._fpath is not None
                and self.rollover_idle_time is not None
                and self.rollover_idle_time > 0
                and time.time() - self._last_activity > self.rollover_idle_time):
            self.logger.debug('rolling over {} after {} seconds idle'.format(self._f_finalname, time.time() - self._last_activity))
            self.close_writer()

class WarcWriterPool:
    logger = logging.getLogger("warcprox.warcwriter.WarcWriterThread")

    def __init__(self, default_warc_writer):
        if default_warc_writer:
            self.default_warc_writer = default_warc_writer
        else:
            self.default_warc_writer = WarcWriter()
        self.warc_writers = {}  # {prefix:WarcWriter}
        self._last_sync = time.time()

        self.logger.info('directory={} gzip={} rollover_size={} rollover_idle_time={} prefix={} port={}'.format(
                os.path.abspath(self.default_warc_writer.directory), self.default_warc_writer.gzip, self.default_warc_writer.rollover_size,
                self.default_warc_writer.rollover_idle_time, self.default_warc_writer.prefix, self.default_warc_writer.port))

    # chooses writer for filename specified by warcprox_meta["warc-prefix"] if set
    def _writer(self, recorded_url):
        w = self.default_warc_writer
        if recorded_url.warcprox_meta and "warc-prefix" in recorded_url.warcprox_meta:
            # self.logger.info("recorded_url.warcprox_meta={} for {}".format(recorded_url.warcprox_meta, recorded_url.url))
            prefix = recorded_url.warcprox_meta["warc-prefix"]
            if not prefix in self.warc_writers:
                self.warc_writers[prefix] = WarcWriter(prefix=prefix,
                        directory=self.default_warc_writer.directory,
                        rollover_size=self.default_warc_writer.rollover_size,
                        rollover_idle_time=self.default_warc_writer.rollover_idle_time,
                        gzip=self.default_warc_writer.gzip,
                        port=self.default_warc_writer.port,
                        digest_algorithm=self.default_warc_writer.digest_algorithm,
                        base32=self.default_warc_writer.base32,
                        dedup_db=self.default_warc_writer.dedup_db,
                        playback_index_db=self.default_warc_writer.playback_index_db)
            w = self.warc_writers[prefix]
        return w

    def write_records(self, recorded_url):
        self._writer(recorded_url).write_records(recorded_url)

    def maybe_idle_rollover(self):
        self.default_warc_writer.maybe_idle_rollover()
        for w in self.warc_writers.values():
            w.maybe_idle_rollover()

    def sync(self):
        # XXX prob doesn't belong here (do we need it at all?)
        if time.time() - self._last_sync > 60:
            if self.default_warc_writer.dedup_db:
                self.default_warc_writer.dedup_db.sync()
            if self.default_warc_writer.playback_index_db:
                self.default_warc_writer.playback_index_db.sync()
            self._last_sync = time.time()

    def close_writers(self):
        self.default_warc_writer.close_writer()
        for w in self.warc_writers.values():
            w.close_writer()

class WarcWriterThread(threading.Thread):
    logger = logging.getLogger("warcprox.warcwriter.WarcWriterThread")

    def __init__(self, recorded_url_q=None, writer_pool=None):
        """recorded_url_q is a queue.Queue of warcprox.warcprox.RecordedUrl."""
        threading.Thread.__init__(self, name='WarcWriterThread')
        self.recorded_url_q = recorded_url_q
        self.stop = threading.Event()
        if writer_pool:
            self.writer_pool = writer_pool
        else:
            self.writer_pool = WarcWriterPool()

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    recorded_url = self.recorded_url_q.get(block=True, timeout=0.5)
                    self.writer_pool.write_records(recorded_url)
                except queue.Empty:
                    self.writer_pool.maybe_idle_rollover()
                    self.writer_pool.sync()

            self.logger.info('WarcWriterThread shutting down')
            self.writer_pool.close_writers()
        except:
            self.logger.critical("WarcWriterThread shutting down after unexpected error", exc_info=True)

