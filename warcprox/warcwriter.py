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
            playback_index_db=None):

        self.rollover_size = rollover_size

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


    # returns a tuple (principal_record, request_record) where principal_record is either a response or revisit record
    def build_warc_records(self, recorded_url):
        warc_date = warctools.warc.warc_datetime_str(datetime.utcnow())

        dedup_info = None
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

            principal_record = self.build_warc_record(
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
            principal_record = self.build_warc_record(
                    url=recorded_url.url, warc_date=warc_date,
                    recorder=recorded_url.response_recorder,
                    warc_type=warctools.WarcRecord.RESPONSE,
                    content_type=hanzo.httptools.ResponseMessage.CONTENT_TYPE,
                    remote_ip=recorded_url.remote_ip)

        request_record = self.build_warc_record(
                url=recorded_url.url, warc_date=warc_date,
                data=recorded_url.request_data,
                warc_type=warctools.WarcRecord.REQUEST,
                content_type=hanzo.httptools.RequestMessage.CONTENT_TYPE,
                concurrent_to=principal_record.id)

        return principal_record, request_record


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
        return '{}{}'.format(now.strftime('%Y%m%d%H%M%S'), now.microsecond//1000)

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


    def _final_tasks(self, recorded_url, recordset, recordset_offset):
        if (self.dedup_db is not None
                and recordset[0].get_header(warctools.WarcRecord.TYPE) == warctools.WarcRecord.RESPONSE
                and recorded_url.response_recorder.payload_size() > 0):
            key = self.digest_str(recorded_url.response_recorder.payload_digest)
            self.dedup_db.save(key, recordset[0], recordset_offset)

        if self.playback_index_db is not None:
            self.playback_index_db.save(self._f_finalname, recordset, recordset_offset)

        recorded_url.response_recorder.tempfile.close()

    def write_records(self, recorded_url):
        recordset = self.build_warc_records(recorded_url)

        writer = self._writer()
        recordset_offset = writer.tell()

        for record in recordset:
            offset = writer.tell()
            record.write_to(writer, gzip=self.gzip)
            self.logger.debug('wrote warc record: warc_type={} content_length={} url={} warc={} offset={}'.format(
                    record.get_header(warctools.WarcRecord.TYPE),
                    record.get_header(warctools.WarcRecord.CONTENT_LENGTH),
                    record.get_header(warctools.WarcRecord.URL),
                    self._fpath, offset))

        self._f.flush()

        self._final_tasks(recorded_url, recordset, recordset_offset)



class WarcWriterThread(threading.Thread):
    logger = logging.getLogger("warcprox.warcwriter.WarcWriterThread")

    def __init__(self, recorded_url_q=None, warc_writer=None, rollover_idle_time=None):
        """recorded_url_q is a queue.Queue of warcprox.warcprox.RecordedUrl."""
        threading.Thread.__init__(self, name='WarcWriterThread')
        self.recorded_url_q = recorded_url_q
        self.rollover_idle_time = rollover_idle_time
        self.stop = threading.Event()
        if warc_writer:
            self.warc_writer = warc_writer
        else:
            self.warc_writer = WarcWriter()

    def run(self):
        self.logger.info('WarcWriterThread starting, directory={} gzip={} rollover_size={} rollover_idle_time={} prefix={} port={}'.format(
                os.path.abspath(self.warc_writer.directory), self.warc_writer.gzip, self.warc_writer.rollover_size,
                self.rollover_idle_time, self.warc_writer.prefix, self.warc_writer.port))

        self._last_sync = self._last_activity = time.time()

        while not self.stop.is_set():
            try:
                recorded_url = self.recorded_url_q.get(block=True, timeout=0.5)
                self.logger.info("recorded_url.warcprox_meta={} for {}".format(recorded_url.warcprox_meta, recorded_url.url))
                self.warc_writer.write_records(recorded_url)
                self._last_activity = time.time()
            except queue.Empty:
                if (self.warc_writer._fpath is not None
                        and self.rollover_idle_time is not None
                        and self.rollover_idle_time > 0
                        and time.time() - self._last_activity > self.rollover_idle_time):
                    self.logger.debug('rolling over warc file after {} seconds idle'.format(time.time() - self._last_activity))
                    self.warc_writer.close_writer()

                if time.time() - self._last_sync > 60:
                    if self.warc_writer.dedup_db:
                        self.warc_writer.dedup_db.sync()
                    if self.warc_writer.playback_index_db:
                        self.warc_writer.playback_index_db.sync()
                    self._last_sync = time.time()

        self.logger.info('WarcWriterThread shutting down')
        self.warc_writer.close_writer();


