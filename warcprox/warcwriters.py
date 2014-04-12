import base64
import os
import logging
import re
import time
import hashlib
import socket

from datetime import datetime
from hanzo import warctools, httptools

#======================================================================
class BaseWarcWriter(object):
    # port is only used for warc filename
    def __init__(self, **kwargs):
        self.logger = logging.getLogger(self.__class__.__name__)

        self.gzip = kwargs.get('gzip', False)
        self.digest_algorithm = kwargs.get('digest_algorithm', 'sha1')
        self.base32 = kwargs.get('base32', False)
        self.dedup_db = kwargs.get('dedup_db', None)

        self.playback_index_db = kwargs.get('playback_index_db', None)

        # warc path and filename stuff
        self.directory = kwargs.get('directory', './warcs')
        self.prefix = kwargs.get('prefix', 'WARCPROX')
        self.port = kwargs.get('port', 0)

        self._last_sync = self._last_activity = time.time()

    # returns a tuple (principal_record, request_record) where principal_record is either a response or revisit record
    def build_warc_records(self, recorded_url):
        warc_date = warctools.warc.warc_datetime_str(datetime.now())

        dedup_info = None
        if self.dedup_db is not None and recorded_url.response_recorder.payload_digest is not None:
            key = self.digest_str(recorded_url.response_recorder.payload_digest)
            dedup_info = self.dedup_db.lookup(key, recorded_url.custom_params)

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
                    profile=warctools.WarcRecord.PROFILE_IDENTICAL_PAYLOAD_DIGEST,
                    content_type=httptools.ResponseMessage.CONTENT_TYPE,
                    remote_ip=recorded_url.remote_ip)
        else:
            # response record
            principal_record = self.build_warc_record(
                    url=recorded_url.url, warc_date=warc_date,
                    recorder=recorded_url.response_recorder,
                    warc_type=warctools.WarcRecord.RESPONSE,
                    content_type=httptools.ResponseMessage.CONTENT_TYPE,
                    remote_ip=recorded_url.remote_ip)

        request_record = self.build_warc_record(
                url=recorded_url.url, warc_date=warc_date,
                data=recorded_url.request_data,
                warc_type=warctools.WarcRecord.REQUEST,
                content_type=httptools.RequestMessage.CONTENT_TYPE,
                concurrent_to=principal_record.id)

        return principal_record, request_record


    def digest_str(self, hash_obj):
        return hash_obj.name.encode('utf-8') + b':' + (base64.b32encode(hash_obj.digest()) if self.base32 else hash_obj.hexdigest().encode('ascii'))


    def build_warc_record(self, url, warc_date=None, recorder=None, data=None,
        concurrent_to=None, warc_type=None, content_type=None, remote_ip=None,
        profile=None, refers_to=None, refers_to_target_uri=None,
        refers_to_date=None):

        if warc_date is None:
            warc_date = warctools.warc.warc_datetime_str(datetime.now())

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
        #truncate to microseconds to get millis padded to 17
        return self.timestamp20()[:17]
        #return '{}{}'.format(now.strftime('%Y%m%d%H%M%S'), now.microsecond//1000)

    def timestamp20(self):
        now = datetime.now()
        return now.strftime('%Y%m%d%H%M%S%f')

    def _build_warcinfo_record(self, filename):
        warc_record_date = warctools.warc.warc_datetime_str(datetime.now())
        record_id = warctools.WarcRecord.random_warc_uuid()

        headers = []
        headers.append((warctools.WarcRecord.ID, record_id))
        headers.append((warctools.WarcRecord.TYPE, warctools.WarcRecord.WARCINFO))
        headers.append((warctools.WarcRecord.FILENAME, filename.encode('latin1')))
        headers.append((warctools.WarcRecord.DATE, warc_record_date))

        warcinfo_fields = []
        warcinfo_fields.append(b'software: warcprox.py https://github.com/internetarchive/warcprox')
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

    def write_url(self, recorded_url):
        self._last_activity = time.time()

        recordset = self.build_warc_records(recorded_url)

        fullpath, filename, writer = self._begin_record(recorded_url)

        recordset_offset = writer.tell()

        record_length = None

        for record in recordset:
            offset = writer.tell()
            record.write_to(writer, gzip=self.gzip)
            self.logger.debug('wrote warc record: warc_type={} content_length={} url={} warc={} offset={}'.format(
                    record.get_header(warctools.WarcRecord.TYPE),
                    record.get_header(warctools.WarcRecord.CONTENT_LENGTH),
                    record.get_header(warctools.WarcRecord.URL),
                    fullpath, offset))

            if record_length is None:
                record_length = writer.tell()

        self._finish_record(fullpath, filename, writer, recorded_url)

        self._final_tasks(recordset, recordset_offset, record_length, filename, recorded_url)

    def on_empty_queue(self):
        self._on_empty_queue()

        if time.time() - self._last_sync > 60:
            if self.dedup_db:
                self.dedup_db.sync()
            if self.playback_index_db:
                self.playback_index_db.sync()
            self._last_sync = time.time()

    def _final_tasks(self, recordset, recordset_offset, record_length, filename, recorded_url):
        if (self.dedup_db or self.playback_index_db):
            digest_key = self.digest_str(recorded_url.response_recorder.payload_digest)

        if self.dedup_db is not None:
            self.dedup_db.save_digest(digest_key,
                                      recordset[0],
                                      recorded_url)

        if self.playback_index_db is not None:
            self.playback_index_db.save_url(digest_key,
                                            recordset[0],
                                            recordset_offset,
                                            record_length,
                                            filename,
                                            recorded_url)

        recorded_url.response_recorder.tempfile.close()


#======================================================================
class WarcWriter(BaseWarcWriter):
    def __init__(self, **kwargs):
        super(WarcWriter, self).__init__(**kwargs)
        self.rollover_size = kwargs.get('rollover_size', 1000000000)
        self.rollover_idle_time = kwargs.get('rollover_idle_time')

    def init_writer(self):
        self._f = None
        self._fpath = None
        self._serial = 0

        if not os.path.exists(self.directory):
            self.logger.info("warc destination directory {} doesn't exist, creating it".format(self.directory))
            os.mkdir(self.directory)

    def close_writer(self):
        if self._fpath:
            self.logger.info('closing {0}'.format(self._f_finalname))
            self._f.close()
            finalpath = os.path.sep.join([self.directory, self._f_finalname])
            os.rename(self._fpath, finalpath)

            self._fpath = None
            self._f = None

    # <!-- <property name="template" value="${prefix}-${timestamp17}-${serialno}-${heritrix.pid}~${heritrix.hostname}~${heritrix.port}" /> -->
    def _begin_record(self, recorded_url):
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

        return (self._fpath, self._f_finalname, self._f)

    def _finish_record(self, fullpath, filename, writer, recorded_url):
        writer.flush()

    def describe(self):
        return '{} starting, directory={} gzip={} rollover_size={} rollover_idle_time={} prefix={} port={}'.format(
                self.__class__.__name__,
                os.path.abspath(self.directory), self.gzip, self.rollover_size,
                self.rollover_idle_time, self.prefix, self.port)

    def _on_empty_queue(self):
        if (self.rollover_idle_time is not None
                and self.rollover_idle_time > 0
                and time.time() - self._last_activity > self.rollover_idle_time):
            self.logger.debug('rolling over warc file after {} seconds idle'.format(time.time() - self._last_activity))
            self.close_writer()


#======================================================================
class WarcPerUrlWriter(BaseWarcWriter):

    # regex to match invalid chars in dir
    STRIP_DIR_RX = re.compile('[\W]+')

    def init_writer(self):
        pass

    def _begin_record(self, recorded_url):
        target_dir = None
        ext = '.gz' if self.gzip else ''

        target_dir = recorded_url.custom_params.get('target')

        if target_dir:
            # strip non-alphanum and _ from target dir, for security
            target_dir = self.STRIP_DIR_RX.sub('', target_dir)
            target_dir = os.path.join(self.directory, target_dir)

            if not os.path.exists(target_dir):
                self.logger.info("warc destination directory {} doesn't exist, creating it".format(target_dir))
                os.mkdir(target_dir)

        else:
            #TODO: is this required? maybe it an error if omitted?
            target_dir = self.directory


        filename= '{}-{}-{}.warc{}'.format(self.prefix,
                                        self.timestamp20(),
                                        os.getpid(),
                                        ext)

        fullpath = os.path.join(target_dir, filename)

        writer = open(fullpath, 'wb')

        return (fullpath, filename, writer)

    def _finish_record(self, fullpath, filename, writer, recorded_url):
        writer.flush()
        writer.close()

    def close_writer(self):
        pass

    def describe(self):
        return '{} starting, directory={} gzip={} prefix={} port={}'.format(
                self.__class__.__name__,
                os.path.abspath(self.directory), self.gzip, self.prefix, self.port)

    def _on_empty_queue(self):
        pass
