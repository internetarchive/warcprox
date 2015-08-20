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

class WarcWriterThread(threading.Thread):
    logger = logging.getLogger("warcprox.warcproxwriter.WarcWriterThread")

    def __init__(self, recorded_url_q=None, writer_pool=None, dedup_db=None, playback_index_db=None, stats_db=None):
        """recorded_url_q is a queue.Queue of warcprox.warcprox.RecordedUrl."""
        threading.Thread.__init__(self, name='WarcWriterThread')
        self.recorded_url_q = recorded_url_q
        self.stop = threading.Event()
        if writer_pool:
            self.writer_pool = writer_pool
        else:
            self.writer_pool = WarcWriterPool()
        self.dedup_db = dedup_db
        self.playback_index_db = playback_index_db
        self.stats_db = stats_db
        self._last_sync = time.time()

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    recorded_url = self.recorded_url_q.get(block=True, timeout=0.5)
                    if self.dedup_db:
                        warcprox.dedup.decorate_with_dedup_info(self.dedup_db, recorded_url, 
                                base32=self.writer_pool.default_warc_writer.record_builder.base32)
                    records = self.writer_pool.write_records(recorded_url)
                    self._final_tasks(recorded_url, records)
                except queue.Empty:
                    self.writer_pool.maybe_idle_rollover()
                    self._sync()

            self.logger.info('WarcWriterThread shutting down')
            self.writer_pool.close_writers()
        except:
            self.logger.critical("WarcWriterThread shutting down after unexpected error", exc_info=True)

    def _sync(self):
        # XXX prob doesn't belong here (do we need it at all?)
        if time.time() - self._last_sync > 60:
            if self.dedup_db:
                self.dedup_db.sync()
            if self.playback_index_db:
                self.playback_index_db.sync()
            self._last_sync = time.time()

    def _save_dedup_info(self, recorded_url, records):
        if (self.dedup_db 
                and records[0].get_header(warctools.WarcRecord.TYPE) == warctools.WarcRecord.RESPONSE
                and recorded_url.response_recorder.payload_size() > 0):
            key = warcprox.digest_str(recorded_url.response_recorder.payload_digest, 
                    self.writer_pool.default_warc_writer.record_builder.base32)
            self.dedup_db.save(key, records[0])

    def _save_playback_info(self, recorded_url, records):
        if self.playback_index_db is not None:
            self.playback_index_db.save(records[0].warc_filename, records, records[0].offset)

    # closest thing we have to heritrix crawl log at the moment
    def _log(self, recorded_url, records):
        def _decode(x):
            if isinstance(x, bytes):
                return x.decode("utf-8")
            else:
                return x

        try:
            payload_digest = records[0].get_header(warctools.WarcRecord.PAYLOAD_DIGEST).decode("utf-8")
        except:
            payload_digest = "-"
        mimetype = _decode(recorded_url.content_type)
        if mimetype:
            n = mimetype.find(";")
            if n >= 0:
                mimetype = mimetype[:n]
        
        # 2015-07-17T22:32:23.672Z     1         58 dns:www.dhss.delaware.gov P http://www.dhss.delaware.gov/dhss/ text/dns #045 20150717223214881+316 sha1:63UTPB7GTWIHAGIK3WWL76E57BBTJGAK http://www.dhss.delaware.gov/dhss/ - {"warcFileOffset":2964,"warcFilename":"ARCHIVEIT-1303-WEEKLY-JOB165158-20150717223222113-00000.warc.gz"}
        self.logger.info("{} {} {} {} {} size={} {} {} {} offset={}".format(
            _decode(recorded_url.client_ip),
            _decode(recorded_url.status), 
            _decode(recorded_url.method),
            _decode(recorded_url.url),
            mimetype,
            recorded_url.size,
            _decode(payload_digest), 
            _decode(records[0].get_header(warctools.WarcRecord.TYPE)),
            _decode(records[0].warc_filename), 
            records[0].offset))

    def _update_stats(self, recorded_url, records):
        if self.stats_db:
            self.stats_db.tally(recorded_url, records)

    def _final_tasks(self, recorded_url, records):
        self._save_dedup_info(recorded_url, records)
        self._save_playback_info(recorded_url, records)
        self._update_stats(recorded_url, records)
        self._log(recorded_url, records)
