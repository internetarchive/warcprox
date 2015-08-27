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

    def __init__(self, recorded_url_q=None, writer_pool=None, dedup_db=None, listeners=None, options=warcprox.Options()):
        """recorded_url_q is a queue.Queue of warcprox.warcprox.RecordedUrl."""
        threading.Thread.__init__(self, name='WarcWriterThread')
        self.recorded_url_q = recorded_url_q
        self.stop = threading.Event()
        if writer_pool:
            self.writer_pool = writer_pool
        else:
            self.writer_pool = WarcWriterPool()
        self.dedup_db = dedup_db
        self.listeners = listeners
        self.options = options
        self.idle = None

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    recorded_url = self.recorded_url_q.get(block=True, timeout=0.5)
                    self.idle = None
                    if self.dedup_db:
                        warcprox.dedup.decorate_with_dedup_info(self.dedup_db,
                                recorded_url, base32=self.options.base32)
                    records = self.writer_pool.write_records(recorded_url)
                    self._final_tasks(recorded_url, records)
                except queue.Empty:
                    self.idle = time.time()
                    self.writer_pool.maybe_idle_rollover()

            self.logger.info('WarcWriterThread shutting down')
            self.writer_pool.close_writers()
        except:
            self.logger.critical("WarcWriterThread shutting down after unexpected error", exc_info=True)

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

    def _final_tasks(self, recorded_url, records):
        if self.listeners:
            for listener in self.listeners:
                listener.notify(recorded_url, records)
        self._log(recorded_url, records)
