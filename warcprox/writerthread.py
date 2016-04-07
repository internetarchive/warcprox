#
# warcprox/writerthread.py - warc writer thread, reads from the recorded url
# queue, writes warc records, runs final tasks after warc records are written
#
# Copyright (C) 2013-2016 Internet Archive
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.
#

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
import cProfile

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
        if self.options.profile:
            cProfile.runctx('self._run()', globals(), locals(), sort='cumulative')
        else:
            self._run()

    def _run(self):
        while not self.stop.is_set():
            try:
                self.name = 'WarcWriterThread(tid={})'.format(warcprox.gettid())
                while True:
                    try:
                        if self.stop.is_set():
                            qsize = self.recorded_url_q.qsize()
                            if qsize % 50 == 0:
                                self.logger.info("%s urls left to write", qsize)

                        recorded_url = self.recorded_url_q.get(block=True, timeout=0.5)
                        self.idle = None
                        if self.dedup_db:
                            warcprox.dedup.decorate_with_dedup_info(self.dedup_db,
                                    recorded_url, base32=self.options.base32)
                        records = self.writer_pool.write_records(recorded_url)
                        self._final_tasks(recorded_url, records)

                        # try to release resources in a timely fashion
                        if recorded_url.response_recorder and recorded_url.response_recorder.tempfile:
                            recorded_url.response_recorder.tempfile.close()
                    except queue.Empty:
                        if self.stop.is_set():
                            break
                        self.idle = time.time()
                        self.writer_pool.maybe_idle_rollover()

                self.logger.info('WarcWriterThread shutting down')
                self.writer_pool.close_writers()
            except:
                self.logger.critical("WarcWriterThread will try to continue after unexpected error", exc_info=True)
                time.sleep(0.5)

    # closest thing we have to heritrix crawl log at the moment
    def _log(self, recorded_url, records):
        try:
            payload_digest = records[0].get_header(warctools.WarcRecord.PAYLOAD_DIGEST).decode("utf-8")
        except:
            payload_digest = "-"

        # 2015-07-17T22:32:23.672Z     1         58 dns:www.dhss.delaware.gov P http://www.dhss.delaware.gov/dhss/ text/dns #045 20150717223214881+316 sha1:63UTPB7GTWIHAGIK3WWL76E57BBTJGAK http://www.dhss.delaware.gov/dhss/ - {"warcFileOffset":2964,"warcFilename":"ARCHIVEIT-1303-WEEKLY-JOB165158-20150717223222113-00000.warc.gz"}
        self.logger.info("{} {} {} {} {} size={} {} {} {} offset={}".format(
            recorded_url.client_ip, recorded_url.status, recorded_url.method,
            recorded_url.url.decode("utf-8"), recorded_url.mimetype,
            recorded_url.size, payload_digest, records[0].type.decode("utf-8"),
            records[0].warc_filename, records[0].offset))

    def _final_tasks(self, recorded_url, records):
        if self.listeners:
            for listener in self.listeners:
                try:
                    listener.notify(recorded_url, records)
                except:
                    self.logger.error('%s raised exception',
                                      listener.notify, exc_info=True)
        self._log(recorded_url, records)
