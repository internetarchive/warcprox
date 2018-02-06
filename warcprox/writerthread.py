"""
warcprox/writerthread.py - warc writer thread, reads from the recorded url
queue, writes warc records, runs final tasks after warc records are written

Copyright (C) 2013-2018 Internet Archive

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
"""

from __future__ import absolute_import

try:
    import queue
except ImportError:
    import Queue as queue

import logging
import time
import warcprox
from concurrent import futures

class WarcWriterProcessor(warcprox.BaseStandardPostfetchProcessor):
    logger = logging.getLogger("warcprox.writerthread.WarcWriterProcessor")

    _ALWAYS_ACCEPT = {'WARCPROX_WRITE_RECORD'}

    def __init__(self, options=warcprox.Options()):
        warcprox.BaseStandardPostfetchProcessor.__init__(self, options=options)
        self.writer_pool = warcprox.writer.WarcWriterPool(options)
        self.method_filter = set(method.upper() for method in self.options.method_filter or [])
        self.pool = futures.ThreadPoolExecutor(max_workers=options.writer_threads or 1)
        self.batch = set()

    def _get_process_put(self):
        recorded_url = self.inq.get(block=True, timeout=0.5)
        self.batch.add(recorded_url)
        self.pool.submit(self._process_url, recorded_url)

    def _process_url(self, recorded_url):
        try:
            records = []
            if self._should_archive(recorded_url):
                records = self.writer_pool.write_records(recorded_url)
            recorded_url.warc_records = records
            self._log(recorded_url, records)
            # try to release resources in a timely fashion
            if recorded_url.response_recorder and recorded_url.response_recorder.tempfile:
                recorded_url.response_recorder.tempfile.close()
        except:
            logging.error(
                    'caught exception processing %s', recorded_url.url,
                    exc_info=True)
        finally:
            self.batch.remove(recorded_url)
            if self.outq:
                self.outq.put(recorded_url)
            self.writer_pool.maybe_idle_rollover()

    def _filter_accepts(self, recorded_url):
        if not self.method_filter:
            return True
        meth = recorded_url.method.upper()
        return meth in self._ALWAYS_ACCEPT or meth in self.method_filter

    # XXX optimize handling of urls not to be archived throughout warcprox
    def _should_archive(self, recorded_url):
        prefix = (recorded_url.warcprox_meta['warc-prefix']
                  if recorded_url.warcprox_meta
                     and 'warc-prefix' in recorded_url.warcprox_meta
                  else self.options.prefix)
        # special warc name prefix '-' means "don't archive"
        return prefix != '-' and self._filter_accepts(recorded_url)

    def _log(self, recorded_url, records):
        try:
            payload_digest = records[0].get_header('WARC-Payload-Digest').decode("utf-8")
        except:
            payload_digest = "-"

        # 2015-07-17T22:32:23.672Z     1         58 dns:www.dhss.delaware.gov P http://www.dhss.delaware.gov/dhss/ text/dns #045 20150717223214881+316 sha1:63UTPB7GTWIHAGIK3WWL76E57BBTJGAK http://www.dhss.delaware.gov/dhss/ - {"warcFileOffset":2964,"warcFilename":"ARCHIVEIT-1303-WEEKLY-JOB165158-20150717223222113-00000.warc.gz"}
        type_ = records[0].type.decode("utf-8") if records else '-'
        filename = records[0].warc_filename if records else '-'
        offset = records[0].offset if records else '-'
        self.logger.info(
                "%s %s %s %s %s size=%s %s %s %s offset=%s",
                recorded_url.client_ip, recorded_url.status,
                recorded_url.method, recorded_url.url.decode("utf-8"),
                recorded_url.mimetype, recorded_url.size, payload_digest,
                type_, filename, offset)

    def _shutdown(self):
        self.writer_pool.close_writers()

