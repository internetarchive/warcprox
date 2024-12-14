"""
warcprox/writerthread.py - warc writer thread, reads from the recorded url
queue, writes warc records, runs final tasks after warc records are written

Copyright (C) 2013-2019 Internet Archive

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
import logging
from datetime import datetime
import queue
import warcprox

class WarcWriterProcessor(warcprox.BaseStandardPostfetchProcessor):
    logger = logging.getLogger("warcprox.writerthread.WarcWriterProcessor")

    _ALWAYS_ACCEPT = {'WARCPROX_WRITE_RECORD'}

    def __init__(self, options=warcprox.Options()):
        warcprox.BaseStandardPostfetchProcessor.__init__(self, options=options)
        self.writer_pool = warcprox.writer.WarcWriterPool(options)
        self.method_filter = {method.upper() for method in self.options.method_filter or []}
        self.blackout_period = options.blackout_period or 0
        self.close_prefix_reqs = queue.Queue()

    def _get_process_put(self):
        while True:
            try:
                prefix = self.close_prefix_reqs.get_nowait()
                self.writer_pool.close_for_prefix(prefix)
            except queue.Empty:
                break
        self.writer_pool.maybe_idle_rollover()
        super()._get_process_put()

    def close_for_prefix(self, prefix=None):
        '''
        Request close of warc writer for the given warc prefix, or the default
        prefix if `prefix` is `None`.

        This API exists so that some code from outside of warcprox proper (in a
        third-party plugin for example) can close open warcs promptly when it
        knows they are finished.
        '''
        self.close_prefix_reqs.put(prefix)

    def _process_url(self, recorded_url):
        if isinstance(recorded_url, warcprox.warcproxy.FailedUrl):
            return
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
        return (prefix != '-' and not recorded_url.do_not_archive
                and self._filter_accepts(recorded_url)
                and not self._in_blackout(recorded_url))

    def _in_blackout(self, recorded_url):
        """If --blackout-period=N (sec) is set, check if duplicate record
        datetime is close to the original. If yes, we don't write it to WARC.
        The aim is to avoid having unnecessary `revisit` records.
        Return Boolean
        """
        if self.blackout_period and hasattr(recorded_url, "dedup_info") and \
                recorded_url.dedup_info:
            dedup_date = recorded_url.dedup_info.get('date')
            if dedup_date and recorded_url.dedup_info.get('url') == recorded_url.url:
                try:
                    dt = datetime.strptime(dedup_date.decode('utf-8'),
                                           '%Y-%m-%dT%H:%M:%SZ')
                    return (datetime.utcnow() - dt).total_seconds() <= self.blackout_period
                except ValueError:
                    return False
        return False

    def _log(self, recorded_url, records):
        # 2015-07-17T22:32:23.672Z     1         58 dns:www.dhss.delaware.gov P http://www.dhss.delaware.gov/dhss/ text/dns #045 20150717223214881+316 sha1:63UTPB7GTWIHAGIK3WWL76E57BBTJGAK http://www.dhss.delaware.gov/dhss/ - {"warcFileOffset":2964,"warcFilename":"ARCHIVEIT-1303-WEEKLY-JOB165158-20150717223222113-00000.warc.gz"}
        try:
            payload_digest = records[0].get_header(b'WARC-Payload-Digest').decode('utf-8')
        except:
            payload_digest = '-'
        type_ = records[0].type.decode('utf-8') if records else '-'
        filename = records[0].warc_filename if records else '-'
        offset = records[0].offset if records else '-'
        self.logger.info(
                '%s %s %s %s %s size=%s %s %s %s offset=%s',
                recorded_url.client_ip, recorded_url.status,
                recorded_url.method, recorded_url.url.decode('utf-8'),
                recorded_url.mimetype, recorded_url.size, payload_digest,
                type_, filename, offset)

    def _shutdown(self):
        self.writer_pool.close_writers()

