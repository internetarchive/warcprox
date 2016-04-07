#
# warcprox/writer.py - warc writer, manages and writes records to warc files
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

import logging
from datetime import datetime
from hanzo import warctools
import time
import warcprox
import os
import socket
import string
import random

class WarcWriter:
    logger = logging.getLogger('warcprox.writer.WarcWriter')

    def __init__(self, options=warcprox.Options()):

        self.rollover_size = options.rollover_size or 1000000000
        self.rollover_idle_time = options.rollover_idle_time or None
        self._last_activity = time.time()

        self.gzip = options.gzip or False
        digest_algorithm = options.digest_algorithm or 'sha1'
        base32 = options.base32
        self.record_builder = warcprox.warc.WarcRecordBuilder(digest_algorithm=digest_algorithm, base32=base32)

        # warc path and filename stuff
        self.directory = options.directory or './warcs'
        self.prefix = options.prefix or 'warcprox'

        self._f = None
        self._fpath = None
        self._f_finalname = None
        self._serial = 0

        self._randomtoken = "".join(random.Random().sample(string.digits + string.ascii_lowercase, 8))

        if not os.path.exists(self.directory):
            self.logger.info("warc destination directory {} doesn't exist, creating it".format(self.directory))
            os.mkdir(self.directory)

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

    # h3 default <!-- <property name="template" value="${prefix}-${timestamp17}-${serialno}-${heritrix.pid}~${heritrix.hostname}~${heritrix.port}" /> -->
    # ${prefix}-${timestamp17}-${randomtoken}-${serialno}.warc.gz"
    def _writer(self):
        if self._fpath and os.path.getsize(self._fpath) > self.rollover_size:
            self.close_writer()

        if self._f == None:
            self._f_finalname = '{}-{}-{:05d}-{}.warc{}'.format(
                    self.prefix, self.timestamp17(), self._serial, self._randomtoken, '.gz' if self.gzip else '')
            self._fpath = os.path.sep.join([self.directory, self._f_finalname + '.open'])

            self._f = open(self._fpath, 'wb')

            warcinfo_record = self.record_builder.build_warcinfo_record(self._f_finalname)
            self.logger.debug('warcinfo_record.headers={}'.format(warcinfo_record.headers))
            warcinfo_record.write_to(self._f, gzip=self.gzip)

            self._serial += 1

        return self._f

    def write_records(self, recorded_url):
        """Returns tuple of records written, which are instances of
        hanzo.warctools.warc.WarcRecord, decorated with "warc_filename" and
        "offset" attributes."""
        records = self.record_builder.build_warc_records(recorded_url)

        writer = self._writer()
        recordset_offset = writer.tell()

        for record in records:
            offset = writer.tell()
            record.write_to(writer, gzip=self.gzip)
            record.offset = offset
            record.length = writer.tell() - offset
            record.warc_filename = self._f_finalname
            self.logger.debug('wrote warc record: warc_type=%s content_length=%s url=%s warc=%s offset=%d',
                    record.get_header(warctools.WarcRecord.TYPE),
                    record.get_header(warctools.WarcRecord.CONTENT_LENGTH),
                    record.get_header(warctools.WarcRecord.URL),
                    self._fpath, record.offset)

        self._f.flush()
        self._last_activity = time.time()

        return records

    def maybe_idle_rollover(self):
        if (self._fpath is not None
                and self.rollover_idle_time is not None
                and self.rollover_idle_time > 0
                and time.time() - self._last_activity > self.rollover_idle_time):
            self.logger.debug('rolling over {} after {} seconds idle'.format(self._f_finalname, time.time() - self._last_activity))
            self.close_writer()

class WarcWriterPool:
    logger = logging.getLogger("warcprox.writer.WarcWriterPool")

    def __init__(self, options=warcprox.Options()):
        self.default_warc_writer = WarcWriter(options=options)
        self.warc_writers = {}  # {prefix:WarcWriter}
        self._last_sync = time.time()
        self.options = options

    # chooses writer for filename specified by warcprox_meta["warc-prefix"] if set
    def _writer(self, recorded_url):
        w = self.default_warc_writer
        if recorded_url.warcprox_meta and "warc-prefix" in recorded_url.warcprox_meta:
            # self.logger.info("recorded_url.warcprox_meta={} for {}".format(recorded_url.warcprox_meta, recorded_url.url))
            options = warcprox.Options(**vars(self.options))
            options.prefix = recorded_url.warcprox_meta["warc-prefix"]
            if not options.prefix in self.warc_writers:
                self.warc_writers[options.prefix] = WarcWriter(options=options)
            w = self.warc_writers[options.prefix]
        return w

    def write_records(self, recorded_url):
        """Returns tuple of records written, which are instances of
        hanzo.warctools.warc.WarcRecord, decorated with "warc_filename" and
        "offset" attributes."""
        return self._writer(recorded_url).write_records(recorded_url)

    def maybe_idle_rollover(self):
        self.default_warc_writer.maybe_idle_rollover()
        for w in self.warc_writers.values():
            w.maybe_idle_rollover()

    def close_writers(self):
        self.default_warc_writer.close_writer()
        for w in self.warc_writers.values():
            w.close_writer()

