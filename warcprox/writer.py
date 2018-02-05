'''
warcprox/writer.py - warc writer, manages and writes records to warc files

Copyright (C) 2013-2017 Internet Archive

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

from __future__ import absolute_import

import logging
from datetime import datetime
from hanzo import warctools
import fcntl
import time
import warcprox
import os
import socket
import string
import random
import threading

class WarcWriter:
    logger = logging.getLogger('warcprox.writer.WarcWriter')

    def __init__(self, options=warcprox.Options()):

        self.rollover_size = options.rollover_size or 1000000000
        self.rollover_idle_time = options.rollover_idle_time or None
        self._last_activity = time.time()

        self.gzip = options.gzip or False
        self.warc_filename = options.warc_filename or \
            '{prefix}-{timestamp17}-{randomtoken}-{serialno}'
        digest_algorithm = options.digest_algorithm or 'sha1'
        base32 = options.base32
        self.record_builder = warcprox.warc.WarcRecordBuilder(
                digest_algorithm=digest_algorithm, base32=base32)

        # warc path and filename stuff
        self.directory = options.directory or './warcs'
        self.prefix = options.prefix or 'warcprox'

        self._f = None
        self._fpath = None
        self._f_finalname = None
        self._f_open_suffix = '' if options.no_warc_open_suffix else '.open'
        self._serial = 0
        self._lock = threading.RLock()

        self._randomtoken = "".join(random.Random().sample(string.digits + string.ascii_lowercase, 8))

        if not os.path.exists(self.directory):
            self.logger.info("warc destination directory {} doesn't exist, creating it".format(self.directory))
            os.mkdir(self.directory)

    def timestamp17(self):
        now = datetime.utcnow()
        return '{:%Y%m%d%H%M%S}{:03d}'.format(now, now.microsecond//1000)

    def timestamp14(self):
        now = datetime.utcnow()
        return '{:%Y%m%d%H%M%S}'.format(now)

    def close_writer(self):
        with self._lock:
            if self._fpath:
                self.logger.info('closing %s', self._f_finalname)
                if self._f_open_suffix == '':
                    try:
                        fcntl.lockf(self._f, fcntl.LOCK_UN)
                    except IOError as exc:
                        self.logger.error('could not unlock file %s (%s)',
                                          self._fpath, exc)
                self._f.close()
                finalpath = os.path.sep.join(
                        [self.directory, self._f_finalname])
                os.rename(self._fpath, finalpath)

                self._fpath = None
                self._f = None

    def serial(self):
        return '{:05d}'.format(self._serial)

    # h3 default <!-- <property name="template" value="${prefix}-${timestamp17}-${serialno}-${heritrix.pid}~${heritrix.hostname}~${heritrix.port}" /> -->
    def _warc_filename(self):
        """WARC filename is configurable with CLI parameter --warc-filename.
        Default: '{prefix}-{timestamp17}-{serialno}-{randomtoken}'
        Available variables are: prefix, timestamp14, timestamp17, serialno,
        randomtoken, hostname, shorthostname.
        Extension ``.warc`` or ``.warc.gz`` is appended automatically.
        """
        hostname = socket.getfqdn()
        shorthostname = hostname.split('.')[0]
        fname = self.warc_filename.format(prefix=self.prefix,
                                          timestamp14=self.timestamp14(),
                                          timestamp17=self.timestamp17(),
                                          serialno=self.serial(),
                                          randomtoken=self._randomtoken,
                                          hostname=hostname,
                                          shorthostname=shorthostname)
        if self.gzip:
            fname = fname + '.warc.gz'
        else:
            fname = fname + '.warc'
        return fname

    def _writer(self):
        with self._lock:
            if self._fpath and os.path.getsize(
                    self._fpath) > self.rollover_size:
                self.close_writer()

            if self._f == None:
                self._f_finalname = self._warc_filename()
                self._fpath = os.path.sep.join([
                    self.directory, self._f_finalname + self._f_open_suffix])

                self._f = open(self._fpath, 'wb')
                # if no '.open' suffix is used for WARC, acquire an exclusive
                # file lock.
                if self._f_open_suffix == '':
                    try:
                        fcntl.lockf(self._f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except IOError as exc:
                        self.logger.error('could not lock file %s (%s)',
                                          self._fpath, exc)

                warcinfo_record = self.record_builder.build_warcinfo_record(
                        self._f_finalname)
                self.logger.debug(
                        'warcinfo_record.headers=%s', warcinfo_record.headers)
                warcinfo_record.write_to(self._f, gzip=self.gzip)

                self._serial += 1

        return self._f

    def write_records(self, recorded_url):
        """Returns tuple of records written, which are instances of
        hanzo.warctools.warc.WarcRecord, decorated with "warc_filename" and
        "offset" attributes."""
        records = self.record_builder.build_warc_records(recorded_url)

        with self._lock:
            writer = self._writer()

            for record in records:
                offset = writer.tell()
                record.write_to(writer, gzip=self.gzip)
                record.offset = offset
                record.length = writer.tell() - offset
                record.warc_filename = self._f_finalname
                self.logger.debug(
                        'wrote warc record: warc_type=%s content_length=%s '
                        'url=%s warc=%s offset=%d',
                        record.get_header(warctools.WarcRecord.TYPE),
                        record.get_header(warctools.WarcRecord.CONTENT_LENGTH),
                        record.get_header(warctools.WarcRecord.URL),
                        self._fpath, record.offset)

            self._f.flush()
            self._last_activity = time.time()

        return records

    def maybe_idle_rollover(self):
        with self._lock:
            if (self._fpath is not None
                    and self.rollover_idle_time is not None
                    and self.rollover_idle_time > 0
                    and time.time() - self._last_activity > self.rollover_idle_time):
                self.logger.info(
                        'rolling over %s after %s seconds idle',
                        self._f_finalname, time.time() - self._last_activity)
                self.close_writer()

class MultiWarcWriter(WarcWriter):
    logger = logging.getLogger("warcprox.writer.MultiWarcWriter")

    def __init__(self, options=warcprox.Options()):
        super().__init__(options)
        self._f = [None] * 3
        self._fpath = [None] * 3
        self._f_finalname = [None] * 3
        self._lock = [threading.RLock()] * 3

    def _writer(self, curr):
        with self._lock[curr]:
            if self._fpath[curr] and os.path.getsize(
                    self._fpath[curr]) > self.rollover_size:
                self.close_writer()

            if self._f[curr] == None:
                self._f_finalname[curr] = self._warc_filename()
                self._fpath[curr] = os.path.sep.join([
                    self.directory, self._f_finalname[curr] + self._f_open_suffix])

                self._f[curr] = open(self._fpath[curr], 'wb')
                # if no '.open' suffix is used for WARC, acquire an exclusive
                # file lock.
                if self._f_open_suffix == '':
                    try:
                        fcntl.lockf(self._f[curr], fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except IOError as exc:
                        self.logger.error('could not lock file %s (%s)',
                                          self._fpath, exc)

                warcinfo_record = self.record_builder.build_warcinfo_record(
                        self._f_finalname[curr])
                self.logger.debug(
                        'warcinfo_record.headers=%s', warcinfo_record.headers)
                warcinfo_record.write_to(self._f[curr], gzip=self.gzip)

                self._serial += 1

        return self._f[curr]

    def write_records(self, recorded_url):
        """Returns tuple of records written, which are instances of
        hanzo.warctools.warc.WarcRecord, decorated with "warc_filename" and
        "offset" attributes."""
        records = self.record_builder.build_warc_records(recorded_url)
        curr = random.choice([0, 1, 2])

        with self._lock[curr]:
            writer = self._writer(curr)

            for record in records:
                offset = writer.tell()
                record.write_to(writer, gzip=self.gzip)
                record.offset = offset
                record.length = writer.tell() - offset
                record.warc_filename = self._f_finalname[curr]
                self.logger.debug(
                        'wrote warc record: warc_type=%s content_length=%s '
                        'url=%s warc=%s offset=%d',
                        record.get_header(warctools.WarcRecord.TYPE),
                        record.get_header(warctools.WarcRecord.CONTENT_LENGTH),
                        record.get_header(warctools.WarcRecord.URL),
                        self._fpath[curr], record.offset)

            self._f[curr].flush()
            self._last_activity = time.time()

        return records

    def maybe_idle_rollover(self):
        for curr in range(0, 3):
            with self._lock[curr]:
                if (self._fpath[curr] is not None
                        and self.rollover_idle_time is not None
                        and self.rollover_idle_time > 0
                        and time.time() - self._last_activity > self.rollover_idle_time):
                    self.logger.info(
                            'rolling over %s after %s seconds idle',
                            self._f_finalname[curr], time.time() - self._last_activity)
                    self.close_writer(curr)

    def close_writer(self, curr):
        with self._lock[curr]:
            if self._fpath[curr]:
                self.logger.info('closing %s', self._f_finalname[curr])
                if self._f_open_suffix == '':
                    try:
                        fcntl.lockf(self._f[curr], fcntl.LOCK_UN)
                    except IOError as exc:
                        self.logger.error('could not unlock file %s (%s)',
                                          self._fpath[curr], exc)
                self._f[curr].close()
                finalpath = os.path.sep.join(
                        [self.directory, self._f_finalname[curr]])
                os.rename(self._fpath[curr], finalpath)

class WarcWriterPool:
    logger = logging.getLogger("warcprox.writer.WarcWriterPool")

    def __init__(self, options=warcprox.Options()):
        # self.default_warc_writer = WarcWriter(options=options)
        self.default_warc_writer = MultiWarcWriter(options=options)
        self.warc_writers = {}  # {prefix:WarcWriter}
        self.options = options
        self._lock = threading.RLock()
        self._last_maybe = time.time()

    # chooses writer for filename specified by warcprox_meta["warc-prefix"] if set
    def _writer(self, recorded_url):
        w = self.default_warc_writer
        if recorded_url.warcprox_meta and "warc-prefix" in recorded_url.warcprox_meta:
            # self.logger.info("recorded_url.warcprox_meta={} for {}".format(recorded_url.warcprox_meta, recorded_url.url))
            options = warcprox.Options(**vars(self.options))
            options.prefix = recorded_url.warcprox_meta["warc-prefix"]
            with self._lock:
                if not options.prefix in self.warc_writers:
                    self.warc_writers[options.prefix] = WarcWriter(
                            options=options)
                w = self.warc_writers[options.prefix]
        return w

    def write_records(self, recorded_url):
        """Returns tuple of records written, which are instances of
        hanzo.warctools.warc.WarcRecord, decorated with "warc_filename" and
        "offset" attributes."""
        return self._writer(recorded_url).write_records(recorded_url)

    def maybe_idle_rollover(self):
        if time.time() - self._last_maybe > 20:
            self.default_warc_writer.maybe_idle_rollover()
            for w in self.warc_writers.values():
                w.maybe_idle_rollover()
            self._last_maybe = time.time()

    def close_writers(self):
        self.default_warc_writer.close_writer()
        for w in self.warc_writers.values():
            w.close_writer()

