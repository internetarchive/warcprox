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
from hanzo import warctools
import fcntl
import time
import warcprox
import os
import socket
import random
import threading
try:
    import queue
except ImportError:
    import Queue as queue
import contextlib
from datetime import datetime, timedelta


class _OneWritableWarc:
    '''
    Utility class used by WarcWriter
    '''

    logger = logging.getLogger('warcprox.writer._OneWritableWarc')

    def __init__(self, options=warcprox.Options(), randomtoken='0'):
        self.f = None
        self.path = None
        self.finalname = None
        self.gzip = options.gzip or False
        self.prefix = options.prefix or 'warcprox'
        self.open_suffix = '' if options.no_warc_open_suffix else '.open'
        self.randomtoken = randomtoken
        self.rollover_size = options.rollover_size or 1000000000
        self.rollover_idle_time = options.rollover_idle_time or None
        self.rollover_time = options.rollover_time or None
        self.directory = options.directory or './warcs'
        self.filename_template = options.warc_filename or \
                '{prefix}-{timestamp17}-{randomtoken}-{serialno}'
        self.last_activity = time.time()
        self.current_rollover_time = None

    # h3 default <!-- <property name="template" value="${prefix}-${timestamp17}-${serialno}-${heritrix.pid}~${heritrix.hostname}~${heritrix.port}" /> -->
    def next_filename(self, serial):
        """WARC filename is configurable with CLI parameter --warc-filename.
        Default: '{prefix}-{timestamp17}-{randomtoken}-{serialno}'
        Available variables are: prefix, timestamp14, timestamp17, serialno,
        randomtoken, hostname, shorthostname.
        Extension ``.warc`` or ``.warc.gz`` is appended automatically.
        """
        hostname = socket.getfqdn()
        shorthostname = hostname.split('.')[0]
        fname = self.filename_template.format(
                prefix=self.prefix, timestamp14=warcprox.timestamp14(),
                timestamp17=warcprox.timestamp17(),
                serialno='{:05d}'.format(serial),
                randomtoken=self.randomtoken, hostname=hostname,
                shorthostname=shorthostname)
        if self.gzip:
            fname = fname + '.warc.gz'
        else:
            fname = fname + '.warc'
        return fname

    def open(self, serial):
        if not os.path.exists(self.directory):
            self.logger.info(
                    "warc destination directory %s doesn't exist, creating it",
                    self.directory)
            os.mkdir(self.directory)

        self.finalname = self.next_filename(serial)
        self.logger.trace('opening %s', self.finalname)
        self.path = os.path.sep.join(
                [self.directory, self.finalname + self.open_suffix])

        self.f = open(self.path, 'wb')
        self.current_rollover_time = datetime.utcnow()
        # if no '.open' suffix is used for WARC, acquire an exclusive
        # file lock.
        if self.open_suffix == '':
            try:
                fcntl.lockf(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError as exc:
                self.logger.error(
                        'could not lock file %s (%s)', self.path, exc)
        return self.f

    def close(self):
        if self.path:
            self.logger.trace('closing %s', self.finalname)
            if self.open_suffix == '':
                try:
                    fcntl.lockf(self.f, fcntl.LOCK_UN)
                except IOError as exc:
                    self.logger.error(
                            'could not unlock file %s (%s)', self.path, exc)
            self.f.close()
            finalpath = os.path.sep.join(
                    [self.directory, self.finalname])
            os.rename(self.path, finalpath)

            self.path = None
            self.f = None

    def maybe_idle_rollover(self):
        if (self.path and self.rollover_idle_time
                and self.rollover_idle_time > 0
                and time.time() - self.last_activity > self.rollover_idle_time):
            self.logger.info(
                    'rolling over %s after %0.1f seconds idle',
                    self.finalname, time.time() - self.last_activity)
            self.close()

    def maybe_size_rollover(self):
        if self.path and os.path.getsize(self.path) > self.rollover_size:
            self.logger.info(
                    'rolling over %s because it has reached %s bytes in size',
                    self.finalname, os.path.getsize(self.path))
            self.close()

    def maybe_time_rollover(self):
        if self.path and self.rollover_time and datetime.utcnow() - self.current_rollover_time > timedelta(seconds=self.rollover_time):
            self.logger.info('rolling over because exceeded rollover time.')
            self.close()

class WarcWriter:
    logger = logging.getLogger('warcprox.writer.WarcWriter')

    def __init__(self, options=warcprox.Options()):
        self.options = options

        self.gzip = options.gzip or False
        self.record_builder = warcprox.warc.WarcRecordBuilder(
                digest_algorithm=options.digest_algorithm or 'sha1',
                base32=options.base32)

        self._available_warcs = queue.Queue()
        self._warc_count = 0
        self._warc_count_lock = threading.Lock()

        self._serial = 0
        self._serial_lock = threading.Lock()

        self._randomtoken = ''.join(
                random.sample('abcdefghijklmnopqrstuvwxyz0123456789', 8))

    def _bespeak_warc(self):
        try:
            return self._available_warcs.get(block=False)
        except queue.Empty:
            with self._warc_count_lock:
                if self._warc_count < self.options.writer_threads:
                    self._warc_count += 1
                    return _OneWritableWarc(self.options, self._randomtoken)
            # else we're maxed out, wait for one to free up
            return self._available_warcs.get(block=True)

    @contextlib.contextmanager
    def _warc(self):
        warc = self._bespeak_warc()

        warc.maybe_size_rollover()
        warc.maybe_time_rollover()

        # lazy file open
        if warc.f == None:
            with self._serial_lock:
                serial = self._serial
                self._serial += 1
            warc.open(serial)
            warcinfo = self.record_builder.build_warcinfo_record(warc.finalname)
            self.logger.debug('warcinfo.headers=%s', warcinfo.headers)
            warcinfo.write_to(warc.f, gzip=self.gzip)

        yield warc

        # __exit__()
        warc.f.flush()
        warc.last_activity = time.time()
        self._available_warcs.put(warc)

    def write_records(self, recorded_url):
        """Returns tuple of records written, which are instances of
        hanzo.warctools.warc.WarcRecord, decorated with "warc_filename" and
        "offset" attributes."""
        records = self.record_builder.build_warc_records(recorded_url)

        with self._warc() as warc:
            for record in records:
                offset = warc.f.tell()
                record.write_to(warc.f, gzip=self.gzip)
                record.offset = offset
                record.length = warc.f.tell() - offset
                record.warc_filename = warc.finalname
                self.logger.debug(
                        'wrote warc record: warc_type=%s content_length=%s '
                        'url=%s warc=%s offset=%d',
                        record.get_header(warctools.WarcRecord.TYPE),
                        record.get_header(warctools.WarcRecord.CONTENT_LENGTH),
                        record.get_header(warctools.WarcRecord.URL),
                        warc.path, record.offset)

        return records

    def maybe_idle_rollover(self):
        warcs = []
        while True:
            try:
                warc = self._available_warcs.get(block=False)
                warcs.append(warc)
            except queue.Empty:
                break
        for warc in warcs:
            warc.maybe_idle_rollover()
            self._available_warcs.put(warc)

    def close_writer(self):
        while self._warc_count > 0:
            with self._warc_count_lock:
                warc = self._available_warcs.get()
                warc.close()
                self._warc_count -= 1

class WarcWriterPool:
    logger = logging.getLogger("warcprox.writer.WarcWriterPool")

    def __init__(self, options=warcprox.Options()):
        self.default_warc_writer = WarcWriter(options)
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
                    self.warc_writers[options.prefix] = WarcWriter(options)
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

