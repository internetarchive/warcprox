'''
warcprox/writer.py - warc writer, manages and writes records to warc files

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
'''
import logging
from hanzo import warctools
import fcntl
import time
import warcprox
import os
import socket
import random

class WarcWriter:
    '''
    A writer for one warc prefix, which rolls over to new warc file,
    incrementing serial number, when size limit is hit. Should only be used
    from one thread.
    '''
    logger = logging.getLogger('warcprox.writer.WarcWriter')

    def __init__(self, options=warcprox.Options()):
        self.options = options

        self.gzip = options.gzip or False
        self.record_builder = warcprox.warc.WarcRecordBuilder(
                digest_algorithm=options.digest_algorithm or 'sha1',
                base32=options.base32)

        self.f = None
        self.path = None
        self.finalname = None
        self.gzip = options.gzip or False
        self.prefix = options.prefix or 'warcprox'
        self.port = options.port or 8000
        self.open_suffix = '' if options.no_warc_open_suffix else '.open'
        self.rollover_size = options.rollover_size or 1000000000
        self.rollover_idle_time = options.rollover_idle_time or None
        if options.subdir_prefix and options.prefix:
            self.directory = os.path.sep.join([options.directory, options.prefix]) or './warcs'
        else:
            self.directory = options.directory or './warcs'
        self.filename_template = options.warc_filename or \
                '{prefix}-{timestamp17}-{randomtoken}-{serialno}'
        self.last_activity = time.time()
        self.serial = 0
        self.randomtoken = ''.join(
                random.sample('abcdefghijklmnopqrstuvwxyz0123456789', 8))

    # h3 default <!-- <property name="template" value="${prefix}-${timestamp17}-${serialno}-${heritrix.pid}~${heritrix.hostname}~${heritrix.port}" /> -->
    def filename(self, serial):
        """WARC filename is configurable with CLI parameter --warc-filename.
        Default: '{prefix}-{timestamp17}-{randomtoken}-{serialno}'
        Available variables are: prefix, timestamp14, timestamp17, serialno,
        randomtoken, hostname, shorthostname, port.
        Extension ``.warc`` or ``.warc.gz`` is appended automatically.
        """
        hostname = socket.getfqdn()
        shorthostname = hostname.split('.')[0]
        fname = self.filename_template.format(
                prefix=self.prefix, timestamp14=warcprox.timestamp14(),
                timestamp17=warcprox.timestamp17(),
                serialno='{:05d}'.format(serial),
                randomtoken=self.randomtoken, hostname=hostname,
                shorthostname=shorthostname, port=self.port)
        if self.gzip:
            fname = fname + '.warc.gz'
        else:
            fname = fname + '.warc'
        return fname

    def open(self, serial):
        '''
        Opens a new warc file with filename prefix `self.prefix` and serial
        number `self.serial` and assigns file handle to `self.f`.
        '''
        if not os.path.exists(self.directory):
            self.logger.info(
                    "warc destination directory %s doesn't exist, creating it",
                    self.directory)
            os.mkdir(self.directory)

        self.finalname = self.filename(serial)
        self.logger.trace('opening %s', self.finalname)
        self.path = os.path.sep.join(
                [self.directory, self.finalname + self.open_suffix])

        self.f = open(self.path, 'wb')
        # if no '.open' suffix is used for WARC, acquire an exclusive
        # file lock.
        if self.open_suffix == '':
            try:
                fcntl.lockf(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                self.logger.error(
                        'could not lock file %s (%s)', self.path, exc)
        return self.f

    def ensure_open(self):
        '''
        Ensures `self.f` is ready to write the next warc record.

        If warc is not open, opens one, and writes the warcinfo record.
        '''
        if not self.f:
            serial = self.serial
            self.serial += 1
            self.open(serial)
            warcinfo = self.record_builder.build_warcinfo_record(self.finalname)
            self.logger.debug('warcinfo.headers=%s', warcinfo.headers)
            warcinfo.write_to(self.f, gzip=self.gzip)

    def write_records(self, recorded_url):
        '''
        Returns tuple of records written, which are instances of
        `hanzo.warctools.warc.WarcRecord`, decorated with `warc_filename` and
        `offset` attributes.
        '''
        records = self.record_builder.build_warc_records(recorded_url)

        self.ensure_open()
        total_warc_file_size = None
        for record in records:
            offset = self.f.tell()
            record.write_to(self.f, gzip=self.gzip)
            record.offset = offset
            offset2 = self.f.tell()
            record.length = offset2 - offset
            total_warc_file_size = offset2
            record.warc_filename = self.finalname
            self.logger.trace(
                    'wrote warc record: warc_type=%s content_length=%s '
                    'digest=%s offset=%d warc=%s url=%s', record.type,
                    record.get_header(warctools.WarcRecord.CONTENT_LENGTH),
                    record.get_header(b'WARC-Payload-Digest'), record.offset,
                    self.path, record.get_header(warctools.WarcRecord.URL))
        self.f.flush()
        self.last_activity = time.time()
        # Closes current warc if size limit has been reached.
        self.maybe_size_rollover(total_warc_file_size)
        return records

    def close(self):
        '''
        Closes out the active warc.

        The next call to `write_records()` will write to a a new warc file with
        the serial number incremented.
        '''
        if self.path:
            self.logger.trace('closing %s', self.finalname)
            if self.open_suffix == '':
                try:
                    fcntl.lockf(self.f, fcntl.LOCK_UN)
                except Exception as exc:
                    self.logger.error(
                            'could not unlock file %s (%s)', self.path, exc)
            try:
                self.f.close()
                finalpath = os.path.sep.join(
                        [self.directory, self.finalname])
                os.rename(self.path, finalpath)
            except Exception as exc:
                self.logger.error(
                    'could not close and rename file %s (%s)', self.path, exc)
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

    def maybe_size_rollover(self, total_warc_file_size):
        if total_warc_file_size and total_warc_file_size > self.rollover_size:
            self.logger.info(
                    'rolling over %s because it has reached %s bytes in size',
                    self.finalname, total_warc_file_size)
            self.close()

class WarcWriterPool:
    '''
    A `WarcWriter` per warc prefix. Should only be used from one thread.
    '''
    logger = logging.getLogger("warcprox.writer.WarcWriterPool")

    def __init__(self, options=warcprox.Options()):
        self.default_warc_writer = WarcWriter(options)
        self.warc_writers = {}  # {prefix:WarcWriter}
        self.options = options
        self._last_maybe = time.time()

    # chooses writer for filename specified by warcprox_meta["warc-prefix"] if set
    def _writer(self, recorded_url):
        w = self.default_warc_writer
        if recorded_url.warcprox_meta and "warc-prefix" in recorded_url.warcprox_meta:
            # self.logger.info("recorded_url.warcprox_meta={} for {}".format(recorded_url.warcprox_meta, recorded_url.url))
            options = warcprox.Options(**vars(self.options))
            options.prefix = recorded_url.warcprox_meta["warc-prefix"]
            if not options.prefix in self.warc_writers:
                self.warc_writers[options.prefix] = WarcWriter(options)
            w = self.warc_writers[options.prefix]
        return w

    def write_records(self, recorded_url):
        '''
        Returns tuple of records written, which are instances of
        `hanzo.warctools.warc.WarcRecord`, decorated with `warc_filename` and
        `offset` attributes.
        '''
        return self._writer(recorded_url).write_records(recorded_url)

    def maybe_idle_rollover(self):
        if time.time() - self._last_maybe > 20:
            self.default_warc_writer.maybe_idle_rollover()
            for w in self.warc_writers.values():
                w.maybe_idle_rollover()
            self._last_maybe = time.time()

    def close_writers(self):
        self.default_warc_writer.close()
        for prefix, writer in list(self.warc_writers.items()):
            del self.warc_writers[prefix]
            writer.close()

    def close_for_prefix(self, prefix=None):
        '''
        Close warc writer for the given warc prefix, or the default prefix if
        `prefix` is `None`.
        '''
        if prefix and prefix in self.warc_writers:
            writer = self.warc_writers[prefix]
            del self.warc_writers[prefix]
            writer.close()
        else:
            self.default_warc_writer.close()

