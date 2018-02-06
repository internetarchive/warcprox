"""
warcprox/__init__.py - warcprox package main file, contains some utility code

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
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.
"""

import sys
import datetime
import threading
import time
import logging
from argparse import Namespace as _Namespace
from pkg_resources import get_distribution as _get_distribution
__version__ = _get_distribution('warcprox').version
try:
    import queue
except ImportError:
    import Queue as queue

def digest_str(hash_obj, base32=False):
    import base64
    return hash_obj.name.encode('utf-8') + b':' + (
            base64.b32encode(hash_obj.digest()) if base32
            else hash_obj.hexdigest().encode('ascii'))

class Options(_Namespace):
    def __getattr__(self, name):
        try:
            return super(Options, self).__getattr__(self, name)
        except AttributeError:
            return None

class TimestampedQueue(queue.Queue):
    """
    A queue.Queue that exposes the time enqueued of the oldest item in the
    queue.
    """
    def put(self, item, block=True, timeout=None):
        return queue.Queue.put(
                self, (datetime.datetime.utcnow(), item), block, timeout)

    def get(self, block=True, timeout=None):
        timestamp, item = self.get_with_timestamp(block, timeout)
        return item

    get_with_timestamp = queue.Queue.get

    def oldest_timestamp(self):
        with self.mutex:
            if self.queue:
                timestamp, item = self.queue[0]
            else:
                return None
        return timestamp

    def seconds_behind(self):
        timestamp = self.oldest_timestamp()
        if timestamp:
            return (datetime.datetime.utcnow() - timestamp).total_seconds()
        else:
            return 0.0

# XXX linux-specific
def gettid():
    try:
        import ctypes
        libc = ctypes.cdll.LoadLibrary('libc.so.6')
        SYS_gettid = 186
        tid = libc.syscall(SYS_gettid)
        return tid
    except:
        return "n/a"

class RequestBlockedByRule(Exception):
    """
    An exception raised when a request should be blocked to respect a
    Warcprox-Meta rule.
    """
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return "%s: %s" % (self.__class__.__name__, self.msg)

class BasePostfetchProcessor(threading.Thread):
    logger = logging.getLogger("warcprox.BasePostfetchProcessor")

    def __init__(self, options=Options()):
        threading.Thread.__init__(self, name=self.__class__.__name__)
        self.options = options
        self.stop = threading.Event()
        # these should be set before thread is started
        self.inq = None
        self.outq = None
        self.profiler = None

    def run(self):
        if self.options.profile:
            import cProfile
            self.profiler = cProfile.Profile()
            self.profiler.enable()
            self._run()
            self.profiler.disable()
        else:
            self._run()

    def _get_process_put(self):
        '''
        Get url(s) from `self.inq`, process url(s), queue to `self.outq`.

        Subclasses must implement this. Implementations may operate on
        individual urls, or on batches.

        May raise queue.Empty.
        '''
        raise Exception('not implemented')

    def _run(self):
        logging.info('%s starting up', self)
        self._startup()
        while not self.stop.is_set():
            try:
                while True:
                    try:
                        self._get_process_put()
                    except queue.Empty:
                        if self.stop.is_set():
                            break
                logging.info('%s shutting down', self)
                self._shutdown()
            except Exception as e:
                if isinstance(e, OSError) and e.errno == 28:
                    # OSError: [Errno 28] No space left on device
                    self.logger.critical(
                            'shutting down due to fatal problem: %s: %s',
                            e.__class__.__name__, e)
                    self._shutdown()
                    sys.exit(1)

                self.logger.critical(
                    '%s will try to continue after unexpected error',
                    self.name, exc_info=True)
                time.sleep(0.5)

    def _startup(self):
        pass

    def _shutdown(self):
        pass

class BaseStandardPostfetchProcessor(BasePostfetchProcessor):
    def _get_process_put(self):
        recorded_url = self.inq.get(block=True, timeout=0.5)
        self._process_url(recorded_url)
        if self.outq:
            self.outq.put(recorded_url)

    def _process_url(self, recorded_url):
        raise Exception('not implemented')

class BaseBatchPostfetchProcessor(BasePostfetchProcessor):
    MAX_BATCH_SIZE = 500
    MAX_BATCH_SEC = 10
    MIN_BATCH_SEC = 2.0

    def _get_process_put(self):
        batch = []
        start = time.time()

        while True:
            try:
                batch.append(self.inq.get(block=True, timeout=0.5))
            except queue.Empty:
                if self.stop.is_set():
                    break
                # else maybe keep adding to the batch

            if len(batch) >= self.MAX_BATCH_SIZE:
                break  # full batch

            elapsed = time.time() - start
            if elapsed >= self.MAX_BATCH_SEC:
                break  # been batching for a while

            if (elapsed >= self.MIN_BATCH_SEC and self.outq
                    and len(self.outq.queue) == 0):
                break  # next processor is waiting on us

        if not batch:
            raise queue.Empty

        self.logger.info(
                'gathered batch of %s in %0.2f sec',
                len(batch), time.time() - start)
        self._process_batch(batch)

        if self.outq:
            for recorded_url in batch:
                self.outq.put(recorded_url)

    def _process_batch(self, batch):
        raise Exception('not implemented')

class ListenerPostfetchProcessor(BaseStandardPostfetchProcessor):
    def __init__(self, listener, options=Options()):
        BaseStandardPostfetchProcessor.__init__(self, options)
        self.listener = listener
        self.name = listener.__class__.__name__

    def _process_url(self, recorded_url):
        return self.listener.notify(recorded_url, recorded_url.warc_records)

    def start(self):
        if hasattr(self.listener, 'start'):
            self.listener.start()
        BaseStandardPostfetchProcessor.start(self)

    def _shutdown(self):
        if hasattr(self.listener, 'stop'):
            try:
                self.listener.stop()
            except:
                self.logger.error(
                        '%s raised exception', listener.stop, exc_info=True)

def timestamp17():
    now = datetime.datetime.utcnow()
    return '{:%Y%m%d%H%M%S}{:03d}'.format(now, now.microsecond//1000)

def timestamp14():
    now = datetime.datetime.utcnow()
    return '{:%Y%m%d%H%M%S}'.format(now)

# monkey-patch log levels TRACE and NOTICE
TRACE = 5
def _logger_trace(self, msg, *args, **kwargs):
    if self.isEnabledFor(TRACE):
        self._log(TRACE, msg, args, **kwargs)
logging.Logger.trace = _logger_trace
logging.trace = logging.root.trace
logging.addLevelName(TRACE, 'TRACE')

NOTICE = (logging.INFO + logging.WARN) // 2
def _logger_notice(self, msg, *args, **kwargs):
    if self.isEnabledFor(NOTICE):
        self._log(NOTICE, msg, args, **kwargs)
logging.Logger.notice = _logger_notice
logging.notice = logging.root.notice
logging.addLevelName(NOTICE, 'NOTICE')

import warcprox.controller as controller
import warcprox.playback as playback
import warcprox.dedup as dedup
import warcprox.warcproxy as warcproxy
import warcprox.mitmproxy as mitmproxy
import warcprox.writer as writer
import warcprox.warc as warc
import warcprox.writerthread as writerthread
import warcprox.stats as stats
import warcprox.bigtable as bigtable
import warcprox.crawl_log as crawl_log
