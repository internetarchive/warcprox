"""
warcprox/__init__.py - warcprox package main file, contains some utility code

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
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.
"""

from argparse import Namespace as _Namespace
from pkg_resources import get_distribution as _get_distribution
__version__ = _get_distribution('warcprox').version
try:
    import queue
except ImportError:
    import Queue as queue
import datetime

def digest_str(hash_obj, base32):
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

# monkey-patch log level TRACE
TRACE = 5
import logging
def _logging_trace(msg, *args, **kwargs):
    logging.root.trace(msg, *args, **kwargs)
def _logger_trace(self, msg, *args, **kwargs):
    if self.isEnabledFor(TRACE):
        self._log(TRACE, msg, args, **kwargs)
logging.trace = _logging_trace
logging.Logger.trace = _logger_trace
logging.addLevelName(TRACE, 'TRACE')

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
import warcprox.kafkafeed as kafkafeed
