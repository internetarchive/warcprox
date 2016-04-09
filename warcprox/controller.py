#
# warcprox/controller.py - contains WarcproxController class, responsible for
# starting up and shutting down the various components of warcprox, and for
# sending heartbeats to the service registry if configured to do so; also has
# some memory profiling capabilities
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
# USA.
#

from __future__ import absolute_import

import logging
import threading
import time
import warcprox
import sys
import gc
import datetime

class WarcproxController(object):
    logger = logging.getLogger("warcprox.controller.WarcproxController")

    HEARTBEAT_INTERVAL = 20.0

    def __init__(self, proxy=None, warc_writer_thread=None,
        playback_proxy=None, service_registry=None,
        options=warcprox.Options()):
        """
        Create warcprox controller.

        If supplied, proxy should be an instance of WarcProxy, and
        warc_writer_thread should be an instance of WarcWriterThread. If not
        supplied, they are created with default values.

        If supplied, playback_proxy should be an instance of PlaybackProxy. If
        not supplied, no playback proxy will run.
        """
        if proxy is not None:
            self.proxy = proxy
        else:
            self.proxy = warcprox.warcprox.WarcProxy()

        if warc_writer_thread is not None:
            self.warc_writer_thread = warc_writer_thread
        else:
            self.warc_writer_thread = warcprox.warcwriter.WarcWriterThread(recorded_url_q=self.proxy.recorded_url_q)

        self.playback_proxy = playback_proxy
        self.service_registry = service_registry
        self.options = options

        self._last_rss = None

    def debug_mem(self):
        self.logger.info("self.proxy.recorded_url_q.qsize()=%s", self.proxy.recorded_url_q.qsize())
        with open("/proc/self/status") as f:
            for line in f:
                fields = line.split()
                if len(fields) >= 2:
                    k, v = fields[0:2]
                if k == "VmHWM:":
                    hwm = int(v)
                elif k == "VmRSS:":
                    rss = int(v)
                elif k == "VmData:":
                    data = int(v)
                elif k == "VmStk:":
                    stk = int(v)
        self.logger.info("rss=%s data=%s stack=%s hwm=%s", rss, data, stk, hwm)
        self._last_rss = self._last_rss or rss  # to set initial value

        if rss - self._last_rss > 1024:
            num_unreachable = gc.collect()
            all_objects = gc.get_objects()
            total_size = 0
            summary = {}
            biggest_objects = [None] * 10
            for obj in all_objects:
                size = sys.getsizeof(obj)
                total_size += size
                if not type(obj) in summary:
                    summary[type(obj)] = {"count":0,"size":0}
                summary[type(obj)]["count"] += 1
                summary[type(obj)]["size"] += size
                if size > sys.getsizeof(biggest_objects[-1]):
                    for i in range(len(biggest_objects)):
                        if size > sys.getsizeof(biggest_objects[i]):
                            index = i
                            break
                    biggest_objects[index+1:] = biggest_objects[index:-1]
                    biggest_objects[index] = obj

            self.logger.info("%s objects totaling %s bytes", len(all_objects), total_size)

            self.logger.info("=== biggest types ===")
            for item in sorted(summary.items(), key=lambda item: item[1]["size"], reverse=True)[:10]:
                self.logger.info("%s bytes in %s instances of %s", item[1]["size"], item[1]["count"], item[0])

            self.logger.info("=== warcprox types ===")
            for t in (t for t in summary if str(t).find("warcprox") >= 0):
                self.logger.info("%s bytes in %s instances of %s", summary[t]["size"], summary[t]["count"], t)

            for i in range(len(biggest_objects)):
                obj = biggest_objects[i]
                try:
                    value = repr(bytes(obj.getbuffer()[:100]))
                except:
                    try:
                        value = repr(obj)[:100]
                    except BaseException as e:
                        value = "<{} getting value>".format(e)
                self.logger.info("#%s (%s) (%s bytes) (%s refs) (id=%s): %s", i+1, type(obj), sys.getsizeof(obj), sys.getrefcount(obj), id(obj), value)
            self.logger.info("%s unreachable objects totaling %s bytes", len(gc.garbage), sum(sys.getsizeof(x) for x in gc.garbage))

        self._last_rss = rss

    def _service_heartbeat(self):
        if hasattr(self, 'status_info'):
            status_info = self.status_info
        else:
            status_info = {
                'role': 'warcprox',
                'heartbeat_interval': self.HEARTBEAT_INTERVAL,
                'port': self.options.port,
            }
        status_info['load'] = 1.0 * self.proxy.recorded_url_q.qsize() / (self.proxy.recorded_url_q.maxsize or 100)
        status_info['queue_size'] = self.proxy.recorded_url_q.qsize()

        self.status_info = self.service_registry.heartbeat(status_info)
        self.logger.debug("status in service registry: %s", self.status_info)

    def run_until_shutdown(self):
        """
        Start warcprox and run until shut down. Call
        warcprox_controller.stop.set() to initiate graceful shutdown.
        """
        proxy_thread = threading.Thread(target=self.proxy.serve_forever, name='ProxyThread')
        proxy_thread.start()
        self.warc_writer_thread.start()

        if self.playback_proxy is not None:
            playback_proxy_thread = threading.Thread(target=self.playback_proxy.serve_forever, name='PlaybackProxyThread')
            playback_proxy_thread.start()

        self.stop = threading.Event()

        last_mem_dbg = datetime.datetime.utcfromtimestamp(0)

        try:
            utc = datetime.timezone.utc
        except AttributeError:
            # python2 :-\
            class UTC(datetime.tzinfo):
                def tzname(self, dt): return "UTC+00:00"
                def dst(self, dt): return datetime.timedelta(0)
                def utcoffset(self, dt): return datetime.timedelta(0)
            utc = UTC()

        try:
            while not self.stop.is_set():
                if self.service_registry and (not hasattr(self, "status_info") or (datetime.datetime.now(utc) - self.status_info["last_heartbeat"]).total_seconds() > self.HEARTBEAT_INTERVAL):
                    self._service_heartbeat()

                if self.options.profile and (datetime.datetime.utcnow() - last_mem_dbg).total_seconds() > 60:
                    self.debug_mem()
                    last_mem_dbg = datetime.datetime.utcnow()

                time.sleep(0.5)
        except:
            self.logger.critical("fatal exception, shutting down", exc_info=True)
            pass
        finally:
            self.warc_writer_thread.stop.set()
            self.proxy.shutdown()
            self.proxy.server_close()

            if self.playback_proxy is not None:
                self.playback_proxy.shutdown()
                self.playback_proxy.server_close()
                if self.playback_proxy.playback_index_db is not None:
                    self.playback_proxy.playback_index_db.close()

            # wait for threads to finish
            self.warc_writer_thread.join()

            if self.proxy.stats_db:
                self.proxy.stats_db.close()
            if self.warc_writer_thread.dedup_db:
                self.warc_writer_thread.dedup_db.close()

            proxy_thread.join()
            if self.playback_proxy is not None:
                playback_proxy_thread.join()

            if self.service_registry and hasattr(self, "status_info"):
                self.service_registry.unregister(self.status_info["id"])

