'''
warcprox/controller.py - contains WarcproxController class, responsible for
starting up and shutting down the various components of warcprox, and for
sending heartbeats to the service registry if configured to do so; also has
some memory profiling capabilities

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
'''

from __future__ import absolute_import

import logging
import threading
import time
import sys
import gc
import datetime
import warcprox
import certauth

class Factory:
    @staticmethod
    def dedup_db(options):
        if options.rethinkdb_dedup_url:
            dedup_db = warcprox.dedup.RethinkDedupDb(options=options)
        elif options.rethinkdb_big_table_url:
            dedup_db = warcprox.bigtable.RethinkCapturesDedup(options=options)
        elif options.rethinkdb_trough_db_url:
            dedup_db = warcprox.dedup.TroughDedupDb(options)
        elif options.cdxserver_dedup:
            dedup_db = warcprox.dedup.CdxServerDedup(
                cdx_url=options.cdxserver_dedup)
        elif options.dedup_db_file in (None, '', '/dev/null'):
            logging.info('deduplication disabled')
            dedup_db = None
        else:
            dedup_db = warcprox.dedup.DedupDb(options.dedup_db_file, options=options)
        return dedup_db

    @staticmethod
    def stats_db(options):
        if options.rethinkdb_stats_url:
            stats_db = warcprox.stats.RethinkStatsDb(options=options)
        elif options.stats_db_file in (None, '', '/dev/null'):
            logging.info('statistics tracking disabled')
            stats_db = None
        else:
            stats_db = warcprox.stats.StatsDb(options.stats_db_file, options=options)
        return stats_db

    # @staticmethod
    # def certauth(options):
    #     ca_name = 'Warcprox CA on {}'.format(socket.gethostname())[:64]
    #     ca = certauth.certauth.CertificateAuthority(
    #             options.cacert, args.certs_dir, ca_name=ca_name)
    #     return ca

    @staticmethod
    def playback_proxy(options):
        if options.playback_port is not None:
            playback_index_db = warcprox.playback.PlaybackIndexDb(
                    options.playback_index_db_file, options=options)
            playback_proxy = warcprox.playback.PlaybackProxy(
                    ca=ca, playback_index_db=playback_index_db, options=options)
        else:
            playback_index_db = None
            playback_proxy = None
        return playback_proxy

    @staticmethod
    def crawl_logger(options):
        if options.crawl_log_dir:
            return warcprox.crawl_log.CrawlLogger(
                options.crawl_log_dir, options=options))
        else:
            return None

    @staticmethod
    def plugin(qualname, inq, outq):
        try:
            (module_name, class_name) = qualname.rsplit('.', 1)
            module_ = importlib.import_module(module_name)
            class_ = getattr(module_, class_name)
            instance = class_()
            plugin.notify  # make sure it has this method
            return instance
        except Exception as e:
            logging.fatal('problem with plugin class %r: %s', qualname, e)
            sys.exit(1)

    # @staticmethod
    # def plugins(options):
    #     plugins = []
    #     for qualname in options.plugins or []:
    #         try:
    #             (module_name, class_name) = qualname.rsplit('.', 1)
    #             module_ = importlib.import_module(module_name)
    #             class_ = getattr(module_, class_name)
    #             plugin = class_()
    #             plugin.notify  # make sure it has this method
    #             plugins.append(plugin)
    #         except Exception as e:
    #             logging.fatal('problem with plugin class %r: %s', qualname, e)
    #             sys.exit(1)
    #     return plugins

    # @staticmethod
    # def service_registry(options):
    #     if options.rethinkdb_services_url:
    #         parsed = doublethink.parse_rethinkdb_url(
    #                 options.rethinkdb_services_url)
    #         rr = doublethink.Rethinker(servers=parsed.hosts, db=parsed.database)
    #         return doublethink.ServiceRegistry(rr, table=parsed.table)
    #     else:
    #         return None

class WarcproxController(object):
    logger = logging.getLogger("warcprox.controller.WarcproxController")

    HEARTBEAT_INTERVAL = 20.0

    def __init__(self, options=warcprox.Options()):
        """
        Create warcprox controller based on `options`.
        """
        self.options = options

        self.proxy_thread = None
        self.playback_proxy_thread = None
        self._last_rss = None
        self.stop = threading.Event()
        self._start_stop_lock = threading.Lock()

        self.proxy = warcprox.warcproxy.WarcProxy(options=options)

        self.build_postfetch_chain(proxy.recorded_url_q)

        # if warc_writer_threads is not None:
        #     self.warc_writer_threads = warc_writer_threads
        # else:
        #     self.warc_writer_threads = [
        #             warcprox.writerthread.WarcWriterThread(
        #                 name='WarcWriterThread%03d' % i,
        #                 recorded_url_q=self.proxy.recorded_url_q,
        #                 listeners=[self.proxy.running_stats], options=options)
        #             for i in range(int(self.proxy.max_threads ** 0.5))]
        # self.playback_proxy = playback_proxy
        # self.service_registry = service_registry

    def build_postfetch_chain(self, inq):
        outq = warcprox.TimestampedQueue(maxsize=self.options.queue_size)

        def maybe_add_to_chain(processor_init):
            processor = processor_init(inq, outq, self.options)
            if processor:
                self._postfetch_chain.append(processor)
                inq = outq
                outq = warcprox.TimestampedQueue(maxsize=self.options.queue_size)

        self.dedup_db = Factory.dedup_db(options)

        # dedup loader
        if self.dedup_db:
            maybe_add_to_chain(self.dedup_db.loader)

        # warc writer
        maybe_add_to_chain(Factory.warc_writer)

        # dedup storer
        if self.dedup_db:
            maybe_add_to_chain(self.dedup_db.storer)

        # playback index storer
        # XXX XXX XXX FIXME
        # self.playback_proxy = Factory.playback_proxy(options)
        # if self.playback_proxy:
        #     maybe_add_to_chain()
        #     outq = warcprox.TimestampedQueue(maxsize=self.options.queue_size)
        #     processor = self.playback_proxy.playback_index_db(inq, outq)
        #     self._postfetch_chain.append(processor)
        #     inq = outq

        # stats db
        maybe_add_to_chain(Factory.stats_db)

        # crawl logger
        maybe_add_to_chain(Factory.crawl_logger)

        for qualname in self.options.plugins:
            maybe_add_to_chain(
                lambda inq, outq, options: Factory.plugin(qualname, inq, outq))
        # self.plugins = Factory.plugins(options)

        
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
                'version': warcprox.__version__,
                'ttl': self.HEARTBEAT_INTERVAL * 3,
                'port': self.proxy.server_port,
            }
        status_info.update(self.proxy.status())

        self.status_info = self.service_registry.heartbeat(status_info)
        self.logger.log(
                warcprox.TRACE, "status in service registry: %s",
                self.status_info)

    def start(self):
        with self._start_stop_lock:
            if self.proxy_thread and self.proxy_thread.is_alive():
                self.logger.info('warcprox is already running')
                return

            if self.proxy.stats_db:
                self.proxy.stats_db.start()
            self.proxy_thread = threading.Thread(
                    target=self.proxy.serve_forever, name='ProxyThread')
            self.proxy_thread.start()

            assert(all(
                wwt.dedup_db is self.warc_writer_threads[0].dedup_db
                for wwt in self.warc_writer_threads))
            if any((t.dedup_db for t in self.warc_writer_threads)):
                self.warc_writer_threads[0].dedup_db.start()

            for wwt in self.warc_writer_threads:
                wwt.start()

            if self.playback_proxy is not None:
                self.playback_proxy_thread = threading.Thread(
                        target=self.playback_proxy.serve_forever,
                        name='PlaybackProxyThread')
                self.playback_proxy_thread.start()

    def shutdown(self):
        with self._start_stop_lock:
            if not self.proxy_thread or not self.proxy_thread.is_alive():
                self.logger.info('warcprox is not running')
                return

            for wwt in self.warc_writer_threads:
                wwt.stop.set()
            self.proxy.shutdown()
            self.proxy.server_close()

            if self.playback_proxy is not None:
                self.playback_proxy.shutdown()
                self.playback_proxy.server_close()
                if self.playback_proxy.playback_index_db is not None:
                    self.playback_proxy.playback_index_db.close()

            # wait for threads to finish
            for wwt in self.warc_writer_threads:
                wwt.join()

            if self.proxy.stats_db:
                self.proxy.stats_db.stop()

            self.proxy_thread.join()
            if self.playback_proxy is not None:
                self.playback_proxy_thread.join()

            if self.service_registry and hasattr(self, "status_info"):
                self.service_registry.unregister(self.status_info["id"])

    def run_until_shutdown(self):
        """
        Start warcprox and run until shut down. Call
        warcprox_controller.stop.set() to initiate graceful shutdown.
        """
        self.start()

        last_mem_dbg = datetime.datetime.utcfromtimestamp(0)
        last_profile_dump = datetime.datetime.utcnow()

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
                if self.proxy.running_stats:
                    self.proxy.running_stats.snap()

                if self.service_registry and (
                        not hasattr(self, "status_info") or (
                            datetime.datetime.now(utc)
                            - self.status_info["last_heartbeat"]
                        ).total_seconds() > self.HEARTBEAT_INTERVAL):
                    self._service_heartbeat()

                # if self.options.profile and (
                #             datetime.datetime.utcnow() - last_mem_dbg
                #         ).total_seconds() > 60:
                #     self.debug_mem()
                #     last_mem_dbg = datetime.datetime.utcnow()

                if (self.options.profile and
                        (datetime.datetime.utcnow() - last_profile_dump
                            ).total_seconds() > 60*10):
                    self._dump_profiling()
                    last_profile_dump = datetime.datetime.utcnow()

                time.sleep(0.5)

            if self.options.profile:
                self._dump_profiling()
        except:
            self.logger.critical(
                    "shutting down in response to fatal exception",
                    exc_info=True)
            pass
        finally:
            self.shutdown()

    def _dump_profiling(self):
        import pstats, tempfile, os, io
        with tempfile.TemporaryDirectory() as tmpdir:
            # proxy threads
            files = []
            for th_id, profiler in self.proxy.profilers.items():
                file = os.path.join(tmpdir, '%s.dat' % th_id)
                profiler.dump_stats(file)
                files.append(file)

            buf = io.StringIO()
            stats = pstats.Stats(*files, stream=buf)
            stats.sort_stats('cumulative')
            stats.print_stats(0.1)
            self.logger.notice(
                    'aggregate performance profile of %s proxy threads:\n%s',
                    len(files), buf.getvalue())

            # warc writer threads
            files = []
            for wwt in self.warc_writer_threads:
                file = os.path.join(tmpdir, '%s.dat' % wwt.ident)
                wwt.profiler.dump_stats(file)
                files.append(file)

            buf = io.StringIO()
            stats = pstats.Stats(*files, stream=buf)
            stats.sort_stats('cumulative')
            stats.print_stats(0.1)
            self.logger.notice(
                    'aggregate performance profile of %s warc writer threads:\n%s',
                    len(self.warc_writer_threads), buf.getvalue())

