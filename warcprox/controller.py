'''
warcprox/controller.py - contains WarcproxController class, responsible for
starting up and shutting down the various components of warcprox, and for
sending heartbeats to the service registry if configured to do so; also has
some memory profiling capabilities

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
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.
'''
import logging
import threading
import time
import sys
import gc
import datetime
import warcprox
import doublethink
import importlib
import queue
import socket
import os

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
                cdx_url=options.cdxserver_dedup, options=options)
        elif options.dedup_db_file in (None, '', '/dev/null'):
            logging.info('deduplication disabled')
            dedup_db = None
        else:
            dedup_db = warcprox.dedup.DedupDb(options.dedup_db_file, options=options)
        return dedup_db

    @staticmethod
    def stats_processor(options):
        if options.rethinkdb_stats_url:
            stats_processor = warcprox.stats.RethinkStatsProcessor(options)
        elif options.stats_db_file in (None, '', '/dev/null'):
            logging.info('statistics tracking disabled')
            stats_processor = None
        else:
            stats_processor = warcprox.stats.StatsProcessor(options)
        return stats_processor

    @staticmethod
    def warc_writer_processor(options):
        return warcprox.writerthread.WarcWriterProcessor(options)

    @staticmethod
    def playback_proxy(ca, options):
        if options.playback_port is not None:
            playback_index_db = warcprox.playback.PlaybackIndexDb(
                options=options)
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
                options.crawl_log_dir, options=options)
        else:
            return None

    @staticmethod
    def plugin(qualname, options, controller=None):
        try:
            (module_name, class_name) = qualname.rsplit('.', 1)
            module_ = importlib.import_module(module_name)
            class_ = getattr(module_, class_name)
            try:
                # new plugins take `options` and `controller` arguments
                plugin = class_(options, controller)
            except:
                try: # medium plugins take `options` argument
                    plugin = class_(options)
                except: # old plugins take no arguments
                    plugin = class_()
            # check that this is either a listener or a batch processor
            assert hasattr(plugin, 'notify') ^ hasattr(plugin, '_startup')
            return plugin
        except Exception as e:
            logging.fatal('problem with plugin class %r', qualname, exc_info=1)
            sys.exit(1)

    @staticmethod
    def service_registry(options):
        if options.rethinkdb_services_url:
            parsed = doublethink.parse_rethinkdb_url(
                    options.rethinkdb_services_url)
            rr = doublethink.Rethinker(servers=parsed.hosts, db=parsed.database)
            return doublethink.ServiceRegistry(rr, table=parsed.table)
        else:
            return None

class WarcproxController:
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

        self.stats_processor = Factory.stats_processor(self.options)

        self.proxy = warcprox.warcproxy.WarcProxy(
                self.stats_processor, self.postfetch_status, options)
        self.playback_proxy = Factory.playback_proxy(
            self.proxy.ca, self.options)

        self.build_postfetch_chain(self.proxy.recorded_url_q)

        self.service_registry = Factory.service_registry(options)

    def earliest_still_active_fetch_start(self):
        '''
        Looks at urls currently in flight, either being fetched or being
        processed at some step of the postfetch chain, finds the one with the
        earliest fetch start time, and returns that time.
        '''
        earliest = None
        for timestamp in list(self.proxy.active_requests.values()):
            if earliest is None or timestamp < earliest:
                earliest = timestamp
        for processor in self._postfetch_chain:
            with processor.inq.mutex:
                l = list(processor.inq.queue)
            for recorded_url in l:
                if earliest is None or recorded_url.timestamp < earliest:
                    earliest = recorded_url.timestamp
        return earliest

    def postfetch_status(self):
        earliest = self.earliest_still_active_fetch_start()
        if earliest:
            seconds_behind = (doublethink.utcnow() - earliest).total_seconds()
        else:
            seconds_behind = 0
        result = {
            'earliest_still_active_fetch_start': earliest,
            'seconds_behind': seconds_behind,
            'postfetch_chain': []
        }
        for processor in self._postfetch_chain:
            if processor.__class__ == warcprox.ListenerPostfetchProcessor:
                name = processor.listener.__class__.__name__
            else:
                name = processor.__class__.__name__

            queued = len(processor.inq.queue)
            if hasattr(processor, 'batch'):
                queued += len(processor.batch)

            result['postfetch_chain'].append({
                'processor': name, 'queued_urls': queued})
        return result

    def chain(self, processor0, processor1):
        '''
        Sets `processor0.outq` = `processor1.inq` = `queue.Queue()`
        '''
        assert not processor0.outq
        assert not processor1.inq
        q = queue.Queue(maxsize=self.options.queue_size)
        processor0.outq = q
        processor1.inq = q

    def build_postfetch_chain(self, inq):
        self._postfetch_chain = []

        self.dedup_db = Factory.dedup_db(self.options)

        if self.dedup_db:
            self._postfetch_chain.append(self.dedup_db.loader())

        self.warc_writer_processor = Factory.warc_writer_processor(self.options)
        self._postfetch_chain.append(self.warc_writer_processor)

        if self.dedup_db:
            self._postfetch_chain.append(self.dedup_db.storer())

        if self.stats_processor:
            self._postfetch_chain.append(self.stats_processor)

        if self.playback_proxy:
            self._postfetch_chain.append(
                    warcprox.ListenerPostfetchProcessor(
                        self.playback_proxy.playback_index_db, self.options))

        crawl_logger = Factory.crawl_logger(self.options)
        if crawl_logger:
            self._postfetch_chain.append(
                    warcprox.ListenerPostfetchProcessor(
                        crawl_logger, self.options))

        for qualname in self.options.plugins or []:
            plugin = Factory.plugin(qualname, self.options, self)
            if hasattr(plugin, 'notify'):
                self._postfetch_chain.append(
                        warcprox.ListenerPostfetchProcessor(
                            plugin, self.options))
            elif hasattr(plugin, 'CHAIN_POSITION') and plugin.CHAIN_POSITION == 'early':
                self._postfetch_chain.insert(0, plugin)
            else:
                self._postfetch_chain.append(plugin)

        self._postfetch_chain.append(
                warcprox.ListenerPostfetchProcessor(
                    self.proxy.running_stats, self.options))

        # chain them all up
        self._postfetch_chain[0].inq = inq
        for i in range(1, len(self._postfetch_chain)):
            self.chain(self._postfetch_chain[i-1], self._postfetch_chain[i])

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
                'id': 'warcprox:{}:{}'.format(
                    socket.gethostname(), self.proxy.server_port),
                'role': 'warcprox',
                'version': warcprox.__version__,
                'ttl': self.HEARTBEAT_INTERVAL * 3,
                'host': socket.gethostname(),
                'port': self.proxy.server_port,
            }
        status_info.update(self.proxy.status())
        self.status_info = self.service_registry.heartbeat(status_info)
        self.logger.trace('status in service registry: %s', self.status_info)

    def start(self):
        with self._start_stop_lock:
            if self.proxy_thread and self.proxy_thread.is_alive():
                self.logger.info('warcprox is already running')
                return

            self.proxy_thread = threading.Thread(
                    target=self.proxy.serve_forever, name='ProxyThread')
            self.proxy_thread.start()

            if self.playback_proxy:
                self.playback_proxy_thread = threading.Thread(
                    target=self.playback_proxy.serve_forever,
                    name='PlaybackProxyThread')
                self.playback_proxy_thread.start()

            for processor in self._postfetch_chain:
                processor.start()

    def shutdown(self):
        '''
        Shut down, aborting active connections, but allowing completed fetches
        to finish processing.

        1. stop accepting new connections
        2. shut down active connections to remote servers
        3. send "503 warcprox shutting down" response to active requests
        4. shut down the postfetch processors one by one, in order, letting
           them finish process their queues
        '''
        with self._start_stop_lock:
            if not self.proxy_thread or not self.proxy_thread.is_alive():
                self.logger.info('warcprox is not running')
                return

            self.proxy.shutdown()
            self.proxy.server_close()
            self.proxy_thread.join()

            if self.playback_proxy is not None:
                self.playback_proxy.shutdown()
                self.playback_proxy.server_close()
                if self.playback_proxy.playback_index_db is not None:
                    self.playback_proxy.playback_index_db.close()

            for processor in self._postfetch_chain:
                processor.stop.set()
                processor.join()

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
            try:
                self.shutdown()
            except:
                self.logger.critical("graceful shutdown failed", exc_info=True)
                self.logger.critical("killing myself -9")
                os.kill(os.getpid(), 9)

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

            # postfetch processors
            for processor in self._postfetch_chain:
                if not processor.profiler:
                    self.logger.notice('%s has no profiling data', processor)
                    continue
                file = os.path.join(tmpdir, '%s.dat' % processor.ident)
                processor.profiler.dump_stats(file)
                buf = io.StringIO()
                stats = pstats.Stats(file, stream=buf)
                stats.sort_stats('cumulative')
                stats.print_stats(0.1)
                self.logger.notice(
                        'performance profile of %s:\n%s', processor,
                        buf.getvalue())

                if hasattr(processor, 'thread_profilers'):
                    files = []
                    for th_id, profiler in processor.thread_profilers.items():
                        file = os.path.join(tmpdir, '%s.dat' % th_id)
                        profiler.dump_stats(file)
                        files.append(file)
                    buf = io.StringIO()
                    stats = pstats.Stats(*files, stream=buf)
                    stats.sort_stats('cumulative')
                    stats.print_stats(0.1)
                    self.logger.notice(
                            'aggregate performance profile of %s worker '
                            'threads of %s:\n%s',
                            len(files), processor, buf.getvalue())
