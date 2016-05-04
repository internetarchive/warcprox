# vim: set sw=4 et:

from __future__ import absolute_import

import logging
import threading
import signal
import time

import warcprox.warcprox
import warcprox.warcwriter

class WarcproxController(object):
    logger = logging.getLogger("warcprox.controller.WarcproxController")

    def __init__(self, proxy=None, warc_writer_thread=None, playback_proxy=None):
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


    def run_until_shutdown(self):
        """Start warcprox and run until shut down.

        If running in the main thread, SIGTERM initiates a graceful shutdown.
        Otherwise, call warcprox_controller.stop.set().
        """
        proxy_thread = threading.Thread(target=self.proxy.serve_forever, name='ProxyThread')
        proxy_thread.start()
        self.warc_writer_thread.start()

        if self.playback_proxy is not None:
            playback_proxy_thread = threading.Thread(target=self.playback_proxy.serve_forever, name='PlaybackProxyThread')
            playback_proxy_thread.start()

        self.stop = threading.Event()

        try:
            signal.signal(signal.SIGTERM, self.stop.set)
            self.logger.info('SIGTERM will initiate graceful shutdown')
        except ValueError:
            pass

        try:
            while not self.stop.is_set():
                time.sleep(0.5)
        except:
            pass
        finally:
            self.warc_writer_thread.stop.set()
            self.proxy.shutdown()
            self.proxy.server_close()

            if self.warc_writer_thread.warc_writer.dedup_db is not None:
                self.warc_writer_thread.warc_writer.dedup_db.close()

            if self.playback_proxy is not None:
                self.playback_proxy.shutdown()
                self.playback_proxy.server_close()
                if self.playback_proxy.playback_index_db is not None:
                    self.playback_proxy.playback_index_db.close()

            # wait for threads to finish
            self.warc_writer_thread.join()
            proxy_thread.join()
            if self.playback_proxy is not None:
                playback_proxy_thread.join()

