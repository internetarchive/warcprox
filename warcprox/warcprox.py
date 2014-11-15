#!/usr/bin/env python
# vim:set sw=4 et:
#
"""
WARC writing MITM HTTP/S proxy

See README.rst or https://github.com/internetarchive/warcprox
"""

from __future__ import absolute_import

try:
    import http.server as http_server
except ImportError:
    import BaseHTTPServer as http_server

try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

try:
    import queue
except ImportError:
    import Queue as queue

try:
    import http.client as http_client
except ImportError:
    import httplib as http_client

import socket
import logging
import sys
import hashlib
import threading
import os
import argparse
import re
import signal
import time
import tempfile
import json
import traceback

import warcprox.certauth
import warcprox.mitmproxy
import warcprox.playback
import warcprox.dedup
import warcprox.warcwriter


class ProxyingRecorder(object):
    """
    Wraps a socket._fileobject, recording the bytes as they are read,
    calculating digests, and sending them on to the proxy client.
    """

    logger = logging.getLogger(__module__ + "." + __qualname__)

    def __init__(self, fp, proxy_dest, digest_algorithm='sha1'):
        self.fp = fp
        # "The file has no name, and will cease to exist when it is closed."
        self.tempfile = tempfile.SpooledTemporaryFile(max_size=512*1024)
        self.digest_algorithm = digest_algorithm
        self.block_digest = hashlib.new(digest_algorithm)
        self.payload_offset = None
        self.payload_digest = None
        self.proxy_dest = proxy_dest
        self._proxy_dest_conn_open = True
        self._prev_hunk_last_two_bytes = b''
        self.len = 0

    def _update(self, hunk):
        if self.payload_digest is None:
            # convoluted handling of two newlines crossing hunks
            # XXX write tests for this
            if self._prev_hunk_last_two_bytes.endswith(b'\n'):
                if hunk.startswith(b'\n'):
                    self.payload_digest = hashlib.new(self.digest_algorithm)
                    self.payload_digest.update(hunk[1:])
                    self.payload_offset = self.len + 1
                elif hunk.startswith(b'\r\n'):
                    self.payload_digest = hashlib.new(self.digest_algorithm)
                    self.payload_digest.update(hunk[2:])
                    self.payload_offset = self.len + 2
            elif self._prev_hunk_last_two_bytes == b'\n\r':
                if hunk.startswith(b'\n'):
                    self.payload_digest = hashlib.new(self.digest_algorithm)
                    self.payload_digest.update(hunk[1:])
                    self.payload_offset = self.len + 1
            else:
                m = re.search(br'\n\r?\n', hunk)
                if m is not None:
                    self.payload_digest = hashlib.new(self.digest_algorithm)
                    self.payload_digest.update(hunk[m.end():])
                    self.payload_offset = self.len + m.end()

            # if we still haven't found start of payload hold on to these bytes
            if self.payload_digest is None:
                self._prev_hunk_last_two_bytes = hunk[-2:]
        else:
            self.payload_digest.update(hunk)

        self.block_digest.update(hunk)

        self.tempfile.write(hunk)

        if self._proxy_dest_conn_open:
            try:
                self.proxy_dest.sendall(hunk)
            except BaseException as e:
                self._proxy_dest_conn_open = False
                self.logger.warn('{} sending data to proxy client'.format(e))
                self.logger.info('will continue downloading from remote server without sending to client')

        self.len += len(hunk)


    def read(self, size=-1):
        hunk = self.fp.read(size)
        self._update(hunk)
        return hunk

    def readinto(self, b):
        n = self.fp.readinto(b)
        self._update(b[:n])
        return n

    def readline(self, size=-1):
        # XXX depends on implementation details of self.fp.readline(), in
        # particular that it doesn't call self.fp.read()
        hunk = self.fp.readline(size)
        self._update(hunk)
        return hunk

    def close(self):
        return self.fp.close()

    def __len__(self):
        return self.len

    def payload_size(self):
        if self.payload_offset is not None:
            return self.len - self.payload_offset
        else:
            return 0


class ProxyingRecordingHTTPResponse(http_client.HTTPResponse):

    def __init__(self, sock, debuglevel=0, method=None, proxy_dest=None, digest_algorithm='sha1'):
        http_client.HTTPResponse.__init__(self, sock, debuglevel=debuglevel, method=method)

        # Keep around extra reference to self.fp because HTTPResponse sets
        # self.fp=None after it finishes reading, but we still need it
        self.recorder = ProxyingRecorder(self.fp, proxy_dest, digest_algorithm)
        self.fp = self.recorder


class WarcProxyHandler(warcprox.mitmproxy.MitmProxyHandler):
    logger = logging.getLogger(__module__ + "." + __qualname__)

    def _proxy_request(self):
        # Build request
        req_str = '{} {} {}\r\n'.format(self.command, self.path, self.request_version)

        # Add headers to the request
        # XXX in at least python3.3 str(self.headers) uses \n not \r\n :(
        req_str += '\r\n'.join('{}: {}'.format(k,v) for (k,v) in self.headers.items())

        req = req_str.encode('utf-8') + b'\r\n\r\n'

        # Append message body if present to the request
        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))

        self.logger.debug('req={}'.format(repr(req)))

        # Send it down the pipe!
        self._proxy_sock.sendall(req)

        # We want HTTPResponse's smarts about http and handling of
        # non-compliant servers. But HTTPResponse.read() doesn't return the raw
        # bytes read from the server, it unchunks them if they're chunked, and
        # might do other stuff. We want to send the raw bytes back to the
        # client. So we ignore the values returned by h.read() below. Instead
        # the ProxyingRecordingHTTPResponse takes care of sending the raw bytes
        # to the proxy client.

        # Proxy and record the response
        h = ProxyingRecordingHTTPResponse(self._proxy_sock,
                proxy_dest=self.connection,
                digest_algorithm=self.server.digest_algorithm)
        h.begin()

        buf = h.read(8192)
        while buf != b'':
            buf = h.read(8192)

        self.log_request(h.status, h.recorder.len)

        remote_ip = self._proxy_sock.getpeername()[0]

        # Let's close off the remote end
        h.close()
        self._proxy_sock.close()

        recorded_url = RecordedUrl(url=self.url, request_data=req,
                response_recorder=h.recorder, remote_ip=remote_ip)
        self.server.recorded_url_q.put(recorded_url)


class RecordedUrl(object):
    def __init__(self, url, request_data, response_recorder, remote_ip):
        # XXX should test what happens with non-ascii url (when does
        # url-encoding happen?)
        if type(url) is not bytes:
            self.url = url.encode('ascii')
        else:
            self.url = url

        if type(remote_ip) is not bytes:
            self.remote_ip = remote_ip.encode('ascii')
        else:
            self.remote_ip = remote_ip

        self.request_data = request_data
        self.response_recorder = response_recorder


class WarcProxy(socketserver.ThreadingMixIn, http_server.HTTPServer):
    logger = logging.getLogger(__module__ + "." + __qualname__)

    def __init__(self, server_address=('localhost', 8000),
            req_handler_class=WarcProxyHandler, bind_and_activate=True,
            ca=None, recorded_url_q=None, digest_algorithm='sha1'):
        http_server.HTTPServer.__init__(self, server_address, req_handler_class, bind_and_activate)

        self.digest_algorithm = digest_algorithm

        if ca is not None:
            self.ca = ca
        else:
            self.ca = warcprox.certauth.CertificateAuthority()

        if recorded_url_q is not None:
            self.recorded_url_q = recorded_url_q
        else:
            self.recorded_url_q = queue.Queue()

    def server_activate(self):
        http_server.HTTPServer.server_activate(self)
        self.logger.info('WarcProxy listening on {0}:{1}'.format(self.server_address[0], self.server_address[1]))

    def server_close(self):
        self.logger.info('WarcProxy shutting down')
        http_server.HTTPServer.server_close(self)


class WarcproxController(object):
    logger = logging.getLogger(__module__ + "." + __qualname__)

    def __init__(self, proxy=None, warc_writer_thread=None, playback_proxy=None):
        """
        Create warcprox controller.

        If supplied, proxy should be an instance of WarcProxy, and
        warc_writer_thread should be an instance of WarcWriterThread. If not
        supplied, they are created with default values.

        If supplied, playback_proxy should be an instance of PlaybackProxy. If not
        supplied, no playback proxy will run.
        """
        if proxy is not None:
            self.proxy = proxy
        else:
            self.proxy = WarcProxy()

        if warc_writer_thread is not None:
            self.warc_writer_thread = warc_writer_thread
        else:
            self.warc_writer_thread = WarcWriterThread(recorded_url_q=self.proxy.recorded_url_q)

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


def _build_arg_parser(prog=os.path.basename(sys.argv[0])):
    arg_parser = argparse.ArgumentParser(prog=prog,
            description='warcprox - WARC writing MITM HTTP/S proxy',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('-p', '--port', dest='port', default='8000',
            help='port to listen on')
    arg_parser.add_argument('-b', '--address', dest='address',
            default='localhost', help='address to listen on')
    arg_parser.add_argument('-c', '--cacert', dest='cacert',
            default='./{0}-warcprox-ca.pem'.format(socket.gethostname()),
            help='CA certificate file; if file does not exist, it will be created')
    arg_parser.add_argument('--certs-dir', dest='certs_dir',
            default='./{0}-warcprox-ca'.format(socket.gethostname()),
            help='where to store and load generated certificates')
    arg_parser.add_argument('-d', '--dir', dest='directory',
            default='./warcs', help='where to write warcs')
    arg_parser.add_argument('-z', '--gzip', dest='gzip', action='store_true',
            help='write gzip-compressed warc records')
    arg_parser.add_argument('-n', '--prefix', dest='prefix',
            default='WARCPROX', help='WARC filename prefix')
    arg_parser.add_argument('-s', '--size', dest='size',
            default=1000*1000*1000,
            help='WARC file rollover size threshold in bytes')
    arg_parser.add_argument('--rollover-idle-time',
            dest='rollover_idle_time', default=None,
            help="WARC file rollover idle time threshold in seconds (so that Friday's last open WARC doesn't sit there all weekend waiting for more data)")
    try:
        hash_algos = hashlib.algorithms_guaranteed
    except AttributeError:
        hash_algos = hashlib.algorithms
    arg_parser.add_argument('-g', '--digest-algorithm', dest='digest_algorithm',
            default='sha1', help='digest algorithm, one of {}'.format(', '.join(hash_algos)))
    arg_parser.add_argument('--base32', dest='base32', action='store_true',
            default=False, help='write digests in Base32 instead of hex')
    arg_parser.add_argument('-j', '--dedup-db-file', dest='dedup_db_file',
            default='./warcprox-dedup.db', help='persistent deduplication database file; empty string or /dev/null disables deduplication')
    arg_parser.add_argument('-P', '--playback-port', dest='playback_port',
            default=None, help='port to listen on for instant playback')
    arg_parser.add_argument('--playback-index-db-file', dest='playback_index_db_file',
            default='./warcprox-playback-index.db',
            help='playback index database file (only used if --playback-port is specified)')
    arg_parser.add_argument('--version', action='version',
            version="warcprox {}".format(warcprox.version_str))
    arg_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true')
    arg_parser.add_argument('-q', '--quiet', dest='quiet', action='store_true')
    # [--ispartof=warcinfo ispartof]
    # [--description=warcinfo description]
    # [--operator=warcinfo operator]
    # [--httpheader=warcinfo httpheader]

    return arg_parser


def main(argv=sys.argv):
    arg_parser = _build_arg_parser(prog=os.path.basename(argv[0]))
    args = arg_parser.parse_args(args=argv[1:])

    if args.verbose:
        loglevel = logging.DEBUG
    elif args.quiet:
        loglevel = logging.WARNING
    else:
        loglevel = logging.INFO

    logging.basicConfig(stream=sys.stdout, level=loglevel,
            format='%(asctime)s %(process)d %(levelname)s %(threadName)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')

    try:
        hashlib.new(args.digest_algorithm)
    except Exception as e:
        logging.fatal(e)
        exit(1)

    if args.dedup_db_file in (None, '', '/dev/null'):
        logging.info('deduplication disabled')
        dedup_db = None
    else:
        dedup_db = warcprox.dedup.DedupDb(args.dedup_db_file)

    recorded_url_q = queue.Queue()

    ca = warcprox.certauth.CertificateAuthority(args.cacert, args.certs_dir)

    proxy = WarcProxy(server_address=(args.address, int(args.port)),
            ca=ca, recorded_url_q=recorded_url_q,
            digest_algorithm=args.digest_algorithm)

    if args.playback_port is not None:
        playback_index_db = warcprox.playback.PlaybackIndexDb(args.playback_index_db_file)
        playback_server_address=(args.address, int(args.playback_port))
        playback_proxy = warcprox.playback.PlaybackProxy(server_address=playback_server_address,
                ca=ca, playback_index_db=playback_index_db,
                warcs_dir=args.directory)
    else:
        playback_index_db = None
        playback_proxy = None

    warc_writer = warcprox.warcwriter.WarcWriter(directory=args.directory,
            gzip=args.gzip, prefix=args.prefix, port=int(args.port),
            rollover_size=int(args.size), base32=args.base32,
            dedup_db=dedup_db, digest_algorithm=args.digest_algorithm,
            playback_index_db=playback_index_db)
    warc_writer_thread = warcprox.warcwriter.WarcWriterThread(
            recorded_url_q=recorded_url_q, warc_writer=warc_writer,
            rollover_idle_time=int(args.rollover_idle_time) if args.rollover_idle_time is not None else None)

    controller = WarcproxController(proxy, warc_writer_thread, playback_proxy)
    controller.run_until_shutdown()


if __name__ == '__main__':
    main()

