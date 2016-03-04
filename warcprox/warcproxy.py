#!/usr/bin/env python
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
import logging
import re
import tempfile
import traceback
import hashlib
import json
import socket
from hanzo import warctools
from certauth.certauth import CertificateAuthority
import warcprox
import datetime
import concurrent.futures
import resource

class ProxyingRecorder(object):
    """
    Wraps a socket._fileobject, recording the bytes as they are read,
    calculating digests, and sending them on to the proxy client.
    """

    logger = logging.getLogger("warcprox.warcproxy.ProxyingRecorder")

    def __init__(self, fp, proxy_dest, digest_algorithm='sha1', url=None):
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
        self.url = url

    def payload_starts_now(self):
        self.payload_digest = hashlib.new(self.digest_algorithm)
        self.payload_offset = self.len

    def _update_payload_digest(self, hunk):
        if self.payload_digest:
            self.payload_digest.update(hunk)

    def _update(self, hunk):
        self._update_payload_digest(hunk)
        self.block_digest.update(hunk)

        self.tempfile.write(hunk)

        if self.payload_digest and self._proxy_dest_conn_open:
            try:
                self.proxy_dest.sendall(hunk)
            except BaseException as e:
                self._proxy_dest_conn_open = False
                self.logger.warn('{} sending data to proxy client for url {}'.format(e, self.url))
                self.logger.info('will continue downloading from remote server without sending to client {}'.format(self.url))

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

    def flush(self):
        return self.fp.flush()

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

    def __init__(self, sock, debuglevel=0, method=None, proxy_dest=None, digest_algorithm='sha1', url=None):
        http_client.HTTPResponse.__init__(self, sock, debuglevel=debuglevel, method=method)
        self.proxy_dest = proxy_dest
        self.url = url

        # Keep around extra reference to self.fp because HTTPResponse sets
        # self.fp=None after it finishes reading, but we still need it
        self.recorder = ProxyingRecorder(self.fp, proxy_dest, digest_algorithm, url=url)
        self.fp = self.recorder

    def begin(self):
        http_client.HTTPResponse.begin(self)  # reads status line, headers

        status_and_headers = 'HTTP/1.1 {} {}\r\n'.format(self.status, self.reason)
        for k,v in self.msg.items():
            if k.lower() not in ('connection', 'proxy-connection', 'keep-alive',
                    'proxy-authenticate', 'proxy-authorization', 'upgrade'):
                status_and_headers += '{}: {}\r\n'.format(k, v)
        status_and_headers += 'Connection: close\r\n\r\n'
        self.proxy_dest.sendall(status_and_headers.encode('latin1'))

        self.recorder.payload_starts_now()


class WarcProxyHandler(warcprox.mitmproxy.MitmProxyHandler):
    # self.server is WarcProxy
    logger = logging.getLogger("warcprox.warcprox.WarcProxyHandler")

    def _enforce_limits(self, warcprox_meta):
        if warcprox_meta and "limits" in warcprox_meta:
            for item in warcprox_meta["limits"].items():
                key, limit = item
                bucket0, bucket1, bucket2 = key.rsplit(".", 2)
                value = self.server.stats_db.value(bucket0, bucket1, bucket2)
                self.logger.debug("warcprox_meta['limits']=%s stats['%s']=%s recorded_url_q.qsize()=%s", 
                        warcprox_meta['limits'], key, value, self.server.recorded_url_q.qsize())
                if value and value >= limit:
                    body = "request rejected by warcprox: reached limit {}={}\n".format(key, limit).encode("utf-8")
                    self.send_response(420, "Reached limit")
                    self.send_header("Content-Type", "text/plain;charset=utf-8")
                    self.send_header("Connection", "close")
                    self.send_header("Content-Length", len(body))
                    response_meta = {"reached-limit":{key:limit}, "stats":{bucket0:self.server.stats_db.value(bucket0)}}
                    self.send_header("Warcprox-Meta", json.dumps(response_meta, separators=(",",":")))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(body)
                    self.connection.close()
                    self.logger.info("%s 420 %s %s -- reached limit %s=%s", self.client_address[0], self.command, self.url, key, limit)
                    return True
        return False

    def _proxy_request(self):
        # Build request
        req_str = '{} {} {}\r\n'.format(self.command, self.path, self.request_version)

        warcprox_meta = None
        raw_warcprox_meta = self.headers.get('Warcprox-Meta')
        if raw_warcprox_meta:
            warcprox_meta = json.loads(raw_warcprox_meta)

        if self._enforce_limits(warcprox_meta):
            return

        # Swallow headers that don't make sense to forward on, i.e. most
        # hop-by-hop headers, see http://tools.ietf.org/html/rfc2616#section-13.5
        # self.headers is an email.message.Message, which is case-insensitive
        # and doesn't throw KeyError in __delitem__
        for key in ('Connection', 'Proxy-Connection', 'Keep-Alive',
                'Proxy-Authenticate', 'Proxy-Authorization', 'Upgrade',
                'Warcprox-Meta'):
            del self.headers[key]

        # Add headers to the request
        # XXX in at least python3.3 str(self.headers) uses \n not \r\n :(
        req_str += '\r\n'.join('{}: {}'.format(k,v) for (k,v) in self.headers.items())

        req = req_str.encode('latin1') + b'\r\n\r\n'

        # Append message body if present to the request
        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))

        prox_rec_res = None
        try:
            self.logger.debug('sending to remote server req=%s', repr(req))

            # warc-date "shall represent the instant that data capture for record creation began"
            timestamp = datetime.datetime.utcnow()

            # Send it down the pipe!
            self._proxy_sock.sendall(req)

            # We want HTTPResponse's smarts about http and handling of
            # non-compliant servers. But HTTPResponse.read() doesn't return the raw
            # bytes read from the server, it unchunks them if they're chunked, and
            # might do other stuff. We want to send the raw bytes back to the
            # client. So we ignore the values returned by prox_rec_res.read() below. Instead
            # the ProxyingRecordingHTTPResponse takes care of sending the raw bytes
            # to the proxy client.

            # Proxy and record the response
            prox_rec_res = ProxyingRecordingHTTPResponse(self._proxy_sock,
                    proxy_dest=self.connection,
                    digest_algorithm=self.server.digest_algorithm,
                    url=self.url)
            prox_rec_res.begin()

            remote_ip=self._proxy_sock.getpeername()[0]

            buf = prox_rec_res.read(8192)
            while buf != b'':
                buf = prox_rec_res.read(8192)

            recorded_url = RecordedUrl(url=self.url, request_data=req,
                    response_recorder=prox_rec_res.recorder,
                    remote_ip=remote_ip, warcprox_meta=warcprox_meta,
                    status=prox_rec_res.status, size=prox_rec_res.recorder.len,
                    client_ip=self.client_address[0],
                    content_type=prox_rec_res.getheader("Content-Type"),
                    method=self.command, timestamp=timestamp,
                    host=self.hostname, duration=datetime.datetime.utcnow()-timestamp)
            self.server.recorded_url_q.put(recorded_url)

            self.log_request(prox_rec_res.status, prox_rec_res.recorder.len)
        except socket.timeout as e:
            self.logger.warn("%s proxying %s %s", repr(e), self.command, self.url)
        except BaseException as e:
            self.logger.error("%s proxying %s %s", repr(e), self.command, self.url, exc_info=True)
        finally:
            # Let's close off the remote end
            if prox_rec_res:
                prox_rec_res.close()
            self._proxy_sock.close()

        return recorded_url

    # deprecated
    def do_PUTMETA(self):
        self.do_WARCPROX_WRITE_RECORD(warc_type=warctools.WarcRecord.METADATA)

    def do_WARCPROX_WRITE_RECORD(self, warc_type=None):
        try:
            self.url = self.path

            if ('Content-Length' in self.headers and 'Content-Type' in self.headers
                    and (warc_type or 'WARC-Type' in self.headers)):
                timestamp = datetime.datetime.utcnow()

                # stream this?
                request_data = self.rfile.read(int(self.headers['Content-Length']))

                warcprox_meta = None
                raw_warcprox_meta = self.headers.get('Warcprox-Meta')
                if raw_warcprox_meta:
                    warcprox_meta = json.loads(raw_warcprox_meta)

                rec_custom = RecordedUrl(url=self.url,
                                         request_data=request_data,
                                         response_recorder=None,
                                         remote_ip=b'',
                                         warcprox_meta=warcprox_meta,
                                         content_type=self.headers['Content-Type'],
                                         custom_type=warc_type or self.headers['WARC-Type'].encode('utf-8'),
                                         status=204, size=len(request_data),
                                         client_ip=self.client_address[0],
                                         method=self.command, timestamp=timestamp)

                self.server.recorded_url_q.put(rec_custom)
                self.send_response(204, 'OK')
            else:
                self.send_error(400, 'Bad request')

            self.end_headers()
        except:
            self.logger.error("uncaught exception in do_WARCPROX_WRITE_RECORD", exc_info=True)
            raise

    def log_message(self, fmt, *args):
        # logging better handled elsewhere?
        pass


class RecordedUrl:
    logger = logging.getLogger("warcprox.warcproxy.RecordedUrl")

    def __init__(self, url, request_data, response_recorder, remote_ip,
            warcprox_meta=None, content_type=None, custom_type=None,
            status=None, size=None, client_ip=None, method=None,
            timestamp=None, host=None, duration=None):
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

        if warcprox_meta:
            self.warcprox_meta = warcprox_meta
        else:
            self.warcprox_meta = {}

        self.content_type = content_type

        self.mimetype = content_type
        if self.mimetype:
            n = self.mimetype.find(";")
            if n >= 0:
                self.mimetype = self.mimetype[:n]

        self.custom_type = custom_type
        self.status = status
        self.size = size
        self.client_ip = client_ip
        self.method = method
        self.timestamp = timestamp
        self.host = host
        self.duration = duration


class SingleThreadedWarcProxy(http_server.HTTPServer):
    logger = logging.getLogger("warcprox.warcproxy.WarcProxy")

    def __init__(self, ca=None, recorded_url_q=None, stats_db=None, options=warcprox.Options()):
        server_address = (options.address or 'localhost', options.port if options.port is not None else 8000)

        if options.onion_tor_socks_proxy:
            try:
                host, port = options.onion_tor_socks_proxy.split(':')
                WarcProxyHandler.onion_tor_socks_proxy_host = host
                WarcProxyHandler.onion_tor_socks_proxy_port = int(port)
            except ValueError:
                WarcProxyHandler.onion_tor_socks_proxy_host = options.onion_tor_socks_proxy
                WarcProxyHandler.onion_tor_socks_proxy_port = None

        http_server.HTTPServer.__init__(self, server_address, WarcProxyHandler, bind_and_activate=True)

        self.digest_algorithm = options.digest_algorithm or 'sha1'

        if ca is not None:
            self.ca = ca
        else:
            ca_name = 'Warcprox CA on {}'.format(socket.gethostname())[:64]
            self.ca = CertificateAuthority(ca_file='warcprox-ca.pem',
                                           certs_dir='./warcprox-ca',
                                           ca_name=ca_name)

        if recorded_url_q is not None:
            self.recorded_url_q = recorded_url_q
        else:
            self.recorded_url_q = queue.Queue(maxsize=options.queue_size or 1000)

        self.stats_db = stats_db

        self.options = options

    def server_activate(self):
        http_server.HTTPServer.server_activate(self)
        self.logger.info('WarcProxy listening on {0}:{1}'.format(self.server_address[0], self.server_address[1]))

    def server_close(self):
        self.logger.info('WarcProxy shutting down')
        http_server.HTTPServer.server_close(self)

    def handle_error(self, request, client_address):
        self.logger.warn("exception processing request %s from %s", request, client_address, exc_info=True)

class PooledMixIn(socketserver.ThreadingMixIn):
    def process_request(self, request, client_address):
        self.pool.submit(self.process_request_thread, request, client_address)

class WarcProxy(PooledMixIn, SingleThreadedWarcProxy):
    logger = logging.getLogger("warcprox.warcproxy.WarcProxy")

    def __init__(self, *args, **kwargs):
        SingleThreadedWarcProxy.__init__(self, *args, **kwargs)
        if self.options.max_threads:
            max_threads = self.options.max_threads
            self.logger.info("max_threads=%s set by command line option",
                             max_threads)
        else:
            # man getrlimit: "RLIMIT_NPROC The maximum number of processes (or,
            # more precisely on Linux, threads) that can be created for the
            # real user ID of the calling process."
            rlimit_nproc = resource.getrlimit(resource.RLIMIT_NPROC)[0]
            rlimit_nofile = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            max_threads = min(rlimit_nofile // 10, rlimit_nproc // 2)
            self.logger.info("max_threads=%s (rlimit_nproc=%s, rlimit_nofile=%s)",
                             max_threads, rlimit_nproc, rlimit_nofile)

        self.pool = concurrent.futures.ThreadPoolExecutor(max_threads)
