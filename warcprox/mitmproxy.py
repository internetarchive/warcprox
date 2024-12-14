'''
warcprox/mitmproxy.py - man-in-the-middle http/s proxy code, handles http
CONNECT method by creating a snakeoil certificate for the requested site,
calling ssl.wrap_socket() on the client connection; connects to remote
(proxied) host, possibly using tor if host tld is .onion and tor proxy is
configured

Copyright (C) 2012 Cygnos Corporation
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
import http.server as http_server
import urllib.parse as urllib_parse
# In python2/3, urllib parse caches in memory URL parsing results to avoid
# repeating the process for the same URL. The problem is that the default
# in memory cache size is just 20.
# https://github.com/python/cpython/blob/3.7/Lib/urllib/parse.py#L80
# since we do a lot of URL parsing, it makes sense to increase cache size.
urllib_parse.MAX_CACHE_SIZE = 2000

import http.client as http_client
# In python3 http.client.parse_headers() enforces http_client._MAXLINE
# as max length of an http header line, but we want to support very
# long warcprox-meta headers, so we tweak it here. Python2 doesn't seem
# to enforce any limit. Multiline headers could be an option but it
# turns out those are illegal as of RFC 7230. Plus, this is easier.
http_client._MAXLINE = 4194304  # 4 MiB
# http_client has an arbitrary limit of 100 HTTP Headers which is too low and
# it raises an HTTPException if the target URL has more.
# https://github.com/python/cpython/blob/3.7/Lib/http/client.py#L113
http_client._MAXHEADERS = 7000

import socket
import logging
import ssl
import warcprox
import threading
import datetime
import random
import socks
import tempfile
import hashlib
import socketserver
import concurrent.futures
import urlcanon
import time
import collections
import cProfile
from urllib3 import PoolManager
from urllib3.util import is_connection_dropped
from urllib3.exceptions import TimeoutError, HTTPError, NewConnectionError
import doublethink
from cachetools import TTLCache
from threading import RLock

from .certauth import CertificateAuthority

class ProxyingRecorder:
    """
    Wraps a socket._fileobject, recording the bytes as they are read,
    calculating the block digest, and sending them on to the proxy client.
    """

    logger = logging.getLogger("warcprox.mitmproxy.ProxyingRecorder")

    def __init__(self, fp, proxy_client, digest_algorithm='sha1', url=None,
                 tmp_file_max_memory_size=524288):
        self.fp = fp
        # "The file has no name, and will cease to exist when it is closed."
        self.tempfile = tempfile.SpooledTemporaryFile(max_size=tmp_file_max_memory_size)
        self.digest_algorithm = digest_algorithm
        self.block_digest = hashlib.new(digest_algorithm)
        self.payload_offset = None
        self.proxy_client = proxy_client
        self._proxy_client_conn_open = bool(self.proxy_client)
        self.len = 0
        self.url = url

    def payload_starts_now(self):
        self.payload_offset = self.len

    def _update(self, hunk):
        self.block_digest.update(hunk)
        self.tempfile.write(hunk)

        if self.payload_offset is not None and self._proxy_client_conn_open:
            try:
                self.proxy_client.sendall(hunk)
            except BaseException as e:
                self._proxy_client_conn_open = False
                self.logger.warning(
                        '%s sending data to proxy client for url %s',
                        e, self.url)
                self.logger.info(
                        'will continue downloading from remote server without '
                        'sending to client %s', self.url)

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
    '''
    Implementation of HTTPResponse that uses a ProxyingRecorder to read the
    response from the remote web server and send it on to the proxy client,
    while recording the bytes in transit.
    '''
    def __init__(
            self, sock, debuglevel=0, method=None, proxy_client=None,
            digest_algorithm='sha1', url=None, tmp_file_max_memory_size=None):
        http_client.HTTPResponse.__init__(
                self, sock, debuglevel=debuglevel, method=method)
        self.proxy_client = proxy_client
        self.url = url
        self.digest_algorithm = digest_algorithm

        # Keep around extra reference to self.fp because HTTPResponse sets
        # self.fp=None after it finishes reading, but we still need it
        self.recorder = ProxyingRecorder(
                self.fp, proxy_client, digest_algorithm, url=url,
                tmp_file_max_memory_size=tmp_file_max_memory_size)
        self.fp = self.recorder

        self.payload_digest = None
        self.truncated = None

    def begin(self, extra_response_headers={}):
        http_client.HTTPResponse.begin(self)  # reads status line, headers

        status_and_headers = 'HTTP/1.1 {} {}\r\n'.format(
                self.status, self.reason)
        self.msg['Via'] = via_header_value(
                self.msg.get('Via'), '%0.1f' % (self.version / 10.0))
        if extra_response_headers:
            for header, value in extra_response_headers.items():
                self.msg[header] = value

        for k,v in self.msg.items():
            if k.lower() not in (
                    'connection', 'proxy-connection', 'keep-alive',
                    'proxy-authenticate', 'proxy-authorization', 'upgrade',
                    'strict-transport-security'):
                status_and_headers += '{}: {}\r\n'.format(k, v)
        status_and_headers += 'Connection: close\r\n\r\n'
        self.proxy_client.sendall(status_and_headers.encode('latin1'))

        self.recorder.payload_starts_now()
        self.payload_digest = hashlib.new(self.digest_algorithm)

    def read(self, amt=None):
        buf = http_client.HTTPResponse.read(self, amt)
        self.payload_digest.update(buf)
        return buf

def via_header_value(orig, request_version):
    via = orig
    if via:
        via += ', '
    else:
        via = ''
    via = via + '{} {}'.format(request_version, 'warcprox')
    return via


# Ref and detailed description about cipher selection at
# https://github.com/urllib3/urllib3/blob/f070ec2e6f6c545f40d9196e5246df10c72e48e1/src/urllib3/util/ssl_.py#L170 
SSL_CIPHERS = [
    "ECDHE+AESGCM",
    "ECDHE+CHACHA20",
    "DH+AESGCM",
    "ECDH+AES",
    "DH+AES",
    "RSA+AESGCM",
    "RSA+AES",
    "!aNULL",
    "!eNULL",
    "!MD5",
    "!DSS",
    "!AESCCM",
    "DHE+AESGCM",
    "DHE+CHACHA20",
    "ECDH+AESGCM",
    ]


class MitmProxyHandler(http_server.BaseHTTPRequestHandler):
    '''
    An http proxy implementation of BaseHTTPRequestHandler, that acts as a
    man-in-the-middle in order to peek at the content of https transactions,
    and records the bytes in transit as it proxies them.
    '''
    logger = logging.getLogger("warcprox.mitmproxy.MitmProxyHandler")

    _socket_timeout = 60
    _max_resource_size = None
    _tmp_file_max_memory_size = 512 * 1024
    onion_tor_socks_proxy_host = None
    onion_tor_socks_proxy_port = None
    socks_proxy_host = None
    socks_proxy_port = None
    socks_proxy_username = None
    socks_proxy_password = None

    def __init__(self, request, client_address, server):
        threading.current_thread().name = 'MitmProxyHandler(tid={},started={},client={}:{})'.format(warcprox.gettid(), datetime.datetime.utcnow().isoformat(), client_address[0], client_address[1])
        self.is_connect = False
        self._headers_buffer = []
        request.settimeout(self._socket_timeout)
        http_server.BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _determine_host_port(self):
        # Get hostname and port to connect to
        if self.is_connect:
            host, self.port = self.path.split(':')
        else:
            self.url = self.path
            u = urllib_parse.urlparse(self.url)
            if u.scheme != 'http' or u.netloc == '':
                raise Exception(
                        'unable to parse request %r as a proxy request' % (
                            self.requestline))
            host = u.hostname
            self.port = u.port or 80
            self.path = urllib_parse.urlunparse(
                urllib_parse.ParseResult(
                    scheme='', netloc='', params=u.params, path=u.path or '/',
                    query=u.query, fragment=u.fragment))
        self.hostname = urlcanon.normalize_host(host).decode('ascii')

    def _hostname_port_cache_key(self):
        return '{}:{}'.format(self.hostname, self.port)

    def _connect_to_remote_server(self):
        '''
        Connect to destination.
        Note that connection_from_host has hard-coded `scheme='http'`
        to avoid internal urllib3 logic when scheme is https. We handle ssl and
        socks inside the current method.
        self._conn_pool._get_conn() will either return an existing connection
        or a new one. If its new, it needs initialization.
        '''
        self._conn_pool = self.server.remote_connection_pool.connection_from_host(
            host=self.hostname, port=int(self.port), scheme='http',
            pool_kwargs={'maxsize': 12, 'timeout': self._socket_timeout})

        remote_ip = None

        self._remote_server_conn = self._conn_pool._get_conn()
        if is_connection_dropped(self._remote_server_conn):
            if self.onion_tor_socks_proxy_host and self.hostname.endswith('.onion'):
                self.logger.info(
                        "using tor socks proxy at %s:%s to connect to %s",
                        self.onion_tor_socks_proxy_host,
                        self.onion_tor_socks_proxy_port or 1080, self.hostname)
                self._remote_server_conn.sock = socks.socksocket()
                self._remote_server_conn.sock.set_proxy(
                        socks.SOCKS5, addr=self.onion_tor_socks_proxy_host,
                        port=self.onion_tor_socks_proxy_port, rdns=True)
                self._remote_server_conn.sock.settimeout(self._socket_timeout)
                self._remote_server_conn.sock.connect((self.hostname, int(self.port)))
            elif self.socks_proxy_host and self.socks_proxy_port:
                self.logger.info(
                        "using socks proxy at %s:%s to connect to %s",
                        self.socks_proxy_host, self.socks_proxy_port, self.hostname)
                self._remote_server_conn.sock = socks.socksocket()
                self._remote_server_conn.sock.set_proxy(
                        socks.SOCKS5, addr=self.socks_proxy_host,
                        port=self.socks_proxy_port, rdns=True,
                        username=self.socks_proxy_username,
                        password=self.socks_proxy_password)
                self._remote_server_conn.sock.settimeout(self._socket_timeout)
                self._remote_server_conn.sock.connect((self.hostname, int(self.port)))
            else:
                self._remote_server_conn.connect()
                remote_ip = self._remote_server_conn.sock.getpeername()[0]

            # Wrap socket if SSL is required
            if self.is_connect:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    # randomize TLS fingerprint to evade anti-web-bot systems
                    random.shuffle(SSL_CIPHERS)
                    context.set_ciphers(":".join(SSL_CIPHERS))
                    self._remote_server_conn.sock = context.wrap_socket(
                            self._remote_server_conn.sock,
                            server_hostname=self.hostname)
                except AttributeError:
                    try:
                        self._remote_server_conn.sock = ssl.wrap_socket(
                                self._remote_server_conn.sock)
                    except ssl.SSLError:
                        self.logger.warning(
                                "failed to establish ssl connection to %s; "
                                "python ssl library does not support SNI, "
                                "consider upgrading to python 2.7.9+ or 3.4+",
                                self.hostname)
                    raise
                except ssl.SSLError as e:
                    self.logger.error(
                            'error connecting to %s (%s) port %s: %s',
                            self.hostname, remote_ip, self.port, e)
                    raise
        return self._remote_server_conn.sock

    def _transition_to_ssl(self):
        certfile = self.server.ca.get_wildcard_cert(self.hostname)
        self.request = self.connection = ssl.wrap_socket(
                self.connection, server_side=True, certfile=certfile)
        # logging.info('self.hostname=%s certfile=%s', self.hostname, certfile)

    def do_CONNECT(self):
        '''
        Handles a http CONNECT request.

        The CONNECT method is meant to "convert the request connection to a
        transparent TCP/IP tunnel, usually to facilitate SSL-encrypted
        communication (HTTPS) through an unencrypted HTTP proxy" (Wikipedia).

        do_CONNECT is where the man-in-the-middle logic happens. In do_CONNECT
        the proxy transitions the proxy client connection to ssl while
        masquerading as the remote web server using a generated certificate.
        Meanwhile makes its own separate ssl connection to the remote web
        server. Then it calls self.handle_one_request() again to handle the
        request intended for the remote server.
        '''
        self.logger.trace(
                'request from %s:%s: %s', self.client_address[0],
                self.client_address[1], self.requestline)
        self.is_connect = True
        try:
            self._determine_host_port()

            # If successful, let's do this!
            self.send_response(200, 'Connection established')
            self.end_headers()
            self._transition_to_ssl()
        except Exception as e:
            try:
                self.logger.error(
                        "problem handling %r: %r", self.requestline, e)
                if type(e) is socket.timeout:
                    self.send_error(504, str(e), exception=e)
                else:
                    self.send_error(500, str(e))
            except Exception as f:
                self.logger.warning("failed to send error response ({}) to proxy client: {}".format(e, f))
            return

        # Reload!
        self.setup()
        self.handle_one_request()

    def _construct_tunneled_url(self):
        if int(self.port) == 443:
            netloc = self.hostname
        else:
            netloc = '{}:{}'.format(self.hostname, self.port)

        result = urllib_parse.urlunparse(
            urllib_parse.ParseResult(
                scheme='https',
                netloc=netloc,
                params='',
                path=self.path,
                query='',
                fragment=''
            )
        )

        return result

    def do_COMMAND(self):
        self.logger.trace(
                'request from %s:%s: %r', self.client_address[0],
                self.client_address[1], self.requestline)
        try:
            if self.is_connect:
                self.url = self._construct_tunneled_url()
            else:
                self._determine_host_port()
                assert self.url
            # Check if target hostname:port is in `bad_hostnames_ports` cache
            # to avoid retrying to connect. Cached value is http status code.
            cached = None
            hostname_port = self._hostname_port_cache_key()
            with self.server.bad_hostnames_ports_lock:
                cached = self.server.bad_hostnames_ports.get(hostname_port)
            if cached:
                self.logger.info('Cannot connect to %s (cache)', hostname_port)
                self.send_error(cached, exception=Exception('Cached Failed Connection'))
                return
            # Connect to destination
            self._connect_to_remote_server()
        except warcprox.RequestBlockedByRule as e:
            # limit enforcers have already sent the appropriate response
            self.logger.info("%r: %r", self.requestline, e)
            return
        except warcprox.BadRequest as e:
            self.send_error(400, e.msg)
            return
        except Exception as e:
            # If connection fails, add hostname:port to cache to avoid slow
            # subsequent reconnection attempts. `NewConnectionError` can be
            # caused by many types of errors which are handled by urllib3.
            response_code = 500
            cache = False
            if isinstance(e, (socket.timeout, TimeoutError,)):
                response_code = 504
                cache = True
            elif isinstance(e, HTTPError):
                response_code = 502
                cache = True

            if cache:
                host_port = self._hostname_port_cache_key()
                with self.server.bad_hostnames_ports_lock:
                    self.server.bad_hostnames_ports[host_port] = response_code
                self.logger.info('bad_hostnames_ports cache size: %d',
                                 len(self.server.bad_hostnames_ports))
            self.logger.error(
                    "problem processing request %r: %r",
                    self.requestline, e, exc_info=True)
            self.send_error(response_code, exception=e)
            return

        try:
            return self._proxy_request()
        except Exception as e:
            if self.server.shutting_down:
                self.logger.warning(
                        'sending 503 warcprox shutting down %r: %r',
                        self.requestline, e)
                self.send_error(503, 'warcprox shutting down')
            else:
                self.logger.error(
                        'error from remote server(?) %r: %r',
                        self.requestline, e, exc_info=True)
                self.send_error(502)
            return

    def send_error(self, code, message=None, explain=None, exception=None):
        # BaseHTTPRequestHandler.send_response_only() in http/server.py
        # does this:
        #     if not hasattr(self, '_headers_buffer'):
        #         self._headers_buffer = []
        # but we sometimes see self._headers_buffer == None
        # (This happened before! see commit dc9fdc34125dd2357)
        # Workaround:
        if hasattr(self, '_headers_buffer') and not self._headers_buffer:
            self._headers_buffer = []
        try:
            return http_server.BaseHTTPRequestHandler.send_error(
                    self, code, message, explain)
        except Exception as e:
            level = logging.ERROR
            if isinstance(e, OSError) and e.errno == 9:
                level = logging.TRACE
            self.logger.log(
                    level, 'send_error(%r, %r, %r) raised exception',
                    exc_info=True)
            return None

    def _proxy_request(self, extra_response_headers={}):
        try:
            self.server.register_remote_server_sock(
                    self._remote_server_conn.sock)
            return self._inner_proxy_request(extra_response_headers)
        finally:
            self.server.unregister_remote_server_sock(
                    self._remote_server_conn.sock)

    def _swallow_hop_by_hop_headers(self):
        '''
        Swallow headers that don't make sense to forward on, i.e.
        most hop-by-hop headers.

        http://tools.ietf.org/html/rfc2616#section-13.5.
        '''
        # self.headers is an email.message.Message, which is case-insensitive
        # and doesn't throw KeyError in __delitem__
        for key in (
                'Warcprox-Meta', 'Connection', 'Proxy-Connection', 'Keep-Alive',
                'Proxy-Authenticate', 'Proxy-Authorization', 'Upgrade'):
            del self.headers[key]

    def _build_request(self):
        req_str = '{} {} {}\r\n'.format(
            self.command, self.path, self.request_version)

        # Add headers to the request
        # XXX in at least python3.3 str(self.headers) uses \n not \r\n :(
        req_str += '\r\n'.join(
            '{}: {}'.format(k,v) for (k,v) in self.headers.items())

        req = req_str.encode('latin1') + b'\r\n\r\n'

        return req

    def _inner_proxy_request(self, extra_response_headers={}):
        '''
        Sends the request to the remote server, then uses a ProxyingRecorder to
        read the response and send it to the proxy client, while recording the
        bytes in transit. Returns a tuple (request, response) where request is
        the raw request bytes, and response is a ProxyingRecorder.

        :param extra_response_headers: generated on warcprox._proxy_request.
        It may contain extra HTTP headers such as ``Warcprox-Meta`` which
        are written in the WARC record for this request.
        '''
        self._swallow_hop_by_hop_headers()
        self.headers['Via'] = via_header_value(
                self.headers.get('Via'),
                self.request_version.replace('HTTP/', ''))
        req = self._build_request()

        # Append message body if present to the request
        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))

        prox_rec_res = None
        start = time.time()
        try:
            self.logger.debug('sending to remote server req=%r', req)

            # Send it down the pipe!
            self._remote_server_conn.sock.sendall(req)

            prox_rec_res = ProxyingRecordingHTTPResponse(
                    self._remote_server_conn.sock, proxy_client=self.connection,
                    digest_algorithm=self.server.digest_algorithm,
                    url=self.url, method=self.command,
                    tmp_file_max_memory_size=self._tmp_file_max_memory_size)
            prox_rec_res.begin(extra_response_headers=extra_response_headers)

            buf = None
            while buf != b'':
                try:
                    buf = prox_rec_res.read(65536)
                except http_client.IncompleteRead as e:
                    self.logger.warning('%s from %s', e, self.url)
                    buf = e.partial

                if (self._max_resource_size and
                        prox_rec_res.recorder.len > self._max_resource_size):
                    prox_rec_res.truncated = b'length'
                    self._remote_server_conn.sock.shutdown(socket.SHUT_RDWR)
                    self._remote_server_conn.sock.close()
                    self.logger.info(
                            'truncating response because max resource size %d '
                            'bytes exceeded for URL %s',
                            self._max_resource_size, self.url)
                    break
                elif (not 'content-length' in self.headers
                        and time.time() - start > 3 * 60 * 60):
                    prox_rec_res.truncated = b'time'
                    self._remote_server_conn.sock.shutdown(socket.SHUT_RDWR)
                    self._remote_server_conn.sock.close()
                    self.logger.info(
                            'reached hard timeout of 3 hours fetching url '
                            'without content-length: %s', self.url)
                    break

            self.log_request(prox_rec_res.status, prox_rec_res.recorder.len)
            # Let's close off the remote end. If remote connection is fine,
            # put it back in the pool to reuse it later.
            if not is_connection_dropped(self._remote_server_conn):
                self._conn_pool._put_conn(self._remote_server_conn)
        except Exception as e:
            # A common error is to connect to the remote server successfully
            # but raise a `RemoteDisconnected` exception when trying to begin
            # downloading. Its caused by prox_rec_res.begin(...) which calls
            # http_client._read_status(). The connection fails there.
            # https://github.com/python/cpython/blob/3.7/Lib/http/client.py#L275
            # Another case is when the connection is fine but the response
            # status is problematic, raising `BadStatusLine`.
            # https://github.com/python/cpython/blob/3.7/Lib/http/client.py#L296
            # In both cases, the host is bad and we must add it to
            # `bad_hostnames_ports` cache.
            if isinstance(e, (http_client.RemoteDisconnected,
                              http_client.BadStatusLine)):
                host_port = self._hostname_port_cache_key()
                with self.server.bad_hostnames_ports_lock:
                    self.server.bad_hostnames_ports[host_port] = 502
                self.logger.info('bad_hostnames_ports cache size: %d',
                                 len(self.server.bad_hostnames_ports))

            # Close the connection only if its still open. If its already
            # closed, an `OSError` "([Errno 107] Transport endpoint is not
            # connected)" would be raised.
            if not is_connection_dropped(self._remote_server_conn):
                self._remote_server_conn.sock.shutdown(socket.SHUT_RDWR)
                self._remote_server_conn.sock.close()
            raise
        finally:
            if prox_rec_res:
                prox_rec_res.close()

        return req, prox_rec_res

    def __getattr__(self, item):
        if item.startswith('do_'):
            return self.do_COMMAND

    def log_error(self, fmt, *args):
        self.logger.warning(fmt, *args)

class PooledMixIn(socketserver.ThreadingMixIn):
    logger = logging.getLogger("warcprox.mitmproxy.PooledMixIn")
    def __init__(self, max_threads=None):
        self.active_requests = {}
        self.unaccepted_requests = 0
        self.max_threads = max_threads or 100
        self.pool = concurrent.futures.ThreadPoolExecutor(self.max_threads)
        self.logger.info("%s proxy threads", self.max_threads)

    def status(self):
        if hasattr(super(), 'status'):
            result = super().status()
        else:
            result = {}
        result.update({
            'threads': self.pool._max_workers,
            'active_requests': len(self.active_requests),
            'unaccepted_requests': self.unaccepted_requests})
        return result

    def process_request(self, request, client_address):
        self.active_requests[request] = doublethink.utcnow()
        future = self.pool.submit(
                self.process_request_thread, request, client_address)
        future.add_done_callback(
                lambda f: self.active_requests.pop(request, None))
        if future.done():
            # avoid theoretical timing issue, in case process_request_thread
            # managed to finish before future.add_done_callback() ran
            self.active_requests.pop(request, None)

    def get_request(self):
        '''
        Waits until no other requests are waiting for a thread in the pool to
        become available, then calls `socket.accept`.

        This override is necessary for the size of the thread pool to act as a
        cap on the number of open file handles.

        N.b. this method blocks if necessary, even though it's called from
        `_handle_request_noblock`.
        '''
        # neither threading.Condition Queue.not_empty nor Queue.not_full do
        # what we need here, right?
        start = time.time()
        self.logger.trace(
                'someone is connecting active_requests=%s',
                len(self.active_requests))
        self.unaccepted_requests += 1
        while len(self.active_requests) > self.max_threads:
            time.sleep(0.05)
        res = self.socket.accept()
        self.logger.trace(
                'accepted after %.1f sec active_requests=%s socket=%s',
                time.time() - start, len(self.active_requests), res[0])
        self.unaccepted_requests -= 1
        return res

class MitmProxy(http_server.HTTPServer):
    def __init__(self, *args, **kwargs):
        self.remote_server_socks = set()
        self.remote_server_socks_lock = threading.Lock()

    def register_remote_server_sock(self, sock):
        with self.remote_server_socks_lock:
            self.remote_server_socks.add(sock)

    def unregister_remote_server_sock(self, sock):
        with self.remote_server_socks_lock:
            self.remote_server_socks.discard(sock)

    def finish_request(self, request, client_address):
        '''
        We override socketserver.BaseServer.finish_request to get at
        MitmProxyHandler's self.request. A normal socket server's self.request
        is set to `request` and never changes, but in our case, it may be
        replaced with an SSL socket. The caller of this method (e.g.
        self.process_request or PooledMitmProxy.process_request_thread) needs
        to get a hold of that socket so it can close it.
        '''
        req_handler = self.RequestHandlerClass(request, client_address, self)
        return req_handler.request

    def process_request(self, request, client_address):
        '''
        This an almost verbatim copy/paste of
        socketserver.BaseServer.process_request.
        The only difference is that it expects self.finish_request to return
        the request (i.e. the socket). This new value of request is passed on
        to self.shutdown_request. See the comment on self.finish_request for
        the rationale.
        '''
        request = self.finish_request(request, client_address)
        self.shutdown_request(request)

class PooledMitmProxy(PooledMixIn, MitmProxy):
    # This value is passed as the "backlog" argument to listen(2). The default
    # value from socketserver.TCPServer is 5. Increasing this value is part of
    # the solution to client connections being closed suddenly and this message
    # appearing in kernel log on linux: "TCP: request_sock_TCP: Possible SYN
    # flooding on port 8000. Sending cookies.  Check SNMP counters." I think
    # this comes into play because we don't always accept(2) immediately (see
    # PooledMixIn.get_request()).
    # See also https://blog.dubbelboer.com/2012/04/09/syn-cookies.html
    request_queue_size = 4096

    def __init__(self, options=warcprox.Options()):
        PooledMixIn.__init__(self, options.max_threads)
        MitmProxy.__init__(self)
        self.profilers = collections.defaultdict(cProfile.Profile)
        self.shutting_down = False

        if options.profile:
            self.process_request_thread = self._profile_process_request_thread
        else:
            self.process_request_thread = self._process_request_thread

    def _profile_process_request_thread(self, request, client_address):
        profiler = self.profilers[threading.current_thread().ident]
        profiler.enable()
        self._process_request_thread(request, client_address)
        profiler.disable()

    def _process_request_thread(self, request, client_address):
        '''
        This an almost verbatim copy/paste of
        socketserver.ThreadingMixIn.process_request_thread.
        The only difference is that it expects self.finish_request to return
        the request (i.e. the socket). This new value of request is passed on
        to self.shutdown_request. See the comment on MitmProxy.finish_request
        for the rationale.
        '''
        try:
            request = self.finish_request(request, client_address)
            self.shutdown_request(request)
        except:
            self.handle_error(request, client_address)
            self.shutdown_request(request)

    def server_close(self):
        '''
        Abort active connections to remote servers to achieve prompt shutdown.
        '''
        self.shutting_down = True
        for sock in list(self.remote_server_socks):
            self.shutdown_request(sock)

class SingleThreadedMitmProxy(http_server.HTTPServer):
    logger = logging.getLogger('warcprox.warcproxy.SingleThreadedMitmProxy')

    def __init__(
            self, MitmProxyHandlerClass=MitmProxyHandler,
            options=warcprox.Options()):
        self.options = options

        # TTLCache is not thread-safe. Access to the shared cache from multiple
        # threads must be properly synchronized with an RLock according to ref:
        # https://cachetools.readthedocs.io/en/latest/
        self.bad_hostnames_ports = TTLCache(maxsize=1024, ttl=60)
        self.bad_hostnames_ports_lock = RLock()

        self.remote_connection_pool = PoolManager(
            num_pools=max((options.max_threads or 0) // 6, 400), maxsize=6)

        if options.onion_tor_socks_proxy:
            try:
                host, port = options.onion_tor_socks_proxy.split(':')
                MitmProxyHandlerClass.onion_tor_socks_proxy_host = host
                MitmProxyHandlerClass.onion_tor_socks_proxy_port = int(port)
            except ValueError:
                MitmProxyHandlerClass.onion_tor_socks_proxy_host = options.onion_tor_socks_proxy
                MitmProxyHandlerClass.onion_tor_socks_proxy_port = None
        if options.socks_proxy:
            host, port = options.socks_proxy.split(':')
            MitmProxyHandlerClass.socks_proxy_host = host
            MitmProxyHandlerClass.socks_proxy_port = int(port)
            if options.socks_proxy_username:
                MitmProxyHandlerClass.socks_proxy_username = options.socks_proxy_username
            if options.socks_proxy_password:
                MitmProxyHandlerClass.socks_proxy_password = options.socks_proxy_password

        if options.socket_timeout:
            MitmProxyHandlerClass._socket_timeout = options.socket_timeout
        if options.max_resource_size:
            MitmProxyHandlerClass._max_resource_size = options.max_resource_size
        if options.tmp_file_max_memory_size:
            MitmProxyHandlerClass._tmp_file_max_memory_size = options.tmp_file_max_memory_size

        self.digest_algorithm = options.digest_algorithm or 'sha1'

        ca_name = ('Warcprox CA on %s' % socket.gethostname())[:64]
        self.ca = CertificateAuthority(
                ca_file=options.cacert or 'warcprox-ca.pem',
                certs_dir=options.certs_dir or './warcprox-ca',
                ca_name=ca_name)

        server_address = (
                options.address or 'localhost',
                options.port if options.port is not None else 8000)

        http_server.HTTPServer.__init__(
                self, server_address, MitmProxyHandlerClass,
                bind_and_activate=True)

