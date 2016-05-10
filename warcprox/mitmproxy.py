'''
warcprox/mitmproxy.py - man-in-the-middle http/s proxy code, handles http
CONNECT method by creating a snakeoil certificate for the requested site,
calling ssl.wrap_socket() on the client connection; connects to remote
(proxied) host, possibly using tor if host tld is .onion and tor proxy is
configured

Copyright (C) 2012 Cygnos Corporation
Copyright (C) 2013-2016 Internet Archive

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

from __future__ import absolute_import

try:
    import http.server as http_server
except ImportError:
    import BaseHTTPServer as http_server

try:
    import urllib.parse as urllib_parse
except ImportError:
    import urlparse as urllib_parse
try:
    import http.client as http_client
except ImportError:
    import httplib as http_client
import socket
import logging
import ssl
import warcprox
import threading
import datetime
import socks
import tempfile
import hashlib

class ProxyingRecorder(object):
    """
    Wraps a socket._fileobject, recording the bytes as they are read,
    calculating digests, and sending them on to the proxy client.
    """

    logger = logging.getLogger("warcprox.mitmproxy.ProxyingRecorder")

    def __init__(self, fp, proxy_client, digest_algorithm='sha1', url=None):
        self.fp = fp
        # "The file has no name, and will cease to exist when it is closed."
        self.tempfile = tempfile.SpooledTemporaryFile(max_size=512*1024)
        self.digest_algorithm = digest_algorithm
        self.block_digest = hashlib.new(digest_algorithm)
        self.payload_offset = None
        self.payload_digest = None
        self.proxy_client = proxy_client
        self._proxy_client_conn_open = True
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

        if self.payload_digest and self._proxy_client_conn_open:
            try:
                self.proxy_client.sendall(hunk)
            except BaseException as e:
                self._proxy_client_conn_open = False
                self.logger.warn(
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
            digest_algorithm='sha1', url=None):
        http_client.HTTPResponse.__init__(
                self, sock, debuglevel=debuglevel, method=method)
        self.proxy_client = proxy_client
        self.url = url

        # Keep around extra reference to self.fp because HTTPResponse sets
        # self.fp=None after it finishes reading, but we still need it
        self.recorder = ProxyingRecorder(
                self.fp, proxy_client, digest_algorithm, url=url)
        self.fp = self.recorder

    def begin(self):
        http_client.HTTPResponse.begin(self)  # reads status line, headers

        status_and_headers = 'HTTP/1.1 {} {}\r\n'.format(
                self.status, self.reason)
        for k,v in self.msg.items():
            if k.lower() not in (
                    'connection', 'proxy-connection', 'keep-alive',
                    'proxy-authenticate', 'proxy-authorization', 'upgrade',
                    'strict-transport-security'):
                status_and_headers += '{}: {}\r\n'.format(k, v)
        status_and_headers += 'Connection: close\r\n\r\n'
        self.proxy_client.sendall(status_and_headers.encode('latin1'))

        self.recorder.payload_starts_now()

class MitmProxyHandler(http_server.BaseHTTPRequestHandler):
    '''
    An http proxy implementation of BaseHTTPRequestHandler, that acts as a
    man-in-the-middle in order to peek at the content of https transactions,
    and records the bytes in transit as it proxies them.
    '''
    logger = logging.getLogger("warcprox.mitmproxy.MitmProxyHandler")

    def __init__(self, request, client_address, server):
        threading.current_thread().name = 'MitmProxyHandler(tid={},started={},client={}:{})'.format(warcprox.gettid(), datetime.datetime.utcnow().isoformat(), client_address[0], client_address[1])
        self.is_connect = False
        self._headers_buffer = []
        request.settimeout(60)  # XXX what value should this have?
        http_server.BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _determine_host_port(self):
        # Get hostname and port to connect to
        if self.is_connect:
            self.hostname, self.port = self.path.split(':')
        else:
            self.url = self.path
            u = urllib_parse.urlparse(self.url)
            if u.scheme != 'http':
                raise Exception('unable to parse request "{}" as a proxy request'.format(self.requestline))
            self.hostname = u.hostname
            self.port = u.port or 80
            self.path = urllib_parse.urlunparse(
                urllib_parse.ParseResult(
                    scheme='',
                    netloc='',
                    params=u.params,
                    path=u.path or '/',
                    query=u.query,
                    fragment=u.fragment
                )
            )

    def _connect_to_remote_server(self):
        # Connect to destination
        if self.onion_tor_socks_proxy_host and self.hostname.lower().endswith('.onion'):
            self.logger.info("using tor socks proxy at %s:%s to connect to %s",
                    self.onion_tor_socks_proxy_host,
                    self.onion_tor_socks_proxy_port or 1080,
                    self.hostname)
            self._remote_server_sock = socks.socksocket()
            self._remote_server_sock.set_proxy(
                    socks.SOCKS5, addr=self.onion_tor_socks_proxy_host,
                    port=self.onion_tor_socks_proxy_port, rdns=True)
        else:
            self._remote_server_sock = socket.socket()

        # XXX what value should this timeout have?
        self._remote_server_sock.settimeout(60)
        self._remote_server_sock.connect((self.hostname, int(self.port)))

        # Wrap socket if SSL is required
        if self.is_connect:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self._remote_server_sock = context.wrap_socket(
                        self._remote_server_sock, server_hostname=self.hostname)
            except AttributeError:
                try:
                    self._remote_server_sock = ssl.wrap_socket(
                            self._remote_server_sock)
                except ssl.SSLError:
                    self.logger.warn(
                            "failed to establish ssl connection to %s; python "
                            "ssl library does not support SNI, considering "
                            "upgrading to python >= 2.7.9 or python 3.4",
                            self.hostname)
                    raise

        return self._remote_server_sock

    def _transition_to_ssl(self):
        self.request = self.connection = ssl.wrap_socket(self.connection,
                server_side=True, certfile=self.server.ca.cert_for_host(self.hostname))

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
        self.is_connect = True
        try:
            self._determine_host_port()

            # If successful, let's do this!
            self.send_response(200, 'Connection established')
            self.end_headers()
            self._transition_to_ssl()
        except Exception as e:
            try:
                self.logger.error("problem handling {}: {}".format(repr(self.requestline), e))
                if type(e) is socket.timeout:
                    self.send_error(504, str(e))
                else:
                    self.send_error(500, str(e))
            except Exception as f:
                self.logger.warn("failed to send error response ({}) to proxy client: {}".format(e, f))
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
        if self.is_connect:
            self.url = self._construct_tunneled_url()
        else:
            self._determine_host_port()
            assert self.url

        try:
            # Connect to destination
            self._connect_to_remote_server()
        except warcprox.RequestBlockedByRule as e:
            # limit enforcers have already sent the appropriate response
            self.logger.info("%s: %s", repr(self.requestline), e)
            return
        except Exception as e:
            self.logger.error("problem processing request {}: {}".format(repr(self.requestline), e))
            self.send_error(500, str(e))
            return

        try:
            self._proxy_request()
        except:
            self.logger.error("exception proxying request", exc_info=True)
            raise

    def _proxy_request(self):
        '''
        Sends the request to the remote server, then uses a ProxyingRecorder to
        read the response and send it to the proxy client, while recording the
        bytes in transit. Returns a tuple (request, response) where request is
        the raw request bytes, and response is a ProxyingRecorder.
        '''
        # Build request
        req_str = '{} {} {}\r\n'.format(
                self.command, self.path, self.request_version)

        # Swallow headers that don't make sense to forward on, i.e. most
        # hop-by-hop headers, see
        # http://tools.ietf.org/html/rfc2616#section-13.5.
        # self.headers is an email.message.Message, which is case-insensitive
        # and doesn't throw KeyError in __delitem__
        for key in (
                'Connection', 'Proxy-Connection', 'Keep-Alive',
                'Proxy-Authenticate', 'Proxy-Authorization', 'Upgrade'):
            del self.headers[key]

        # Add headers to the request
        # XXX in at least python3.3 str(self.headers) uses \n not \r\n :(
        req_str += '\r\n'.join(
                '{}: {}'.format(k,v) for (k,v) in self.headers.items())

        req = req_str.encode('latin1') + b'\r\n\r\n'

        # Append message body if present to the request
        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))

        try:
            self.logger.debug('sending to remote server req=%s', repr(req))

            # Send it down the pipe!
            self._remote_server_sock.sendall(req)

            prox_rec_res = ProxyingRecordingHTTPResponse(
                    self._remote_server_sock, proxy_client=self.connection,
                    digest_algorithm=self.server.digest_algorithm,
                    url=self.url)
            prox_rec_res.begin()

            buf = prox_rec_res.read(8192)
            while buf != b'':
                buf = prox_rec_res.read(8192)

            self.log_request(prox_rec_res.status, prox_rec_res.recorder.len)
        except socket.timeout as e:
            self.logger.warn(
                    "%s proxying %s %s", repr(e), self.command, self.url)
        except BaseException as e:
            self.logger.error(
                    "%s proxying %s %s", repr(e), self.command, self.url,
                    exc_info=True)
        finally:
            # Let's close off the remote end
            if prox_rec_res:
                prox_rec_res.close()
            self._remote_server_sock.close()

        return req, prox_rec_res

    def __getattr__(self, item):
        if item.startswith('do_'):
            return self.do_COMMAND

    def log_error(self, fmt, *args):
        self.logger.warn(fmt, *args)

