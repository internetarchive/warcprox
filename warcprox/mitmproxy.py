# vim:set sw=4 et:

from __future__ import absolute_import

try:
    import http.server as http_server
except ImportError:
    import BaseHTTPServer as http_server

try:
    import urllib.parse as urllib_parse
except ImportError:
    import urlparse as urllib_parse

import socket
import logging
import ssl

class MitmProxyHandler(http_server.BaseHTTPRequestHandler):
    logger = logging.getLogger("warcprox.mitmproxy.MitmProxyHandler")

    def __init__(self, request, client_address, server):
        self.is_connect = False

        ## XXX hack around bizarre bug on my mac python 3.2 in http.server
        ## where hasattr returns true in the code snippet below, but
        ## self._headers_buffer is None
        #
        # if not hasattr(self, '_headers_buffer'):
        #     self._headers_buffer = []
        # self._headers_buffer.append(
        self._headers_buffer = []

        http_server.BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _determine_host_port(self):
        # Get hostname and port to connect to
        if self.is_connect:
            self.hostname, self.port = self.path.split(':')
        else:
            self.url = self.path
            u = urllib_parse.urlparse(self.url)
            if u.scheme != 'http':
                raise Exception('Unknown scheme %s' % repr(u.scheme))
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

    def _connect_to_host(self):
        # Connect to destination
        self._proxy_sock = socket.socket()
        self._proxy_sock.settimeout(10)
        self._proxy_sock.connect((self.hostname, int(self.port)))

        # Wrap socket if SSL is required
        if self.is_connect:
            self._proxy_sock = ssl.wrap_socket(self._proxy_sock)

    def _transition_to_ssl(self):
        self.request = self.connection = ssl.wrap_socket(self.connection,
                server_side=True, certfile=self.server.ca.cert_for_host(self.hostname))

    def do_CONNECT(self):
        self.is_connect = True
        try:
            # Connect to destination first
            self._determine_host_port()
            self._connect_to_host()

            # If successful, let's do this!
            self.send_response(200, 'Connection established')
            self.end_headers()
            self._transition_to_ssl()
        except Exception as e:
            self.send_error(500, str(e))
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
        if not self.is_connect:
            try:
                # Connect to destination
                self._determine_host_port()
                self._connect_to_host()
                assert self.url
            except Exception as e:
                self.send_error(500, str(e))
                return
        else:
            # if self.is_connect we already connected in do_CONNECT
            self.url = self._construct_tunneled_url()

        self._proxy_request()


    def _proxy_request(self):
        raise Exception('_proxy_request() not implemented in MitmProxyHandler, must be implemented in subclass!')

    def __getattr__(self, item):
        if item.startswith('do_'):
            return self.do_COMMAND

    def log_error(self, fmt, *args):
        self.logger.error("{0} - - [{1}] {2}".format(self.address_string(),
            self.log_date_time_string(), fmt % args))

    def log_message(self, fmt, *args):
        self.logger.info("{} {} - - [{}] {}".format(self.__class__.__name__,
            self.address_string(), self.log_date_time_string(), fmt % args))


