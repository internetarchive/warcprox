#!/usr/bin/python
# vim:set sw=4 et:
#

# python3 imports
# from http.server import HTTPServer, BaseHTTPRequestHandler
# from urllib.parse import urlparse, urlunparse, ParseResult
# from socketserver import ThreadingMixIn
# from http.client import HTTPResponse

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse, urlunparse, ParseResult
from SocketServer import ThreadingMixIn
from httplib import HTTPResponse
from tempfile import gettempdir
from os import path, listdir
from ssl import wrap_socket
from socket import socket
from sys import argv

from OpenSSL.crypto import (X509Extension, X509, dump_privatekey, dump_certificate, load_certificate, load_privatekey,
                            PKey, TYPE_RSA, X509Req)
from OpenSSL.SSL import FILETYPE_PEM
import logging
import sys
import ssl
from hanzo.warctools import WarcRecord
from hanzo.warctools.warc import warc_datetime_str
import uuid
import hashlib
from datetime import datetime
import time
import Queue
import threading

__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PyMiProxy Project'
__credits__ = ['Nadeem Douba']

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'

__all__ = [
    'CertificateAuthority',
    'ProxyHandler',
    'RequestInterceptorPlugin',
    'ResponseInterceptorPlugin',
    'MitmProxy',
    'AsyncMitmProxy',
    'InvalidInterceptorPluginException'
]


class CertificateAuthority(object):

    def __init__(self, ca_file='ca.pem', cache_dir=gettempdir()):
        self.ca_file = ca_file
        self.cache_dir = cache_dir
        self._serial = self._get_serial()
        if not path.exists(ca_file):
            self._generate_ca()
        else:
            self._read_ca(ca_file)

    def _get_serial(self):
        s = 1
        for c in filter(lambda x: x.startswith('.pymp_'), listdir(self.cache_dir)):
            c = load_certificate(FILETYPE_PEM, open(path.sep.join([self.cache_dir, c])).read())
            sc = c.get_serial_number()
            if sc > s:
                s = sc
            del c
        return s

    def _generate_ca(self):
        # Generate key
        self.key = PKey()
        self.key.generate_key(TYPE_RSA, 2048)

        # Generate certificate
        self.cert = X509()
        self.cert.set_version(3)
        self.cert.set_serial_number(1)
        self.cert.get_subject().CN = 'ca.mitm.com'
        self.cert.gmtime_adj_notBefore(0)
        self.cert.gmtime_adj_notAfter(315360000)
        self.cert.set_issuer(self.cert.get_subject())
        self.cert.set_pubkey(self.key)
        self.cert.add_extensions([
            X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
            X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
            X509Extension("subjectKeyIdentifier", False, "hash", subject=self.cert),
            ])
        self.cert.sign(self.key, "sha1")

        with open(self.ca_file, 'wb+') as f:
            f.write(dump_privatekey(FILETYPE_PEM, self.key))
            f.write(dump_certificate(FILETYPE_PEM, self.cert))

    def _read_ca(self, file):
        self.cert = load_certificate(FILETYPE_PEM, open(file).read())
        self.key = load_privatekey(FILETYPE_PEM, open(file).read())

    def __getitem__(self, cn):
        cnp = path.sep.join([self.cache_dir, '.pymp_%s.pem' % cn])
        if not path.exists(cnp):
            # create certificate
            key = PKey()
            key.generate_key(TYPE_RSA, 2048)

            # Generate CSR
            req = X509Req()
            req.get_subject().CN = cn
            req.set_pubkey(key)
            req.sign(key, 'sha1')

            # Sign CSR
            cert = X509()
            cert.set_subject(req.get_subject())
            cert.set_serial_number(self.serial)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(31536000)
            cert.set_issuer(self.cert.get_subject())
            cert.set_pubkey(req.get_pubkey())
            cert.sign(self.key, 'sha1')

            with open(cnp, 'wb+') as f:
                f.write(dump_privatekey(FILETYPE_PEM, key))
                f.write(dump_certificate(FILETYPE_PEM, cert))

        return cnp

    @property
    def serial(self):
        self._serial += 1
        return self._serial


class UnsupportedSchemeException(Exception):
    pass


class ProxyHandler(BaseHTTPRequestHandler):

    def __init__(self, request, client_address, server):
        self.is_connect = False
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _connect_to_host(self):
        # Get hostname and port to connect to
        if self.is_connect:
            self.hostname, self.port = self.path.split(':')
        else:
            self.url = self.path
            u = urlparse(self.url)
            if u.scheme != 'http':
                raise UnsupportedSchemeException('Unknown scheme %s' % repr(u.scheme))
            self.hostname = u.hostname
            self.port = u.port or 80
            self.path = urlunparse(
                ParseResult(
                    scheme='',
                    netloc='',
                    params=u.params,
                    path=u.path or '/',
                    query=u.query,
                    fragment=u.fragment
                )
            )

        # Connect to destination
        self._proxy_sock = socket()
        self._proxy_sock.settimeout(10)
        self._proxy_sock.connect((self.hostname, int(self.port)))

        # Wrap socket if SSL is required
        if self.is_connect:
            self._proxy_sock = wrap_socket(self._proxy_sock)


    def _transition_to_ssl(self):
        self.request = wrap_socket(self.request, server_side=True, certfile=self.server.ca[self.path.split(':')[0]])


    def do_CONNECT(self):
        self.is_connect = True
        try:
            # Connect to destination first
            self._connect_to_host()

            # If successful, let's do this!
            self.send_response(200, 'Connection established')
            self.end_headers()
            #self.request.sendall('%s 200 Connection established\r\n\r\n' % self.request_version)
            self._transition_to_ssl()
        except Exception as e:
            self.send_error(500, str(e))
            return

        # Reload!
        self.setup()
        self.handle_one_request()
#         try:
#         except ssl.SSLError, e:
#             logging.warn("caught SSLError {0}".format(e))
#             pass


    def do_COMMAND(self):

        # Is this an SSL tunnel?
        if not self.is_connect:
            try:
                # Connect to destination
                self._connect_to_host()
            except Exception as e:
                self.send_error(500, str(e))
                return
            # Extract path

        # Build request
        req = '%s %s %s\r\n' % (self.command, self.path, self.request_version)
        
        # Add headers to the request
        req += '%s\r\n' % self.headers

        # Append message body if present to the request
        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))

        # Send it down the pipe!
        self._proxy_sock.sendall(self.mitm_request(req))

        # Parse response
        h = HTTPResponse(self._proxy_sock)
        h.begin()

        # Get rid of the pesky header
        del h.msg['Transfer-Encoding']

        # Time to relay the message across
        res = '%s %s %s\r\n' % (self.request_version, h.status, h.reason)
        res += '%s\r\n' % h.msg
        res += h.read()

        # Let's close off the remote end
        h.close()
        self._proxy_sock.close()

        # Relay the message
        self.request.sendall(self.mitm_response(res))

    def mitm_request(self, data):
        for p in self.server._req_plugins:
            data = p(self.server, self).do_request(data)
        return data

    def mitm_response(self, data):
        for p in self.server._res_plugins:
            data = p(self.server, self).do_response(data)
        return data

    def __getattr__(self, item):
        if item.startswith('do_'):
            return self.do_COMMAND


class InterceptorPlugin(object):

    def __init__(self, server, msg):
        self.server = server
        self.message = msg


class RequestInterceptorPlugin(InterceptorPlugin):

    def do_request(self, data):
        return data


class ResponseInterceptorPlugin(InterceptorPlugin):

    def do_response(self, data):
        return data


class InvalidInterceptorPluginException(Exception):
    pass


class MitmProxy(HTTPServer):

    def __init__(self, server_address=('', 8080), RequestHandlerClass=ProxyHandler, bind_and_activate=True, ca_file='ca.pem'):
        HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.ca = CertificateAuthority(ca_file)
        self._res_plugins = []
        self._req_plugins = []

    def register_interceptor(self, interceptor_class):
        if not issubclass(interceptor_class, InterceptorPlugin):
            raise InvalidInterceptorPluginException('Expected type InterceptorPlugin got %s instead' % type(interceptor_class))
        if issubclass(interceptor_class, RequestInterceptorPlugin):
            self._req_plugins.append(interceptor_class)
        if issubclass(interceptor_class, ResponseInterceptorPlugin):
            self._res_plugins.append(interceptor_class)


    def server_activate(self):
        HTTPServer.server_activate(self)
        logging.info('listening on {0}:{1}'.format(self.server_address[0], self.server_address[1]))


    def server_close(self):
        HTTPServer.server_close(self)
        logging.info('shut down')


class AsyncMitmProxy(ThreadingMixIn, MitmProxy):
    pass


class WarcRecordQueuer(RequestInterceptorPlugin, ResponseInterceptorPlugin):

    warc_record_out_queue = Queue.Queue()

    def __init__(self, server, msg):
        InterceptorPlugin.__init__(self, server, msg)

        if msg.is_connect:
            assert not msg.url

            if int(msg.port) == 443:
                netloc = msg.hostname
            else:
                netloc = '{0}:{1}'.format(msg.hostname, msg.port)

            self.url = urlunparse(
                ParseResult(
                    scheme='https',
                    netloc=netloc,
                    params='',
                    path=msg.path,
                    query='',
                    fragment=''
                )
            )
        else:
            assert msg.url
            self.url = msg.url


    def do_request(self, data):
        logging.info('{0} >> {1}'.format(self.url, repr(data[:100])))
        return data


    def make_warc_uuid(self, text):
        return "<urn:uuid:{0}>".format(uuid.UUID(hashlib.sha1(text).hexdigest()[0:32]))


    def do_response(self, data):
        logging.info('{0} << {1}'.format(self.url, repr(data[:100])))

        warc_record_id = self.make_warc_uuid("{0} {1}".format(self.url, time.time()))
        logging.info('{0}: {1}'.format(WarcRecord.ID, warc_record_id))

        headers = []
        headers.append((WarcRecord.ID, warc_record_id))
        headers.append((WarcRecord.URL, self.url))
        headers.append((WarcRecord.DATE, warc_datetime_str(datetime.now())))
        # headers.append((WarcRecord.IP_ADDRESS, ip))
        headers.append((WarcRecord.TYPE, WarcRecord.RESPONSE))

        warcrecord = WarcRecord(headers=headers, content=("application/http;msgtype=response", data))

        # warcrecord.write_to(sys.stdout, gzip=False)
        WarcRecordQueuer.warc_record_out_queue.put(warcrecord)
        
        return data


class WarcWriterThread(threading.Thread):

    # def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
    #     Thread.__init__(self, group=group, target=target, name=name, args=args, kwargs=args

    def __init__(self, warc_record_in_queue):
        threading.Thread.__init__(self, name='WarcWriterThread')
        self.warc_record_in_queue = warc_record_in_queue
        self.stop = threading.Event()


    def run(self):
        logging.info('WarcWriterThread starting')

        while not self.stop.is_set():
            try:
                warc_record = self.warc_record_in_queue.get(block=False, timeout=0.5)
                logging.info('got warc record to write from the queue: {0}'.format(warc_record))
                # warc_record.write_to(sys.stdout, gzip=False)
            except Queue.Empty:
                pass

        logging.info('WarcWriterThread shutting down')


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s %(process)d %(levelname)s %(funcName)s(%(filename)s:%(lineno)d) %(message)s')
    proxy = None
    if not argv[1:]:
        proxy = AsyncMitmProxy()
    else:
        proxy = AsyncMitmProxy(ca_file=argv[1])

    proxy.register_interceptor(WarcRecordQueuer)

    warc_writer = WarcWriterThread(WarcRecordQueuer.warc_record_out_queue)
    warc_writer.start()

    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        warc_writer.stop.set()
        proxy.server_close()

