#!/usr/bin/env python
# vim:set sw=4 et:
#
"""
WARC writing MITM HTTP/S proxy

See README.rst or https://github.com/internetarchive/warcprox
"""

try:
    import http.server
    http_server = http.server
except ImportError:
    import BaseHTTPServer
    http_server = BaseHTTPServer

try:
    import socketserver
except ImportError:
    import SocketServer
    socketserver = SocketServer

try:
    import urllib.parse
    urllib_parse = urllib.parse
except ImportError:
    import urlparse
    urllib_parse = urlparse

try:
    import queue
except ImportError:
    import Queue
    queue = Queue

try:
    import http.client
    http_client = http.client
except ImportError:
    import httplib
    http_client = httplib

try:
    import dbm.gnu
    dbm_gnu = dbm.gnu
except ImportError:
    try:
        import gdbm
        dbm_gnu = gdbm
    except ImportError:
        import anydbm
        dbm_gnu = anydbm

try:
    from io import StringIO
except ImportError:
    from StringIO import StringIO

try:
    import http.cookies
    cookie = http.cookies
except ImportError:
    import Cookie
    cookie = Cookie

import socket
import OpenSSL
import ssl
import logging
import sys
from hanzo import warctools, httptools
import hashlib
from datetime import datetime
import threading
import os
import argparse
import random
import re
import signal
import time
import tempfile
import json
import traceback

try:
    from warcprox.warcwriters import WarcWriter, WarcPerUrlWriter
except ImportError:
    from warcwriters import WarcWriter, WarcPerUrlWriter

class CertificateAuthority(object):
    logger = logging.getLogger('warcprox.CertificateAuthority')

    def __init__(self, ca_file='warcprox-ca.pem', certs_dir='./warcprox-ca'):
        self.ca_file = ca_file
        self.certs_dir = certs_dir

        if not os.path.exists(ca_file):
            self._generate_ca()
        else:
            self._read_ca(ca_file)

        if not os.path.exists(certs_dir):
            self.logger.info("directory for generated certs {} doesn't exist, creating it".format(certs_dir))
            os.mkdir(certs_dir)


    def _generate_ca(self):
        # Generate key
        self.key = OpenSSL.crypto.PKey()
        self.key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        # Generate certificate
        self.cert = OpenSSL.crypto.X509()
        self.cert.set_version(3)
        # avoid sec_error_reused_issuer_and_serial
        self.cert.set_serial_number(random.randint(0,2**64-1))
        self.cert.get_subject().CN = 'Warcprox CA on {}'.format(socket.gethostname())[:64]
        self.cert.gmtime_adj_notBefore(0)                # now
        self.cert.gmtime_adj_notAfter(100*365*24*60*60)  # 100 yrs in future
        self.cert.set_issuer(self.cert.get_subject())
        self.cert.set_pubkey(self.key)
        self.cert.add_extensions([
            OpenSSL.crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
            OpenSSL.crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=self.cert),
            ])
        self.cert.sign(self.key, "sha1")

        with open(self.ca_file, 'wb+') as f:
            f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.SSL.FILETYPE_PEM, self.key))
            f.write(OpenSSL.crypto.dump_certificate(OpenSSL.SSL.FILETYPE_PEM, self.cert))

        self.logger.info('generated CA key+cert and wrote to {}'.format(self.ca_file))


    def _read_ca(self, filename):
        self.cert = OpenSSL.crypto.load_certificate(OpenSSL.SSL.FILETYPE_PEM, open(filename).read())
        self.key = OpenSSL.crypto.load_privatekey(OpenSSL.SSL.FILETYPE_PEM, open(filename).read())
        self.logger.info('read CA key+cert from {}'.format(self.ca_file))

    def __getitem__(self, cn):
        cnp = os.path.sep.join([self.certs_dir, '%s.pem' % cn])
        if not os.path.exists(cnp):
            # create certificate
            key = OpenSSL.crypto.PKey()
            key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

            # Generate CSR
            req = OpenSSL.crypto.X509Req()
            req.get_subject().CN = cn
            req.set_pubkey(key)
            req.sign(key, 'sha1')

            # Sign CSR
            cert = OpenSSL.crypto.X509()
            cert.set_subject(req.get_subject())
            cert.set_serial_number(random.randint(0,2**64-1))
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(10*365*24*60*60)
            cert.set_issuer(self.cert.get_subject())
            cert.set_pubkey(req.get_pubkey())
            cert.sign(self.key, 'sha1')

            with open(cnp, 'wb+') as f:
                f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.SSL.FILETYPE_PEM, key))
                f.write(OpenSSL.crypto.dump_certificate(OpenSSL.SSL.FILETYPE_PEM, cert))

            self.logger.info('wrote generated key+cert to {}'.format(cnp))

        return cnp


class ProxyingRecorder(object):
    """
    Wraps a socket._fileobject, recording the bytes as they are read,
    calculating digests, and sending them on to the proxy client.
    """

    logger = logging.getLogger('warcprox.ProxyingRecordingHTTPResponse')

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


class MitmProxyHandler(http_server.BaseHTTPRequestHandler):
    logger = logging.getLogger('warcprox.MitmProxyHandler')

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
                server_side=True, certfile=self.server.ca[self.hostname])


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


class WarcProxyHandler(MitmProxyHandler):

    logger = logging.getLogger('warcprox.WarcProxyHandler')

    def _proxy_request(self):
        # Build request
        req_str = '{} {} {}\r\n'.format(self.command, self.path, self.request_version)

        # Get and remove optional request 'cookies' for warcprox
        # parse the header as cookie to avoid dealing with custom encoding schemes
        custom_params_header = self.headers.get('x-warcprox-params')
        if custom_params_header:
            del self.headers['x-warcprox-params']
            cp_cookie = cookie.SimpleCookie()
            cp_cookie.load(custom_params_header)
            custom_params = dict((n, m.value) for n, m in cp_cookie.items())
        else:
            custom_params = {}

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
                response_recorder=h.recorder, remote_ip=remote_ip,
                custom_params=custom_params, status=h.status)
        self.server.recorded_url_q.put(recorded_url)


class RecordedUrl(object):
    def __init__(self, url, request_data, response_recorder, remote_ip,
                 custom_params={}, status=None):
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

        # Optional params dict, if any, passed to warcprox
        # via a cookie-like header
        self.custom_params = custom_params

        self.status = status


class WarcProxy(socketserver.ThreadingMixIn, http_server.HTTPServer):
    logger = logging.getLogger('warcprox.WarcProxy')

    def __init__(self, server_address=('localhost', 8000),
            req_handler_class=WarcProxyHandler, bind_and_activate=True,
            ca=None, recorded_url_q=None, digest_algorithm='sha1'):
        http_server.HTTPServer.__init__(self, server_address, req_handler_class, bind_and_activate)

        self.digest_algorithm = digest_algorithm

        if ca is not None:
            self.ca = ca
        else:
            self.ca = CertificateAuthority()

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


class PlaybackProxyHandler(MitmProxyHandler):
    logger = logging.getLogger('warcprox.PlaybackProxyHandler')

    # @Override
    def _connect_to_host(self):
        # don't connect to host!
        pass


    # @Override
    def _proxy_request(self):
        date, location = self.server.playback_index_db.lookup_latest(self.url.encode('utf-8'))
        self.logger.debug('lookup_latest returned {}:{}'.format(date, location))

        status = None
        if location is not None:
            try:
                status, sz = self._send_response_from_warc(location['f'], location['o'])
            except:
                status = 500
                self.logger.error('PlaybackProxyHandler problem playing back {}'.format(self.url), exc_info=1)
                payload = b'500 Warcprox Error\n\n{}\n'.format(traceback.format_exc()).encode('utf-8')
                headers = (b'HTTP/1.1 500 Internal Server Error\r\n'
                        +  b'Content-Type: text/plain;charset=utf-8\r\n'
                        +  b'Content-Length: ' + str(len(payload)) + b'\r\n'
                        +  b'\r\n')
                self.connection.sendall(headers)
                self.connection.sendall(payload)
                sz = len(headers) + len(payload)
        else:
            status = 404
            payload = b'404 Not in Archive\n'
            headers = (b'HTTP/1.1 404 Not Found\r\n'
                    +  b'Content-Type: text/plain;charset=utf-8\r\n'
                    +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n'
                    +  b'\r\n')
            self.connection.sendall(headers)
            self.connection.sendall(payload)
            sz = len(headers) + len(payload)

        self.log_message('"%s" %s %s %s',
                         self.requestline, str(status), str(sz), repr(location) if location else '-')


    def _open_warc_at_offset(self, warcfilename, offset):
        self.logger.debug('opening {} at offset {}'.format(warcfilename, offset))

        warcpath = None
        for p in (os.path.sep.join([self.server.warcs_dir, warcfilename]),
                os.path.sep.join([self.server.warcs_dir, '{}.open'.format(warcfilename)])):
            if os.path.exists(p):
                warcpath = p

        if warcpath is None:
            raise Exception('{} not found'.format(warcfilename))

        return warctools.warc.WarcRecord.open_archive(filename=warcpath, mode='rb', offset=offset)


    def _send_response(self, headers, payload_fh):
        status = '-'
        m = re.match(br'^HTTP/\d\.\d (\d{3})', headers)
        if m is not None:
            status = m.group(1)

        self.connection.sendall(headers)
        sz = len(headers)

        while True:
            buf = payload_fh.read(8192)
            if buf == b'': break
            self.connection.sendall(buf)
            sz += len(buf)

        return status, sz


    def _send_headers_and_refd_payload(self, headers, refers_to, refers_to_target_uri, refers_to_date):
        location = self.server.playback_index_db.lookup_exact(refers_to_target_uri, refers_to_date, record_id=refers_to)
        self.logger.debug('loading http payload from {}'.format(location))

        fh = self._open_warc_at_offset(location['f'], location['o'])
        try:
            for (offset, record, errors) in fh.read_records(limit=1, offsets=True):
                pass

            if errors:
                raise Exception('warc errors at {}:{} -- {}'.format(warcfilename, offset, errors))

            warc_type = record.get_header(warctools.WarcRecord.TYPE)
            if warc_type != warctools.WarcRecord.RESPONSE:
                raise Exception('invalid attempt to retrieve http payload of "{}" record'.format(warc_type))

            # find end of headers
            while True:
                line = record.content_file.readline()
                if line == b'' or re.match(br'^\r?\n$', line):
                    break

            return self._send_response(headers, record.content_file)

        finally:
            fh.close()


    def _send_response_from_warc(self, warcfilename, offset):
        fh = self._open_warc_at_offset(warcfilename, offset)
        try:
            for (offset, record, errors) in fh.read_records(limit=1, offsets=True):
                pass

            if errors:
                raise Exception('warc errors at {}:{} -- {}'.format(warcfilename, offset, errors))

            warc_type = record.get_header(warctools.WarcRecord.TYPE)

            if warc_type == warctools.WarcRecord.RESPONSE:
                headers_buf = bytearray()
                while True:
                    line = record.content_file.readline()
                    headers_buf.extend(line)
                    if line == b'' or re.match(b'^\r?\n$', line):
                        break

                return self._send_response(headers_buf, record.content_file)

            elif warc_type == warctools.WarcRecord.REVISIT:
                # response consists of http headers from revisit record and
                # payload from the referenced record
                warc_profile = record.get_header(warctools.WarcRecord.PROFILE)
                if warc_profile != warctools.WarcRecord.PROFILE_IDENTICAL_PAYLOAD_DIGEST:
                    raise Exception('unknown revisit record profile {}'.format(warc_profile))

                refers_to = record.get_header(warctools.WarcRecord.REFERS_TO)
                refers_to_target_uri = record.get_header(warctools.WarcRecord.REFERS_TO_TARGET_URI)
                refers_to_date = record.get_header(warctools.WarcRecord.REFERS_TO_DATE)

                self.logger.debug('revisit record references {}:{} capture of {}'.format(refers_to_date, refers_to, refers_to_target_uri))
                return self._send_headers_and_refd_payload(record.content[1], refers_to, refers_to_target_uri, refers_to_date)

            else:
                raise Exception('unknown warc record type {}'.format(warc_type))

        finally:
            fh.close()

        raise Exception('should not reach this point')


class PlaybackProxy(socketserver.ThreadingMixIn, http_server.HTTPServer):
    logger = logging.getLogger('warcprox.PlaybackProxy')

    def __init__(self, server_address, req_handler_class=PlaybackProxyHandler,
            bind_and_activate=True, ca=None, playback_index_db=None,
            warcs_dir=None):
        http_server.HTTPServer.__init__(self, server_address, req_handler_class, bind_and_activate)
        self.ca = ca
        self.playback_index_db = playback_index_db
        self.warcs_dir = warcs_dir

    def server_activate(self):
        http_server.HTTPServer.server_activate(self)
        self.logger.info('PlaybackProxy listening on {0}:{1}'.format(self.server_address[0], self.server_address[1]))

    def server_close(self):
        self.logger.info('PlaybackProxy shutting down')
        http_server.HTTPServer.server_close(self)


class DedupDb(object):
    logger = logging.getLogger('warcprox.DedupDb')

    def __init__(self, dbm_file='./warcprox-dedup.db'):
        if os.path.exists(dbm_file):
            self.logger.info('opening existing deduplication database {}'.format(dbm_file))
        else:
            self.logger.info('creating new deduplication database {}'.format(dbm_file))

        self.db = dbm_gnu.open(dbm_file, 'c')

    def close(self):
        self.db.close()

    def sync(self):
        self.db.sync()

    def save_digest(self, digest, response_record, recorded_url):
        if ((response_record.get_header(warctools.WarcRecord.TYPE) !=
             warctools.WarcRecord.RESPONSE) or
            recorded_url.response_recorder.payload_size() == 0):
            return

        record_id = response_record.get_header(warctools.WarcRecord.ID).decode('latin1')
        url = response_record.get_header(warctools.WarcRecord.URL).decode('latin1')
        date = response_record.get_header(warctools.WarcRecord.DATE).decode('latin1')

        py_value = {'i':record_id, 'u':url, 'd':date}
        json_value = json.dumps(py_value, separators=(',',':'))

        self.db[digest] = json_value.encode('utf-8')
        self.logger.debug('dedup db saved {}:{}'.format(digest, json_value))


    def lookup(self, digest, url=None, custom_params={}):
        if digest in self.db:
            json_result = self.db[digest]
            result = json.loads(json_result.decode('utf-8'))
            result['i'] = result['i'].encode('latin1')
            result['u'] = result['u'].encode('latin1')
            result['d'] = result['d'].encode('latin1')
            return result
        else:
            return None


class PlaybackIndexDb(object):
    logger = logging.getLogger('warcprox.PlaybackIndexDb')

    def __init__(self, dbm_file='./warcprox-playback-index.db'):
        if os.path.exists(dbm_file):
            self.logger.info('opening existing playback index database {}'.format(dbm_file))
        else:
            self.logger.info('creating new playback index database {}'.format(dbm_file))

        self.db = dbm_gnu.open(dbm_file, 'c')


    def close(self):
        self.db.close()


    def sync(self):
        self.db.sync()


    def save_url(self, digest, response_record, offset, length, filename, recorded_url):
        # XXX canonicalize url?
        url = response_record.get_header(warctools.WarcRecord.URL)
        date_str = response_record.get_header(warctools.WarcRecord.DATE).decode('latin1')
        record_id_str = response_record.get_header(warctools.WarcRecord.ID).decode('latin1')

        # there could be two visits of same url in the same second, and WARC-Date is
        # prescribed as YYYY-MM-DDThh:mm:ssZ, so we have to handle it :-\

        # url:{date1:[record1={'f':filename,'o':response_offset,'q':request_offset,'i':record_id},record2,...],date2:[{...}],...}
        if url in self.db:
            existing_json_value = self.db[url].decode('utf-8')
            py_value = json.loads(existing_json_value)
        else:
            py_value = {}

        if date_str in py_value:
            py_value[date_str].append({'f':filename, 'o':offset, 'i':record_id_str})
        else:
            py_value[date_str] = [{'f':filename, 'o':offset, 'i':record_id_str}]

        json_value = json.dumps(py_value, separators=(',',':'))

        self.db[url] = json_value.encode('utf-8')

        self.logger.debug('playback index saved: {}:{}'.format(url, json_value))


    def lookup_latest(self, url):
        if url not in self.db:
            return None, None

        json_value = self.db[url].decode('utf-8')
        self.logger.debug("{}:{}".format(repr(url), repr(json_value)))
        py_value = json.loads(json_value)

        latest_date = max(py_value)
        result = py_value[latest_date][0]
        result['i'] = result['i'].encode('ascii')
        return latest_date, result


    # in python3 params are bytes
    def lookup_exact(self, url, warc_date, record_id):
        if url not in self.db:
            return None

        json_value = self.db[url].decode('utf-8')
        self.logger.debug("{}:{}".format(repr(url), repr(json_value)))
        py_value = json.loads(json_value)

        warc_date_str = warc_date.decode('ascii')

        if warc_date_str in py_value:
            for record in py_value[warc_date_str]:
                if record['i'].encode('ascii') == record_id:
                    self.logger.debug("found exact match for ({},{},{})".format(repr(warc_date), repr(record_id), repr(url)))
                    record['i'] = record['i'].encode('ascii')
                    return record
        else:
            self.logger.info("match not found for ({},{},{})".format(repr(warc_date), repr(record_id), repr(url)))
            return None


class WarcproxController(object):
    logger = logging.getLogger('warcprox.WarcproxController')

    def __init__(self, proxy=None, warc_writer=None, playback_proxy=None):
        """
        Create warcprox controller.

        If supplied, proxy should be an instance of WarcProxy, and warc_writer
        should be an instance of WarcproxWriter. If not supplied, they are
        created with default values.

        If supplied, playback_proxy should be an instance of PlaybackProxy. If not
        supplied, no playback proxy will run.
        """
        if proxy is not None:
            self.proxy = proxy
        else:
            self.proxy = WarcProxy()

        if warc_writer is None:
            warc_writer = WarcWriter()

        self.warc_writer_thread = WarcproxWriterThread(recorded_url_q=self.proxy.recorded_url_q,
                                                       warc_writer=warc_writer)
        self.warc_writer = warc_writer

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

            # should this be moved into warc_writer thread?
            if self.warc_writer.dedup_db is not None:
                self.warc_writer.dedup_db.close()

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


class WarcproxWriterThread(threading.Thread):
    def __init__(self, recorded_url_q, warc_writer=None):
        threading.Thread.__init__(self, name=self.__class__.__name__)

        self.logger = logging.getLogger(self.__class__.__name__)

        self.recorded_url_q = recorded_url_q

        if warc_writer:
            self.warc_writer = warc_writer
        else:
            self.warc_writer = WarcWriter()

        self.stop = threading.Event()


    def run(self):
        self.warc_writer.init_writer()

        self.logger.info(self.warc_writer.describe())

        try:
            while not self.stop.is_set():
                try:
                    recorded_url = self.recorded_url_q.get(block=True, timeout=0.5)
                    self.warc_writer.write_url(recorded_url)
                except queue.Empty:
                    self.warc_writer.on_empty_queue()
        finally:
            self.logger.info('{} shutting down'.format(self.warc_writer.__class__.__name__))
            self.warc_writer.close_writer()

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
    arg_parser.add_argument('-u', '--warc-per-url', dest='warc_per_url', action='store_true',
            help='create a warc per request in optional target dir')
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
        dedup_db = DedupDb(args.dedup_db_file)

    recorded_url_q = queue.Queue()

    ca = CertificateAuthority(args.cacert, args.certs_dir)

    proxy = WarcProxy(server_address=(args.address, int(args.port)),
            ca=ca, recorded_url_q=recorded_url_q,
            digest_algorithm=args.digest_algorithm)

    if args.playback_port is not None:
        playback_index_db = PlaybackIndexDb(args.playback_index_db_file)
        playback_server_address=(args.address, int(args.playback_port))
        playback_proxy = PlaybackProxy(server_address=playback_server_address,
                ca=ca, playback_index_db=playback_index_db,
                warcs_dir=args.directory)
    else:
        playback_index_db = None
        playback_proxy = None

    if args.warc_per_url:
        logging.info('Using warc-per-url writer')
        warc_writer_class = WarcPerUrlWriter
    else:
        logging.info('Using default warc writer')
        warc_writer_class = WarcWriter

    warc_writer = warc_writer_class(directory=args.directory,
            gzip=args.gzip, prefix=args.prefix,
            port=int(args.port), rollover_size=int(args.size),
            rollover_idle_time=int(args.rollover_idle_time) if args.rollover_idle_time is not None else None,
            base32=args.base32, dedup_db=dedup_db,
            digest_algorithm=args.digest_algorithm,
            playback_index_db=playback_index_db)

    warcprox = WarcproxController(proxy, warc_writer, playback_proxy)
    warcprox.run_until_shutdown()


if __name__ == '__main__':
    main()

