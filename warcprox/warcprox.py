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

import logging
import re
import tempfile
import traceback
import hashlib
import json
import socket
import threading
import time

from certauth.certauth import CertificateAuthority
import warcprox.mitmproxy

class ProxyingRecorder(object):
    """
    Wraps a socket._fileobject, recording the bytes as they are read,
    calculating digests, and sending them on to the proxy client.
    """

    logger = logging.getLogger("warcprox.warcprox.ProxyingRecorder")

    def __init__(self, fp, proxy_dest, digest_algorithm='sha1', prev_continuation_payload_size=0):
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
        self.prev_continuation_payload_size = prev_continuation_payload_size

    def _update_payload_digest(self, hunk):
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

    def _update(self, hunk):
        self._update_payload_digest(hunk)
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

    def continuation_payload_size(self):
        return self.prev_continuation_payload_size + self.payload_size()


class ProxyingRecordingHTTPResponse(http_client.HTTPResponse):

    def __init__(self, sock, debuglevel=0, method=None, proxy_dest=None, digest_algorithm='sha1'):
        http_client.HTTPResponse.__init__(self, sock, debuglevel=debuglevel, method=method)

        self.proxy_dest = proxy_dest
        self.digest_algorithm = digest_algorithm
        self.orig_fp = self.fp
        # Keep around extra reference to self.fp because HTTPResponse sets
        # self.fp=None after it finishes reading, but we still need it
        self.recorder = ProxyingRecorder(self.orig_fp, self.proxy_dest, self.digest_algorithm)
        self.fp = self.recorder


class WarcProxyHandler(warcprox.mitmproxy.MitmProxyHandler):
    logger = logging.getLogger("warcprox.warcprox.WarcProxyHandler")

    def _proxy_request(self):
        # Build request
        req_str = '{} {} {}\r\n'.format(self.command, self.path, self.request_version)

        warcprox_meta = self.headers.get('Warcprox-Meta')

        # Swallow headers that don't make sense to forward on, i.e. most
        # hop-by-hop headers, see http://tools.ietf.org/html/rfc2616#section-13.5
        # self.headers is an email.message.Message, which is case-insensitive
        # and doesn't throw KeyError in __delitem__
        for h in ('Connection', 'Proxy-Connection', 'Keep-Alive',
                'Proxy-Authenticate', 'Proxy-Authorization', 'Upgrade',
                'Warcprox-Meta'):
            del self.headers[h]

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

        remote_ip = self._proxy_sock.getpeername()[0]

        buf = h.read(8192)
        # Keep track of which segment is the first segment, since WARC
        # continuation records need WARC-Segment-Origin-ID header field.
        first_segment = None
        # Keep track of segment number, since WARC continuation records
        # need WARC-Segment-Number header field.
        segment_number = 0
        # Keep track of start time so that can rollover WARC record based on time.
        record_start_time = time.time()
        while buf != b'':
            # Check if should interrupt reading the response.
            if self.server.stop.is_set():
                self.logger.debug("Interrupting stream since stop is set")
                break
            # Read a chunk from the response.
            buf = h.read(8192)
            self.logger.debug("Record size: %s. Max is %s.", h.recorder.len, self.server.record_size)
            # If record has gotten too big or taken too long, segment it.
            if (self.server.record_size and h.recorder.len > self.server.record_size) \
                    or (self.server.record_rollover_time
                        and time.time() - record_start_time > self.server.record_rollover_time):
                self.logger.info("Starting a new record")
                segment_number += 1
                # Create a RecordedUrl and add it to the queue to be written to WARC.
                recorded_url = RecordedUrl(url=self.url, request_data=req,
                    response_recorder=h.recorder, remote_ip=remote_ip,
                    warcprox_meta=warcprox_meta, first_segment=first_segment, segment_number=segment_number)
                self.server.recorded_url_q.put(recorded_url)
                # Update information that will be needed for later segments.
                if not first_segment:
                    first_segment = recorded_url
                prev_continuation_payload_size = h.recorder.continuation_payload_size()
                # Reset things.
                # Provide ProxyingRecordingHTTPResponse with a fresh ProxyingRecorder
                h.recorder = ProxyingRecorder(h.orig_fp, h.proxy_dest, h.digest_algorithm,
                                              prev_continuation_payload_size=prev_continuation_payload_size)
                h.fp = h.recorder
                record_start_time = time.time()

        self.log_request(h.status, h.recorder.len)

        # Let's close off the remote end
        h.close()
        self._proxy_sock.close()

        if first_segment:
            segment_number += 1
        recorded_url = RecordedUrl(url=self.url, request_data=req,
                response_recorder=h.recorder, remote_ip=remote_ip,
                warcprox_meta=warcprox_meta, first_segment=first_segment, is_last_segment=True,
                segment_number=segment_number, truncated=(first_segment and self.server.stop.is_set()))
        self.server.recorded_url_q.put(recorded_url)

        return recorded_url


class RecordedUrl(object):
    def __init__(self, url, request_data, response_recorder, remote_ip, warcprox_meta=None, first_segment=None,
                 is_last_segment=False, segment_number=0, truncated=False):
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
            self.warcprox_meta = json.loads(warcprox_meta)
        else:
            self.warcprox_meta = {}

        self.first_segment = first_segment
        self.is_last_segment = is_last_segment
        self.segment_number = segment_number
        self.truncated = truncated


class WarcProxy(socketserver.ThreadingMixIn, http_server.HTTPServer):
    logger = logging.getLogger("warcprox.warcprox.WarcProxy")

    def __init__(self, server_address=('localhost', 8000),
            req_handler_class=WarcProxyHandler, bind_and_activate=True,
            ca=None, recorded_url_q=None, digest_algorithm='sha1', record_size=1000 * 1000 * 100,
            record_rollover_time=5 * 60):
        http_server.HTTPServer.__init__(self, server_address, req_handler_class, bind_and_activate)

        #This will be used to tell the WarcProxyHandler to interrupt.
        self.stop = threading.Event()

        self.digest_algorithm = digest_algorithm
        self.record_size  = record_size
        self.record_rollover_time= record_rollover_time
        #This causes abrupt termination
        #However, we don't want to end abruptly since need to write final segment record.
        # self.daemon_threads = True

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
            self.recorded_url_q = queue.Queue()

    def server_activate(self):
        http_server.HTTPServer.server_activate(self)
        self.logger.info('WarcProxy listening on {0}:{1}'.format(self.server_address[0], self.server_address[1]))

    def server_close(self):
        self.logger.info('WarcProxy shutting down')
        http_server.HTTPServer.server_close(self)

