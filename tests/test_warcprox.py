#!/usr/bin/env python
'''
tests/test_warcprox.py - automated tests for warcprox

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
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
USA.
'''

import pytest
import threading
import time
import logging
import sys
import ssl
import re
import tempfile
import OpenSSL
import os
import shutil
import requests
import re
import json
import random
import doublethink
from hanzo import warctools
import warnings
import pprint
import traceback
import signal
from collections import Counter
import socket
import datetime
import warcio.archiveiterator
import io
import gzip
import mock
import email.message
import socketserver
from concurrent import futures
import urllib.parse

try:
    import http.server as http_server
except ImportError:
    import BaseHTTPServer as http_server

try:
    import queue
except ImportError:
    import Queue as queue

import certauth.certauth

import warcprox
import warcprox.main
import warcprox.crawl_log as crawl_log

try:
    import http.client as http_client
except ImportError:
    import httplib as http_client
orig_send = http_client.HTTPConnection.send
def _send(self, data):
    if isinstance(data, bytes) and hasattr(
            logging.root.handlers[0].stream, 'buffer'):
        logging.info('sending data (bytes): ')
        logging.root.handlers[0].stream.buffer.write(data)
        logging.root.handlers[0].stream.buffer.write(b'\n')
    elif isinstance(data, str):
        logging.info('sending data (str): ')
        logging.root.handlers[0].stream.write(data)
        logging.root.handlers[0].stream.write('\n')
    else:
        logging.info('sending data from %r', data)
    orig_send(self, data)
### uncomment this to block see raw requests going over the wire
# http_client.HTTPConnection.send = _send

logging.basicConfig(
        stream=sys.stdout, level=logging.TRACE,
        format='%(asctime)s %(process)d %(levelname)s %(threadName)s '
        '%(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')

logging.getLogger("urllib3").setLevel(logging.WARN)
logging.getLogger("requests.packages.urllib3").setLevel(logging.WARN)
import urllib3 ; urllib3.disable_warnings()
import requests.packages.urllib3 ; requests.packages.urllib3.disable_warnings()

def wait(callback, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        if callback():
            return
        time.sleep(0.1)
    raise Exception('timed out waiting for %s to return truthy' % callback)

# monkey patch dns lookup so we can test domain inheritance on localhost
orig_getaddrinfo = socket.getaddrinfo
orig_gethostbyname = socket.gethostbyname
orig_socket_connect = socket.socket.connect

def _getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if host.endswith('.localhost'):
        return orig_getaddrinfo('localhost', port, family, type, proto, flags)
    else:
        return orig_getaddrinfo(host, port, family, type, proto, flags)

def _gethostbyname(host):
    if host.endswith('.localhost'):
        return orig_gethostbyname('localhost')
    else:
        return orig_gethostbyname(host)

def _socket_connect(self, address):
    if address[0].endswith('.localhost'):
        return orig_socket_connect(self, ('localhost', address[1]))
    else:
        return orig_socket_connect(self, address)

socket.gethostbyname = _gethostbyname
socket.getaddrinfo = _getaddrinfo
socket.socket.connect = _socket_connect

def dump_state(signum=None, frame=None):
    pp = pprint.PrettyPrinter(indent=4)
    state_strs = []

    for th in threading.enumerate():
        try:
            state_strs.append(str(th))
        except AssertionError:
            state_strs.append("<n/a:AssertionError>")
        stack = traceback.format_stack(sys._current_frames()[th.ident])
        state_strs.append("".join(stack))

    logging.warning("dumping state (caught signal {})\n{}".format(signum, "\n".join(state_strs)))

signal.signal(signal.SIGQUIT, dump_state)

def chunkify(buf, chunk_size=13):
    i = 0
    result = b''
    while i < len(buf):
        chunk_len = min(len(buf) - i, chunk_size)
        result += ('%x\r\n' % chunk_len).encode('ascii')
        result += buf[i:i+chunk_len]
        result += b'\r\n'
        i += chunk_size
    result += b'0\r\n\r\n'
    return result

# def gzipify(buf):
#     with io.BytesIO() as outbuf:
#         with gzip.GzipFile(fileobj=outbuf, mode='wb') as gz:
#             gz.write(buf)
#         return outbuf.getvalue()

class _TestHttpRequestHandler(http_server.BaseHTTPRequestHandler):
    # enable keepalive
    protocol_version = 'HTTP/1.1'

    def build_response(self):
        m = re.match(r'^/([^/]+)/([^/]+)$', self.path)
        if m is not None:
            seg1 = urllib.parse.unquote(m.group(1))
            seg2 = urllib.parse.unquote(m.group(2))
            special_header = 'warcprox-test-header: {}!'.format(seg1).encode('utf-8')
            payload = 'I am the warcprox test payload! {}!\n'.format(10*seg2).encode('utf-8')
            headers = (b'HTTP/1.1 200 OK\r\n'
                    +  b'Content-Type: text/plain\r\n'
                    +  special_header + b'\r\n'
                    +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n'
                    +  b'\r\n')
        elif self.path == '/missing-content-length':
            headers = (b'HTTP/1.1 200 OK\r\n'
                    +  b'Content-Type: text/plain\r\n'
                    +  b'\r\n')
            payload = b'This response is missing a Content-Length http header.'
        elif self.path == '/300k-content':
            payload = b'0123456789' * 30000
            headers = (b'HTTP/1.1 200 OK\r\n'
                    +  b'Content-Type: text/plain\r\n'
                    +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n'
                    +  b'\r\n')
        elif self.path == '/text-2bytes':
            payload = b'aa'
            headers = (b'HTTP/1.1 200 OK\r\n'
                    +  b'Content-Type: text/plain\r\n'
                    +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n'
                    +  b'\r\n')
        elif self.path == '/binary-4bytes':
            payload = b'aaaa'
            headers = (b'HTTP/1.1 200 OK\r\n'
                    +  b'Content-Type: application/octet-stream\r\n'
                    +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n'
                    +  b'\r\n')
        elif self.path.startswith('/test_payload_digest-'):
            content_body = (
                    b'Hello. How are you. I am the test_payload_digest '
                    b'content body. The entity body is a possibly content-'
                    b'encoded version of me. The message body is a possibly '
                    b'transfer-encoded version of the entity body.\n')
            gzipped = (
                    b"\x1f\x8b\x08\x00jA\x06Z\x02\xffm\x8d1\x0e\xc20\x10\x04{^"
                    b"\xb1\x1f\xc0\xef\x08=}t\x897\xc1\x92\xed\x8b|\x07\xc8"
                    b"\xbf'\n\xa2@J9\xab\x19\xed\xc0\x9c5`\xd07\xa4\x11]\x9f"
                    b"\x017H\x81?\x08\xa7\xf9\xb8I\xcf*q\x8ci\xdd\x11\xb3VguL"
                    b"\x1a{\xc0}\xb7vJ\xde\x8f\x01\xc9 \xd8\xd4,M\xb9\xff\xdc"
                    b"+\xeb\xac\x91\x11/6KZ\xa1\x0b\n\xbfq\xa1\x99\xac<\xab"
                    b"\xbdI\xb5\x85\xed,\xf7\xff\xdfp\xf9\x00\xfc\t\x02\xb0"
                    b"\xc8\x00\x00\x00")
            double_gzipped = (
                    b"\x1f\x8b\x08\x00jA\x06Z\x02\xff\x01\x89\x00v\xff\x1f\x8b"
                    b"\x08\x00jA\x06Z\x02\xffm\x8d1\x0e\xc20\x10\x04{^\xb1\x1f"
                    b"\xc0\xef\x08=}t\x897\xc1\x92\xed\x8b|\x07\xc8\xbf'\n\xa2"
                    b"@J9\xab\x19\xed\xc0\x9c5`\xd07\xa4\x11]\x9f\x017H\x81?"
                    b"\x08\xa7\xf9\xb8I\xcf*q\x8ci\xdd\x11\xb3VguL\x1a{\xc0}"
                    b"\xb7vJ\xde\x8f\x01\xc9 \xd8\xd4,M\xb9\xff\xdc+\xeb\xac"
                    b"\x91\x11/6KZ\xa1\x0b\n\xbfq\xa1\x99\xac<\xab\xbdI\xb5"
                    b"\x85\xed,\xf7\xff\xdfp\xf9\x00\xfc\t\x02\xb0\xc8\x00\x00"
                    b"\x00\xf9\xdd\x8f\xed\x89\x00\x00\x00")
            if self.path == '/test_payload_digest-plain':
                payload = content_body
                actual_headers = (b'Content-Type: text/plain\r\n'
                               +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n')
            elif self.path == '/test_payload_digest-gzip':
                payload = gzipped
                actual_headers = (b'Content-Type: application/gzip\r\n'
                               +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n')
            elif self.path == '/test_payload_digest-ce-gzip':
                payload = gzipped
                actual_headers = (b'Content-Type: text/plain\r\n'
                               +  b'Content-Encoding: gzip\r\n'
                               +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n')
            elif self.path == '/test_payload_digest-gzip-ce-gzip':
                payload = double_gzipped
                actual_headers = (b'Content-Type: application/gzip\r\n'
                               +  b'Content-Encoding: gzip\r\n'
                               +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n')
            elif self.path == '/test_payload_digest-te-chunked':
                payload = chunkify(content_body)
                actual_headers = (b'Content-Type: text/plain\r\n'
                               +  b'Transfer-Encoding: chunked\r\n')
            elif self.path == '/test_payload_digest-gzip-te-chunked':
                payload = chunkify(gzipped)
                actual_headers = (b'Content-Type: application/gzip\r\n'
                               +  b'Transfer-Encoding: chunked\r\n')
            elif self.path == '/test_payload_digest-ce-gzip-te-chunked':
                payload = chunkify(gzipped)
                actual_headers = (b'Content-Type: text/plain\r\n'
                               +  b'Content-Encoding: gzip\r\n'
                               +  b'Transfer-Encoding: chunked\r\n')
            elif self.path == '/test_payload_digest-gzip-ce-gzip-te-chunked':
                payload = chunkify(double_gzipped)
                actual_headers = (b'Content-Type: application/gzip\r\n'
                               +  b'Content-Encoding: gzip\r\n'
                               +  b'Transfer-Encoding: chunked\r\n')
            else:
                raise Exception('bad path')
            headers = b'HTTP/1.1 200 OK\r\n' + actual_headers +  b'\r\n'
            logging.info('headers=%r payload=%r', headers, payload)
        elif self.path == '/empty-response':
            headers = b''
            payload = b''
        elif self.path == '/slow-response':
            time.sleep(6)
            headers = (b'HTTP/1.1 200 OK\r\n'
                    +  b'Content-Type: text/plain\r\n'
                    +  b'\r\n')
            payload = b'Test.'
            actual_headers = (b'Content-Type: text/plain\r\n'
                           + b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n')
        elif self.path == '/incomplete-read':
            headers = (b'HTTP/1.1 200 OK\r\n'
                     + b'Content-Type: text/plain\r\n'
                     + b'Transfer-Encoding: chunked\r\n'
                     + b'\r\n')
            # payload = b'''1\r\na'''
            payload = chunkify(
                    b'Server closes connection when client expects next chunk')
            payload = payload[:-7]
        elif self.path == '/space_in_content_type':
            payload = b'test'
            headers = (b'HTTP/1.1 200 OK\r\n'
                    +  b'Content-Type:  \r\n'
                    +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n'
                    +  b'\r\n')
        else:
            payload = b'404 Not Found\n'
            headers = (b'HTTP/1.1 404 Not Found\r\n'
                    +  b'Content-Type: text/plain\r\n'
                    +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n'
                    +  b'\r\n')
        return headers, payload

    def do_GET(self):
        logging.info('GET {}'.format(self.path))
        headers, payload = self.build_response()
        self.connection.sendall(headers)
        self.connection.sendall(payload)
        if self.path in (
                '/missing-content-length', '/empty-response',
                '/incomplete-read'):
            # server must close the connection, else client has no idea if
            # there is more data coming
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()

    def do_HEAD(self):
        logging.info('HEAD {}'.format(self.path))
        headers, payload = self.build_response()
        self.connection.sendall(headers)

@pytest.fixture(scope="module")
def cert(request):
    f = tempfile.NamedTemporaryFile(prefix='warcprox-test-https-', suffix='.pem', delete=False)

    def fin():
        logging.info("deleting file %s", f.name)
        os.unlink(f.name)
    request.addfinalizer(fin)

    try:
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        req = OpenSSL.crypto.X509Req()
        req.get_subject().CN = 'localhost'
        req.set_pubkey(key)
        req.sign(key, 'sha1')
        cert = OpenSSL.crypto.X509()
        cert.set_subject(req.get_subject())
        cert.set_serial_number(0)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(2*60*60) # valid for 2hrs
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(key, 'sha1')

        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.SSL.FILETYPE_PEM, key))
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.SSL.FILETYPE_PEM, cert))

        logging.info('generated self-signed certificate {}'.format(f.name))
        return f.name
    finally:
        f.close()

# We need this test server to accept multiple simultaneous connections in order
# to avoid mysterious looking test failures like these:
# https://travis-ci.org/internetarchive/warcprox/builds/362892231
# This is because we can't guarantee (without jumping through hoops) that
# MitmProxyHandler._proxy_request() returns the connection to the pool before
# the next request tries to get a connection from the pool in
# MitmProxyHandler._connect_to_remote_server(). (Unless we run warcprox
# single-threaded for these tests, which maybe we should consider?)
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http_server.HTTPServer):
    pass

@pytest.fixture(scope="module")
def http_daemon(request):
    http_daemon = ThreadedHTTPServer(
            ('localhost', 0), RequestHandlerClass=_TestHttpRequestHandler)
    logging.info('starting http://{}:{}'.format(http_daemon.server_address[0], http_daemon.server_address[1]))
    http_daemon_thread = threading.Thread(name='HttpDaemonThread',
            target=http_daemon.serve_forever)
    http_daemon_thread.start()

    def fin():
        logging.info("stopping http daemon")
        http_daemon.shutdown()
        http_daemon.server_close()
        http_daemon_thread.join()
    request.addfinalizer(fin)

    return http_daemon

@pytest.fixture(scope="module")
def https_daemon(request, cert):
    # http://www.piware.de/2011/01/creating-an-https-server-in-python/
    https_daemon = ThreadedHTTPServer(('localhost', 0),
            RequestHandlerClass=_TestHttpRequestHandler)
    https_daemon.socket = ssl.wrap_socket(https_daemon.socket, certfile=cert, server_side=True)
    logging.info('starting https://{}:{}'.format(https_daemon.server_address[0], https_daemon.server_address[1]))
    https_daemon_thread = threading.Thread(name='HttpsDaemonThread',
            target=https_daemon.serve_forever)
    https_daemon_thread.start()

    def fin():
        logging.info("stopping https daemon")
        https_daemon.shutdown()
        https_daemon.server_close()
        https_daemon_thread.join()
    request.addfinalizer(fin)

    return https_daemon

# specify http_daemon and https_daemon as dependencies so that their finalizers
# run after warcprox is shut down, otherwise warcprox holds connections open
# and prevents the servers from shutting down
@pytest.fixture(scope="module")
def warcprox_(request, http_daemon, https_daemon):
    orig_dir = os.getcwd()
    work_dir = tempfile.mkdtemp()
    logging.info('changing to working directory %r', work_dir)
    os.chdir(work_dir)

    # we can't wait around all day in the tests
    warcprox.BaseBatchPostfetchProcessor.MAX_BATCH_SEC = 0.5

    argv = ['warcprox',
            '--method-filter=GET',
            '--method-filter=POST',
            '--port=0',
            '--playback-port=0',
            '--onion-tor-socks-proxy=localhost:9050',
            '--crawl-log-dir=crawl-logs',
            '--socket-timeout=4',
            '--max-resource-size=200000',
            '--dedup-min-text-size=3',
            '--dedup-min-binary-size=5']
    if request.config.getoption('--rethinkdb-dedup-url'):
        argv.append('--rethinkdb-dedup-url=%s' % request.config.getoption('--rethinkdb-dedup-url'))
        # test these here only
        argv.append('--rethinkdb-stats-url=rethinkdb://localhost/test0/stats')
        argv.append('--rethinkdb-services-url=rethinkdb://localhost/test0/services')
    elif request.config.getoption('--rethinkdb-big-table-url'):
        argv.append('--rethinkdb-big-table-url=%s' % request.config.getoption('--rethinkdb-big-table-url'))
    elif request.config.getoption('--rethinkdb-trough-db-url'):
        argv.append('--rethinkdb-trough-db-url=%s' % request.config.getoption('--rethinkdb-trough-db-url'))

    args = warcprox.main.parse_args(argv)

    options = warcprox.Options(**vars(args))
    warcprox_ = warcprox.controller.WarcproxController(options)

    logging.info('starting warcprox')
    warcprox_.start()
    warcprox_thread = threading.Thread(
            name='WarcproxThread', target=warcprox_.run_until_shutdown)
    warcprox_thread.start()

    def fin():
        warcprox_.stop.set()
        warcprox_thread.join()
        for rethinkdb_url in (
                warcprox_.options.rethinkdb_big_table_url,
                warcprox_.options.rethinkdb_dedup_url,
                warcprox_.options.rethinkdb_services_url,
                warcprox_.options.rethinkdb_stats_url):
            if not rethinkdb_url:
                continue
            parsed = doublethink.parse_rethinkdb_url(rethinkdb_url)
            rr = doublethink.Rethinker(servers=parsed.hosts)
            try:
                logging.info('dropping rethinkdb database %r', parsed.database)
                rr.db_drop(parsed.database).run()
            except Exception as e:
                logging.warning(
                        'problem deleting rethinkdb database %r: %s',
                        parsed.database, e)
        logging.info('deleting working directory %r', work_dir)
        os.chdir(orig_dir)
        shutil.rmtree(work_dir)

    request.addfinalizer(fin)

    return warcprox_

@pytest.fixture(scope="module")
def archiving_proxies(warcprox_):
    archiving_proxy = 'http://localhost:{}'.format(warcprox_.proxy.server_port)
    return {'http':archiving_proxy, 'https':archiving_proxy}

@pytest.fixture(scope="module")
def playback_proxies(warcprox_):
    playback_proxy = 'http://localhost:{}'.format(warcprox_.playback_proxy.server_port)
    return {'http':playback_proxy, 'https':playback_proxy}

def test_httpds_no_proxy(http_daemon, https_daemon):
    url = 'http://localhost:{}/'.format(http_daemon.server_port)
    response = requests.get(url)
    assert response.status_code == 404
    assert response.content == b'404 Not Found\n'

    url = 'https://localhost:{}/'.format(https_daemon.server_port)
    response = requests.get(url, verify=False)
    assert response.status_code == 404
    assert response.content == b'404 Not Found\n'

    url = 'http://localhost:{}/a/b'.format(http_daemon.server_port)
    response = requests.get(url)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'a!'
    assert response.content == b'I am the warcprox test payload! bbbbbbbbbb!\n'

    url = 'https://localhost:{}/c/d'.format(https_daemon.server_port)
    response = requests.get(url, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'c!'
    assert response.content == b'I am the warcprox test payload! dddddddddd!\n'

    # ensure monkey-patched dns resolution is working
    url = 'https://foo.bar.localhost:{}/c/d'.format(https_daemon.server_port)
    response = requests.get(url, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'c!'
    assert response.content == b'I am the warcprox test payload! dddddddddd!\n'

def test_archive_and_playback_http_url(http_daemon, archiving_proxies, playback_proxies, warcprox_):
    urls_before = warcprox_.proxy.running_stats.urls

    url = 'http://localhost:{}/a/b'.format(http_daemon.server_port)

    # ensure playback fails before archiving
    response = requests.get(url, proxies=playback_proxies)
    assert response.status_code == 404
    assert response.content == b'404 Not in Archive\n'

    # archive
    response = requests.get(url, proxies=archiving_proxies)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'a!'
    assert response.content == b'I am the warcprox test payload! bbbbbbbbbb!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    response = requests.get(url, proxies=playback_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'a!'
    assert response.content == b'I am the warcprox test payload! bbbbbbbbbb!\n'

def test_archive_and_playback_https_url(https_daemon, archiving_proxies, playback_proxies, warcprox_):
    urls_before = warcprox_.proxy.running_stats.urls

    url = 'https://localhost:{}/c/d'.format(https_daemon.server_port)

    # ensure playback fails before archiving
    response = requests.get(url, proxies=playback_proxies, verify=False)
    assert response.status_code == 404
    assert response.content == b'404 Not in Archive\n'

    # fetch & archive response
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'c!'
    assert response.content == b'I am the warcprox test payload! dddddddddd!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    # test playback
    response = requests.get(url, proxies=playback_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'c!'
    assert response.content == b'I am the warcprox test payload! dddddddddd!\n'

# test dedup of same http url with same payload
def test_dedup_http(http_daemon, warcprox_, archiving_proxies, playback_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    url = 'http://localhost:{}/e/f'.format(http_daemon.server_port)

    # ensure playback fails before archiving
    response = requests.get(url, proxies=playback_proxies, verify=False)
    assert response.status_code == 404
    assert response.content == b'404 Not in Archive\n'

    # check not in dedup db
    dedup_lookup = warcprox_.dedup_db.lookup(
        b'sha1:65e1216acfd220f0292715e74bd7a1ec35c99dfc')
    assert dedup_lookup is None

    # archive
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'e!'
    assert response.content == b'I am the warcprox test payload! ffffffffff!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)
    # test playback
    response = requests.get(url, proxies=playback_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'e!'
    assert response.content == b'I am the warcprox test payload! ffffffffff!\n'

    # check in dedup db
    # {u'id': u'<urn:uuid:e691dc0f-4bb9-4ad8-9afb-2af836aa05e4>', u'url': u'https://localhost:62841/c/d', u'date': u'2013-11-22T00:14:37Z'}
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:65e1216acfd220f0292715e74bd7a1ec35c99dfc')
    assert dedup_lookup
    assert dedup_lookup['url'] == url.encode('ascii')
    assert re.match(br'^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$', dedup_lookup['id'])
    assert re.match(br'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', dedup_lookup['date'])
    record_id = dedup_lookup['id']
    dedup_date = dedup_lookup['date']

    # need revisit to have a later timestamp than original, else playing
    # back the latest record might not hit the revisit
    time.sleep(1.1)

    # fetch & archive revisit
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'e!'
    assert response.content == b'I am the warcprox test payload! ffffffffff!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 2)

    # check in dedup db (no change from prev)
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:65e1216acfd220f0292715e74bd7a1ec35c99dfc')
    assert dedup_lookup['url'] == url.encode('ascii')
    assert dedup_lookup['id'] == record_id
    assert dedup_lookup['date'] == dedup_date

    # test playback
    logging.debug('testing playback of revisit of {}'.format(url))
    response = requests.get(url, proxies=playback_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'e!'
    assert response.content == b'I am the warcprox test payload! ffffffffff!\n'
    # XXX how to check dedup was used?

# test dedup of same https url with same payload
def test_dedup_https(https_daemon, warcprox_, archiving_proxies, playback_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    url = 'https://localhost:{}/g/h'.format(https_daemon.server_port)

    # ensure playback fails before archiving
    response = requests.get(url, proxies=playback_proxies, verify=False)
    assert response.status_code == 404
    assert response.content == b'404 Not in Archive\n'

    # check not in dedup db
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:5b4efa64fdb308ec06ae56a9beba155a6f734b89')
    assert dedup_lookup is None

    # archive
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'g!'
    assert response.content == b'I am the warcprox test payload! hhhhhhhhhh!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    # test playback
    response = requests.get(url, proxies=playback_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'g!'
    assert response.content == b'I am the warcprox test payload! hhhhhhhhhh!\n'

    # check in dedup db
    # {u'id': u'<urn:uuid:e691dc0f-4bb9-4ad8-9afb-2af836aa05e4>', u'url': u'https://localhost:62841/c/d', u'date': u'2013-11-22T00:14:37Z'}
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:5b4efa64fdb308ec06ae56a9beba155a6f734b89')
    assert dedup_lookup
    assert dedup_lookup['url'] == url.encode('ascii')
    assert re.match(br'^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$', dedup_lookup['id'])
    assert re.match(br'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', dedup_lookup['date'])
    record_id = dedup_lookup['id']
    dedup_date = dedup_lookup['date']

    # need revisit to have a later timestamp than original, else playing
    # back the latest record might not hit the revisit
    time.sleep(1.1)

    # fetch & archive revisit
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'g!'
    assert response.content == b'I am the warcprox test payload! hhhhhhhhhh!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 2)

    # check in dedup db (no change from prev)
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:5b4efa64fdb308ec06ae56a9beba155a6f734b89')
    assert dedup_lookup['url'] == url.encode('ascii')
    assert dedup_lookup['id'] == record_id
    assert dedup_lookup['date'] == dedup_date

    # test playback
    logging.debug('testing playback of revisit of {}'.format(url))
    response = requests.get(url, proxies=playback_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'g!'
    assert response.content == b'I am the warcprox test payload! hhhhhhhhhh!\n'
    # XXX how to check dedup was used?

def test_limits(http_daemon, warcprox_, archiving_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    url = 'http://localhost:{}/i/j'.format(http_daemon.server_port)
    request_meta = {"stats":{"buckets":["test_limits_bucket"]},"limits":{"test_limits_bucket/total/urls":10}}
    headers = {"Warcprox-Meta": json.dumps(request_meta)}

    response = requests.get(url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'i!'
    assert response.content == b'I am the warcprox test payload! jjjjjjjjjj!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    for i in range(9):
        response = requests.get(url, proxies=archiving_proxies, headers=headers, stream=True)
        assert response.status_code == 200
        assert response.headers['warcprox-test-header'] == 'i!'
        assert response.content == b'I am the warcprox test payload! jjjjjjjjjj!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 10)

    # next fetch hits the limit
    response = requests.get(url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 420
    assert response.reason == "Reached limit"
    expected_response_meta = {'reached-limit': {'test_limits_bucket/total/urls': 10}, 'stats': {'test_limits_bucket': {'bucket': 'test_limits_bucket', 'revisit': {'wire_bytes': 1215, 'urls': 9}, 'total': {'wire_bytes': 1350, 'urls': 10}, 'new': {'wire_bytes': 135, 'urls': 1}}}}
    assert json.loads(response.headers["warcprox-meta"]) == expected_response_meta
    assert response.headers["content-type"] == "text/plain;charset=utf-8"
    assert response.content == b"request rejected by warcprox: reached limit test_limits_bucket/total/urls=10\n"

    # limits should apply to WARCPROX_WRITE_RECORD requests
    payload = b'I am the WARCPROX_WRITE_RECORD payload'
    wwr_headers = {
        'Content-Type': 'text/plain',
        'WARC-Type': 'metadata',
        'Host': 'N/A'
    }
    wwr_headers.update(headers)
    response = requests.request(
            method='WARCPROX_WRITE_RECORD', url='http://fakeurl/',
            data=payload, headers=wwr_headers, proxies=archiving_proxies)
    assert response.status_code == 420
    assert response.reason == "Reached limit"
    expected_response_meta = {'reached-limit': {'test_limits_bucket/total/urls': 10}, 'stats': {'test_limits_bucket': {'bucket': 'test_limits_bucket', 'revisit': {'wire_bytes': 1215, 'urls': 9}, 'total': {'wire_bytes': 1350, 'urls': 10}, 'new': {'wire_bytes': 135, 'urls': 1}}}}
    assert json.loads(response.headers["warcprox-meta"]) == expected_response_meta
    assert response.headers["content-type"] == "text/plain;charset=utf-8"
    assert response.content == b"request rejected by warcprox: reached limit test_limits_bucket/total/urls=10\n"

    # make sure limit doesn't get applied to a different stats bucket
    request_meta = {"stats":{"buckets":["no_limits_bucket"]},"limits":{"test_limits_bucket/total/urls":10}}
    headers = {"Warcprox-Meta": json.dumps(request_meta)}
    response = requests.get(url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'i!'
    assert response.content == b'I am the warcprox test payload! jjjjjjjjjj!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 11)

def test_return_capture_timestamp(http_daemon, warcprox_, archiving_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    url = 'http://localhost:{}/i/j'.format(http_daemon.server_port)
    request_meta = {"accept": ["capture-metadata"]}
    headers = {"Warcprox-Meta": json.dumps(request_meta)}
    response = requests.get(url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 200
    assert response.headers['Warcprox-Meta']
    response_meta = json.loads(response.headers['Warcprox-Meta'])
    assert response_meta['capture-metadata']
    try:
        dt = datetime.datetime.strptime(response_meta['capture-metadata']['timestamp'],
                                        '%Y-%m-%dT%H:%M:%SZ')
        assert dt
    except ValueError:
        pytest.fail(
                'Invalid http response warcprox-meta["capture-metadata"]["timestamp"]: %r',
                meta['capture-metadata']['timestamp'])

    # wait for postfetch chain (or subsequent test could fail)
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

def test_dedup_buckets(https_daemon, http_daemon, warcprox_, archiving_proxies, playback_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    url1 = 'http://localhost:{}/k/l'.format(http_daemon.server_port)
    url2 = 'https://localhost:{}/k/l'.format(https_daemon.server_port)

    # archive url1 bucket_a
    headers = {"Warcprox-Meta": json.dumps({"warc-prefix":"test_dedup_buckets","dedup-buckets":{"bucket_a":"rw"}})}
    response = requests.get(url1, proxies=archiving_proxies, verify=False, headers=headers)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'k!'
    assert response.content == b'I am the warcprox test payload! llllllllll!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    # check url1 in dedup db bucket_a
    # logging.info('looking up sha1:bc3fac8847c9412f49d955e626fb58a76befbf81 in bucket_a')
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:bc3fac8847c9412f49d955e626fb58a76befbf81', bucket="bucket_a")
    assert dedup_lookup
    assert dedup_lookup['url'] == url1.encode('ascii')
    assert re.match(br'^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$', dedup_lookup['id'])
    assert re.match(br'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', dedup_lookup['date'])
    record_id = dedup_lookup['id']
    dedup_date = dedup_lookup['date']

    # check url1 not in dedup db bucket_b
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:bc3fac8847c9412f49d955e626fb58a76befbf81', bucket="bucket_b")
    assert dedup_lookup is None

    # archive url2 bucket_b
    headers = {"Warcprox-Meta": json.dumps({"warc-prefix":"test_dedup_buckets","dedup-buckets":{"bucket_b":""}})}
    response = requests.get(url2, proxies=archiving_proxies, verify=False, headers=headers)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'k!'
    assert response.content == b'I am the warcprox test payload! llllllllll!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 2)

    # check url2 in dedup db bucket_b
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:bc3fac8847c9412f49d955e626fb58a76befbf81', bucket="bucket_b")
    assert dedup_lookup['url'] == url2.encode('ascii')
    assert re.match(br'^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$', dedup_lookup['id'])
    assert re.match(br'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', dedup_lookup['date'])
    record_id = dedup_lookup['id']
    dedup_date = dedup_lookup['date']

    # archive url2 bucket_a
    headers = {"Warcprox-Meta": json.dumps({"warc-prefix":"test_dedup_buckets","captures-bucket":"bucket_a"})}
    response = requests.get(url2, proxies=archiving_proxies, verify=False, headers=headers)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'k!'
    assert response.content == b'I am the warcprox test payload! llllllllll!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 3)

    # archive url1 bucket_b
    headers = {"Warcprox-Meta": json.dumps({"warc-prefix":"test_dedup_buckets","dedup-bucket":"bucket_b"})}
    response = requests.get(url1, proxies=archiving_proxies, verify=False, headers=headers)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'k!'
    assert response.content == b'I am the warcprox test payload! llllllllll!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 4)

    # close the warc
    assert warcprox_.warc_writer_processor.writer_pool.warc_writers["test_dedup_buckets"]
    writer = warcprox_.warc_writer_processor.writer_pool.warc_writers["test_dedup_buckets"]
    warc_path = os.path.join(writer.directory, writer.finalname)
    assert not os.path.exists(warc_path)
    warcprox_.warc_writer_processor.writer_pool.warc_writers["test_dedup_buckets"].close()
    assert os.path.exists(warc_path)

    # read the warc
    fh = warctools.ArchiveRecord.open_archive(warc_path)
    record_iter = fh.read_records(limit=None, offsets=True)
    try:
        (offset, record, errors) = next(record_iter)
        assert record.type == b'warcinfo'

        # url1 bucket_a
        (offset, record, errors) = next(record_iter)
        assert record.type == b'response'
        assert record.url == url1.encode('ascii')
        # check for duplicate warc record headers
        assert Counter(h[0] for h in record.headers).most_common(1)[0][1] == 1
        assert record.content[1] == b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nwarcprox-test-header: k!\r\nContent-Length: 44\r\n\r\nI am the warcprox test payload! llllllllll!\n'
        (offset, record, errors) = next(record_iter)
        assert record.type == b'request'

        # url2 bucket_b
        (offset, record, errors) = next(record_iter)
        assert record.type == b'response'
        assert record.url == url2.encode('ascii')
        # check for duplicate warc record headers
        assert Counter(h[0] for h in record.headers).most_common(1)[0][1] == 1
        assert record.content[1] == b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nwarcprox-test-header: k!\r\nContent-Length: 44\r\n\r\nI am the warcprox test payload! llllllllll!\n'
        (offset, record, errors) = next(record_iter)
        assert record.type == b'request'

        # url2 bucket_a (revisit)
        (offset, record, errors) = next(record_iter)
        assert record.type == b'revisit'
        assert record.url == url2.encode('ascii')
        # check for duplicate warc record headers
        assert Counter(h[0] for h in record.headers).most_common(1)[0][1] == 1
        assert record.content[1] == b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nwarcprox-test-header: k!\r\nContent-Length: 44\r\n\r\n'
        (offset, record, errors) = next(record_iter)
        assert record.type == b'request'

        # url1 bucket_b (revisit)
        (offset, record, errors) = next(record_iter)
        assert record.type == b'revisit'
        assert record.url == url1.encode('ascii')
        # check for duplicate warc record headers
        assert Counter(h[0] for h in record.headers).most_common(1)[0][1] == 1
        assert record.content[1] == b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nwarcprox-test-header: k!\r\nContent-Length: 44\r\n\r\n'
        (offset, record, errors) = next(record_iter)
        assert record.type == b'request'

        # that's all folks
        assert next(record_iter)[1] == None
        assert next(record_iter, None) == None

    finally:
        fh.close()

def test_dedup_buckets_readonly(https_daemon, http_daemon, warcprox_, archiving_proxies, playback_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    url1 = 'http://localhost:{}/k/l'.format(http_daemon.server_port)

    # archive url1
    headers = {"Warcprox-Meta": json.dumps({"warc-prefix":"test_dedup_buckets_readonly",
                                            "dedup-buckets":{"bucket_1":"rw", "bucket_2":"ro"}})
              }
    response = requests.get(url1, proxies=archiving_proxies, verify=False, headers=headers)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'k!'
    assert response.content == b'I am the warcprox test payload! llllllllll!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    # check url1 in dedup db bucket_1 (rw)
    # logging.info('looking up sha1:bc3fac8847c9412f49d955e626fb58a76befbf81 in bucket_1')
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:bc3fac8847c9412f49d955e626fb58a76befbf81', bucket="bucket_1")
    assert dedup_lookup
    assert dedup_lookup['url'] == url1.encode('ascii')
    assert re.match(br'^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$', dedup_lookup['id'])
    assert re.match(br'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', dedup_lookup['date'])
    record_id = dedup_lookup['id']
    dedup_date = dedup_lookup['date']

    # check url1 not in dedup db bucket_2 (ro)
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:bc3fac8847c9412f49d955e626fb58a76befbf81', bucket="bucket_2")
    assert dedup_lookup is None

    # close the warc
    assert warcprox_.warc_writer_processor.writer_pool.warc_writers["test_dedup_buckets_readonly"]
    writer = warcprox_.warc_writer_processor.writer_pool.warc_writers["test_dedup_buckets_readonly"]
    warc_path = os.path.join(writer.directory, writer.finalname)
    assert not os.path.exists(warc_path)
    warcprox_.warc_writer_processor.writer_pool.warc_writers["test_dedup_buckets_readonly"].close()
    assert os.path.exists(warc_path)

    # read the warc
    fh = warctools.ArchiveRecord.open_archive(warc_path)
    record_iter = fh.read_records(limit=None, offsets=True)
    try:
        (offset, record, errors) = next(record_iter)
        assert record.type == b'warcinfo'

        # url1 bucket_1
        (offset, record, errors) = next(record_iter)
        assert record.type == b'response'
        assert record.url == url1.encode('ascii')
        # check for duplicate warc record headers
        assert Counter(h[0] for h in record.headers).most_common(1)[0][1] == 1
        assert record.content[1] == b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nwarcprox-test-header: k!\r\nContent-Length: 44\r\n\r\nI am the warcprox test payload! llllllllll!\n'
        (offset, record, errors) = next(record_iter)
        assert record.type == b'request'

        # that's all folks
        assert next(record_iter)[1] == None
        assert next(record_iter, None) == None

    finally:
        fh.close()

def test_dedup_bucket_concurrency(https_daemon, http_daemon, warcprox_, archiving_proxies):
    urls_before = warcprox_.proxy.running_stats.urls
    revisits_before = warcprox_.proxy.stats_db.value(
            '__all__', 'revisit', 'urls') or 0

    # fire off 20 initial requests simultaneously-ish
    with futures.ThreadPoolExecutor(max_workers=20) as pool:
        for i in range(20):
            url = 'http://localhost:{}/test_dedup_bucket_concurrency/{}'.format(
                    http_daemon.server_port, i)
            headers = {"Warcprox-Meta": json.dumps({
                "warc-prefix":"test_dedup_buckets",
                "dedup-buckets":{"bucket_%s" % i:"rw"}})}
            pool.submit(
                    requests.get, url, proxies=archiving_proxies, verify=False,
                    headers=headers)

    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 20)
    assert warcprox_.proxy.stats_db.value('__all__', 'revisit', 'urls') == revisits_before

    # fire off 20 requests to the same urls but different buckets
    # none should be deduped
    with futures.ThreadPoolExecutor(max_workers=20) as pool:
        for i in range(20):
            url = 'http://localhost:{}/test_dedup_bucket_concurrency/{}'.format(
                    http_daemon.server_port, -i - 1)
            headers = {"Warcprox-Meta": json.dumps({
                "warc-prefix":"test_dedup_buckets",
                "dedup-buckets":{"bucket_%s" % i:"rw"}})}
            pool.submit(
                    requests.get, url, proxies=archiving_proxies, verify=False,
                    headers=headers)

    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 40)
    assert warcprox_.proxy.stats_db.value('__all__', 'revisit', 'urls') == revisits_before

    # fire off 20 requests same as the initial requests, all should be deduped
    with futures.ThreadPoolExecutor(max_workers=20) as pool:
        for i in range(20):
            url = 'http://localhost:{}/test_dedup_bucket_concurrency/{}'.format(
                    http_daemon.server_port, i)
            headers = {"Warcprox-Meta": json.dumps({
                "warc-prefix":"test_dedup_buckets",
                "dedup-buckets":{"bucket_%s" % i:"rw"}})}
            pool.submit(
                    requests.get, url, proxies=archiving_proxies, verify=False,
                    headers=headers)

    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 60)
    assert warcprox_.proxy.stats_db.value('__all__', 'revisit', 'urls') == revisits_before + 20

def test_block_rules(http_daemon, https_daemon, warcprox_, archiving_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    rules = [
        {
            "domain": "localhost",
            "url_match": "STRING_MATCH",
            "value": "bar",
        },
        {
            "url_match": "SURT_MATCH",
            "value": "http://(localhost,:%s)/fuh/" % (http_daemon.server_port),
        },
        {
            "url_match": "SURT_MATCH",
            # this rule won't match because of http scheme, https port
            "value": "http://(localhost,:%s)/fuh/" % (https_daemon.server_port),
        },
        {
            "domain": "bad.domain.com",
        },
    ]
    request_meta = {"blocks":rules}
    headers = {"Warcprox-Meta":json.dumps(request_meta)}

    # blocked by STRING_MATCH rule
    url = 'http://localhost:{}/bar'.format(http_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 403
    assert response.content.startswith(b"request rejected by warcprox: blocked by rule found in Warcprox-Meta header:")
    assert json.loads(response.headers['warcprox-meta']) == {"blocked-by-rule":rules[0]}

    # not blocked
    url = 'http://localhost:{}/m/n'.format(http_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 200

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    # blocked by SURT_MATCH
    url = 'http://localhost:{}/fuh/guh'.format(http_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 403
    assert response.content.startswith(b"request rejected by warcprox: blocked by rule found in Warcprox-Meta header:")
    assert json.loads(response.headers['warcprox-meta']) == {"blocked-by-rule":rules[1]}

    # not blocked (no trailing slash)
    url = 'http://localhost:{}/fuh'.format(http_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    # 404 because server set up at the top of this file doesn't handle this url
    assert response.status_code == 404

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 2)

    # not blocked because surt scheme does not match (differs from heritrix
    # behavior where https urls are coerced to http surt form)
    url = 'https://localhost:{}/fuh/guh'.format(https_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True,
            verify=False)
    assert response.status_code == 200

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 3)

    # blocked by blanket domain block
    url = 'http://bad.domain.com/'
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 403
    assert response.content.startswith(b"request rejected by warcprox: blocked by rule found in Warcprox-Meta header:")
    assert json.loads(response.headers['warcprox-meta']) == {"blocked-by-rule":rules[3]}

    # blocked by blanket domain block
    url = 'https://bad.domain.com/'
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True,
            verify=False)
    assert response.status_code == 403
    assert response.content.startswith(b"request rejected by warcprox: blocked by rule found in Warcprox-Meta header:")
    assert json.loads(response.headers['warcprox-meta']) == {"blocked-by-rule":rules[3]}

    # blocked by blanket domain block
    url = 'http://bad.domain.com:1234/'
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 403
    assert response.content.startswith(b"request rejected by warcprox: blocked by rule found in Warcprox-Meta header:")
    assert json.loads(response.headers['warcprox-meta']) == {"blocked-by-rule":rules[3]}

    # blocked by blanket domain block
    url = 'http://foo.bar.bad.domain.com/'
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 403
    assert response.content.startswith(b"request rejected by warcprox: blocked by rule found in Warcprox-Meta header:")
    assert json.loads(response.headers['warcprox-meta']) == {"blocked-by-rule":rules[3]}

    # domain block also applies to subdomains
    url = 'https://foo.bar.bad.domain.com/'
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True,
            verify=False)
    assert response.status_code == 403
    assert response.content.startswith(b"request rejected by warcprox: blocked by rule found in Warcprox-Meta header:")
    assert json.loads(response.headers['warcprox-meta']) == {"blocked-by-rule":rules[3]}

    # blocked by blanket domain block
    url = 'http://foo.bar.bad.domain.com:1234/'
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 403
    assert response.content.startswith(b"request rejected by warcprox: blocked by rule found in Warcprox-Meta header:")
    assert json.loads(response.headers['warcprox-meta']) == {"blocked-by-rule":rules[3]}

def test_domain_doc_soft_limit(
        http_daemon, https_daemon, warcprox_, archiving_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    # ** comment is obsolete (server is multithreaded) but still useful **
    # we need to clear the connection pool here because
    # - connection pool already may already have an open connection localhost
    # - we're about to make a connection to foo.localhost
    # - but our test server, which handles all the hosts, is single threaded
    # - so it will fail to connect (socket timeout)
    # must close connections before each connection to a different hostname
    warcprox_.proxy.remote_connection_pool.clear()

    request_meta = {
        "stats": {"buckets": [{"bucket":"test_domain_doc_limit_bucket","tally-domains":["foo.localhost"]}]},
        "soft-limits": {"test_domain_doc_limit_bucket:foo.localhost/total/urls":10},
    }
    headers = {"Warcprox-Meta": json.dumps(request_meta)}

    # (1)
    url = 'http://foo.localhost:{}/o/p'.format(http_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'o!'
    assert response.content == b'I am the warcprox test payload! pppppppppp!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    warcprox_.proxy.remote_connection_pool.clear()

    # make sure stats from different domain don't count
    url = 'http://bar.localhost:{}/o/p'.format(http_daemon.server_port)
    for i in range(10):
        response = requests.get(
                url, proxies=archiving_proxies, headers=headers, stream=True)
        assert response.status_code == 200
        assert response.headers['warcprox-test-header'] == 'o!'
        assert response.content == b'I am the warcprox test payload! pppppppppp!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 11)

    warcprox_.proxy.remote_connection_pool.clear()

    # (2) same host but different scheme and port: domain limit applies
    url = 'https://foo.localhost:{}/o/p'.format(https_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True,
            verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'o!'
    assert response.content == b'I am the warcprox test payload! pppppppppp!\n'

    warcprox_.proxy.remote_connection_pool.clear()

    # (3-9) different subdomain: host limit applies
    url = 'https://baz.foo.localhost:{}/o/p'.format(https_daemon.server_port)
    for i in range(7):
        response = requests.get(
                url, proxies=archiving_proxies, headers=headers, stream=True,
                verify=False)
        assert response.status_code == 200
        assert response.headers['warcprox-test-header'] == 'o!'
        assert response.content == b'I am the warcprox test payload! pppppppppp!\n'

    # wait for postfetch chain
    time.sleep(3)
    logging.info(
        'warcprox_.proxy.running_stats.urls - urls_before = %s',
        warcprox_.proxy.running_stats.urls - urls_before)
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 19)

    # (10)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True,
            verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'o!'
    assert response.content == b'I am the warcprox test payload! pppppppppp!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 20)

    warcprox_.proxy.remote_connection_pool.clear()

    # (11) back to http, and this is the 11th request
    url = 'http://zuh.foo.localhost:{}/o/p'.format(http_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 430
    assert response.reason == "Reached soft limit"
    expected_response_meta = {'reached-soft-limit': {'test_domain_doc_limit_bucket:foo.localhost/total/urls': 10}, 'stats': {'test_domain_doc_limit_bucket:foo.localhost': {'bucket': 'test_domain_doc_limit_bucket:foo.localhost', 'revisit': {'wire_bytes': 1215, 'urls': 9}, 'new': {'wire_bytes': 135, 'urls': 1}, 'total': {'wire_bytes': 1350, 'urls': 10}}}}
    assert json.loads(response.headers["warcprox-meta"]) == expected_response_meta
    assert response.headers["content-type"] == "text/plain;charset=utf-8"
    assert response.content == b"request rejected by warcprox: reached soft limit test_domain_doc_limit_bucket:foo.localhost/total/urls=10\n"

    warcprox_.proxy.remote_connection_pool.clear()

    # make sure limit doesn't get applied to a different domain
    url = 'https://localhost:{}/o/p'.format(https_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True,
            verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'o!'
    assert response.content == b'I am the warcprox test payload! pppppppppp!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 21)

    warcprox_.proxy.remote_connection_pool.clear()

    # https also blocked
    url = 'https://zuh.foo.localhost:{}/o/p'.format(https_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True,
            verify=False)
    assert response.status_code == 430
    assert response.reason == "Reached soft limit"
    expected_response_meta = {'reached-soft-limit': {'test_domain_doc_limit_bucket:foo.localhost/total/urls': 10}, 'stats': {'test_domain_doc_limit_bucket:foo.localhost': {'bucket': 'test_domain_doc_limit_bucket:foo.localhost', 'revisit': {'wire_bytes': 1215, 'urls': 9}, 'new': {'wire_bytes': 135, 'urls': 1}, 'total': {'wire_bytes': 1350, 'urls': 10}}}}
    assert json.loads(response.headers["warcprox-meta"]) == expected_response_meta
    assert response.headers["content-type"] == "text/plain;charset=utf-8"
    assert response.content == b"request rejected by warcprox: reached soft limit test_domain_doc_limit_bucket:foo.localhost/total/urls=10\n"

    warcprox_.proxy.remote_connection_pool.clear()

    # same host, different capitalization still blocked
    url = 'https://HEHEHE.fOO.lOcALhoST:{}/o/p'.format(https_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True,
            verify=False)
    assert response.status_code == 430
    assert response.reason == "Reached soft limit"
    expected_response_meta = {'reached-soft-limit': {'test_domain_doc_limit_bucket:foo.localhost/total/urls': 10}, 'stats': {'test_domain_doc_limit_bucket:foo.localhost': {'bucket': 'test_domain_doc_limit_bucket:foo.localhost', 'revisit': {'wire_bytes': 1215, 'urls': 9}, 'new': {'wire_bytes': 135, 'urls': 1}, 'total': {'wire_bytes': 1350, 'urls': 10}}}}
    assert json.loads(response.headers["warcprox-meta"]) == expected_response_meta
    assert response.headers["content-type"] == "text/plain;charset=utf-8"
    assert response.content == b"request rejected by warcprox: reached soft limit test_domain_doc_limit_bucket:foo.localhost/total/urls=10\n"

    # make sure soft limit doesn't get applied to a different stats bucket
    request_meta = {
        "stats": {"buckets": [{"bucket":"no_limit_bucket","tally-domains":["foo.localhost"]}]},
        "soft-limits": {"test_domain_doc_limit_bucket:foo.localhost/total/urls":10},
    }
    headers = {"Warcprox-Meta": json.dumps(request_meta)}
    url = 'http://zuh.foo.localhost:{}/o/p'.format(http_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True,
            verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'o!'
    assert response.content == b'I am the warcprox test payload! pppppppppp!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 22)

def test_domain_data_soft_limit(
        http_daemon, https_daemon, warcprox_, archiving_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    # using idn
    request_meta = {
        "stats": {"buckets": [{"bucket":"test_domain_data_limit_bucket","tally-domains":['ÞzZ.LOCALhost']}]},
        # response is 135 bytes, so 3rd novel url should be disallowed
        "soft-limits": {"test_domain_data_limit_bucket:ÞZZ.localhost/new/wire_bytes":200},
    }
    headers = {"Warcprox-Meta": json.dumps(request_meta)}

    warcprox_.proxy.remote_connection_pool.clear()

    url = 'http://ÞZz.localhost:{}/y/z'.format(http_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'y!'
    assert response.content == b'I am the warcprox test payload! zzzzzzzzzz!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    warcprox_.proxy.remote_connection_pool.clear()

    # duplicate, does not count toward limit
    url = 'https://baz.Þzz.localhost:{}/y/z'.format(https_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True,
            verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'y!'
    assert response.content == b'I am the warcprox test payload! zzzzzzzzzz!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 2)

    warcprox_.proxy.remote_connection_pool.clear()

    # novel, pushes stats over the limit
    url = 'https://muh.XN--Zz-2Ka.locALHOst:{}/z/%7E'.format(https_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True,
            verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'z!'
    assert response.content == b'I am the warcprox test payload! ~~~~~~~~~~!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 3)

    warcprox_.proxy.remote_connection_pool.clear()

    # make sure limit doesn't get applied to a different host
    url = 'http://baz.localhost:{}/z/~'.format(http_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'z!'
    assert response.content == b'I am the warcprox test payload! ~~~~~~~~~~!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 4)

    warcprox_.proxy.remote_connection_pool.clear()

    # blocked because we're over the limit now
    url = 'http://lOl.wHut.ÞZZ.lOcALHOst:{}/y/z'.format(http_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 430
    assert response.reason == "Reached soft limit"
    expected_response_meta = {'reached-soft-limit': {'test_domain_data_limit_bucket:xn--zz-2ka.localhost/new/wire_bytes': 200}, 'stats': {'test_domain_data_limit_bucket:xn--zz-2ka.localhost': {'total': {'wire_bytes': 405, 'urls': 3}, 'revisit': {'wire_bytes': 135, 'urls': 1}, 'new': {'wire_bytes': 270, 'urls': 2}, 'bucket': 'test_domain_data_limit_bucket:xn--zz-2ka.localhost'}}}
    assert json.loads(response.headers["warcprox-meta"]) == expected_response_meta
    assert response.headers["content-type"] == "text/plain;charset=utf-8"
    assert response.content == b"request rejected by warcprox: reached soft limit test_domain_data_limit_bucket:xn--zz-2ka.localhost/new/wire_bytes=200\n"

    # XXX this check is resulting in a segfault on mac and linux, from ssl I
    # think, probably because of the dns resolution monkey-patching
    # https://travis-ci.org/internetarchive/warcprox/builds/141187342
    #
    ### # https also blocked
    ### url = 'https://xn--zz-2ka.loCAlhost:{}/w/x'.format(https_daemon.server_port)
    ### response = requests.get(
    ###         url, proxies=archiving_proxies, headers=headers, stream=True,
    ###         verify=False)
    ### assert response.status_code == 430
    ### assert response.reason == "Reached soft limit"
    ### expected_response_meta = {'reached-soft-limit': {'test_domain_data_limit_bucket:xn--zz-2ka.localhost/new/wire_bytes': 200}, 'stats': {'test_domain_data_limit_bucket:xn--zz-2ka.localhost': {'total': {'wire_bytes': 405, 'urls': 3}, 'revisit': {'wire_bytes': 135, 'urls': 1}, 'new': {'wire_bytes': 270, 'urls': 2}, 'bucket': 'test_domain_data_limit_bucket:xn--zz-2ka.localhost'}}}
    ### assert json.loads(response.headers["warcprox-meta"]) == expected_response_meta
    ### assert response.headers["content-type"] == "text/plain;charset=utf-8"
    ### assert response.content == b"request rejected by warcprox: reached soft limit test_domain_data_limit_bucket:xn--zz-2ka.localhost/new/wire_bytes=200\n"

    # make sure soft limit doesn't get applied to a different stats bucket
    request_meta = {
        "stats": {"buckets": [{"bucket":"no_limit_bucket","tally-domains":['ÞzZ.LOCALhost']}]},
        "soft-limits": {"test_domain_data_limit_bucket:ÞZZ.localhost/new/wire_bytes":200},
    }
    headers = {"Warcprox-Meta": json.dumps(request_meta)}
    url = 'http://ÞZz.localhost:{}/y/z'.format(http_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'y!'
    assert response.content == b'I am the warcprox test payload! zzzzzzzzzz!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 5)

# XXX this test relies on a tor proxy running at localhost:9050 with a working
# connection to the internet, and relies on a third party site (facebook) being
# up and behaving a certain way
@pytest.mark.xfail
def test_tor_onion(archiving_proxies, warcprox_):
    urls_before = warcprox_.proxy.running_stats.urls

    response = requests.get('http://www.facebookcorewwwi.onion/',
        proxies=archiving_proxies, verify=False, allow_redirects=False)
    assert response.status_code == 302

    response = requests.get('https://www.facebookcorewwwi.onion/',
        proxies=archiving_proxies, verify=False, allow_redirects=False)
    assert response.status_code == 200

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 2)

def test_missing_content_length(archiving_proxies, http_daemon, https_daemon, warcprox_):
    urls_before = warcprox_.proxy.running_stats.urls

    # double-check that our test http server is responding as expected
    url = 'http://localhost:%s/missing-content-length' % (
            http_daemon.server_port)
    response = requests.get(url, verify=False, timeout=10)
    assert response.content == (
            b'This response is missing a Content-Length http header.')
    assert not 'content-length' in response.headers

    # double-check that our test https server is responding as expected
    url = 'https://localhost:%s/missing-content-length' % (
            https_daemon.server_port)
    response = requests.get(url, verify=False, timeout=10)
    assert response.content == (
            b'This response is missing a Content-Length http header.')
    assert not 'content-length' in response.headers

    # now check that the proxy doesn't hang (http)
    url = 'http://localhost:%s/missing-content-length' % (
            http_daemon.server_port)
    response = requests.get(
            url, proxies=archiving_proxies, verify=False, timeout=10)
    assert response.content == (
            b'This response is missing a Content-Length http header.')
    assert not 'content-length' in response.headers

    # now check that the proxy doesn't hang (https)
    url = 'https://localhost:%s/missing-content-length' % (
            https_daemon.server_port)
    # before fixing the issue this tests for, this would fail by raising
    # requests.exceptions.ConnectionError: ... Read timed out
    response = requests.get(
            url, proxies=archiving_proxies, verify=False, timeout=10)
    assert response.content == (
            b'This response is missing a Content-Length http header.')
    assert not 'content-length' in response.headers

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 2, timeout=20)

def test_limit_large_resource(archiving_proxies, http_daemon, warcprox_):
    """We try to load a 300k response but we use --max-resource-size=200000 in
    `warcprox_` so it will be truncated. We expect it to limit the result as
    soon as it passes the 200000 limit. As warcprox read() chunk size is 65536,
    the expected result size is 65536*4=262144.
    """
    urls_before = warcprox_.proxy.running_stats.urls

    # this should be truncated
    url = 'http://localhost:%s/300k-content' % http_daemon.server_port
    response = requests.get(
        url, proxies=archiving_proxies, verify=False, timeout=10)
    assert len(response.content) == 262144

    # test that the connection is cleaned up properly after truncating a
    # response (no hang or timeout)
    url = 'http://localhost:%s/' % http_daemon.server_port
    response = requests.get(
        url, proxies=archiving_proxies, verify=False, timeout=10)
    assert response.status_code == 404
    assert response.content == b'404 Not Found\n'

    # wait for processing of this url to finish so that it doesn't interfere
    # with subsequent tests
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 2)

def test_method_filter(
        warcprox_, https_daemon, http_daemon, archiving_proxies,
        playback_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    # we've configured warcprox with method_filters=['GET','POST'] so HEAD
    # requests should not be archived

    url = 'http://localhost:{}/z/a'.format(http_daemon.server_port)

    response = requests.head(url, proxies=archiving_proxies)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'z!'
    assert response.content == b''

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    response = requests.get(url, proxies=playback_proxies, verify=False)
    assert response.status_code == 404
    assert response.content == b'404 Not in Archive\n'

    # WARCPROX_WRITE_RECORD is exempt from method filter
    url = 'http://fakeurl/'
    payload = b'I am the WARCPROX_WRITE_RECORD payload'
    headers = {
        'Content-Type': 'text/plain',
        'WARC-Type': 'metadata',
        'Host': 'N/A'
    }
    response = requests.request(
            method='WARCPROX_WRITE_RECORD', url=url, data=payload,
            headers=headers, proxies=archiving_proxies)
    assert response.status_code == 204

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 2)

    response = requests.get(url, proxies=playback_proxies, verify=False)
    assert response.status_code == 200
    assert response.content == payload

def test_dedup_ok_flag(
        https_daemon, http_daemon, warcprox_, archiving_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    if not warcprox_.options.rethinkdb_big_table:
        # this feature is n/a unless using rethinkdb big table
        return

    url = 'http://localhost:{}/z/b'.format(http_daemon.server_port)

    # check not in dedup db
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:2d7f13181b90a256ce5e5ebfd6e9c9826ece9079',
            bucket='test_dedup_ok_flag')
    assert dedup_lookup is None

    # archive with dedup_ok:False
    request_meta = {'dedup-buckets':{'test_dedup_ok_flag':''},'dedup-ok':False}
    headers = {'Warcprox-Meta': json.dumps(request_meta)}
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'z!'
    assert response.content == b'I am the warcprox test payload! bbbbbbbbbb!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    # check that dedup db doesn't give us anything for this
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:2d7f13181b90a256ce5e5ebfd6e9c9826ece9079',
            bucket='test_dedup_ok_flag')
    assert dedup_lookup is None

    # archive without dedup_ok:False
    request_meta = {'dedup-buckets':{'test_dedup_ok_flag':''}}
    headers = {'Warcprox-Meta': json.dumps(request_meta)}
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, verify=False)

    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'z!'
    assert response.content == b'I am the warcprox test payload! bbbbbbbbbb!\n'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 2)

    # check that dedup db gives us something for this
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:2d7f13181b90a256ce5e5ebfd6e9c9826ece9079',
            bucket='test_dedup_ok_flag')
    assert dedup_lookup

    # inspect what's in rethinkdb more closely
    rethink_captures = warcprox_.dedup_db.captures_db
    results_iter = rethink_captures.rr.table(rethink_captures.table).get_all(
                ['FV7RGGA3SCRFNTS6L275N2OJQJXM5EDZ', 'response',
                    'test_dedup_ok_flag'], index='sha1_warc_type').order_by(
                            'timestamp').run()
    results = list(results_iter)
    assert len(results) == 2
    assert results[0].get('dedup_ok') == False
    assert not 'dedup_ok' in results[1]
    assert results[0]['url'] == url
    assert results[1]['url'] == url
    assert results[0]['warc_type'] == 'response'
    assert results[1]['warc_type'] == 'response' # not revisit
    assert results[0]['filename'] == results[1]['filename']
    assert results[0]['offset'] < results[1]['offset']

def test_status_api(warcprox_):
    url = 'http://localhost:%s/status' % warcprox_.proxy.server_port
    response = requests.get(url)
    assert response.status_code == 200
    status = json.loads(response.content.decode('ascii'))
    assert set(status.keys()) == {
            'role', 'version', 'host', 'address', 'port', 'pid', 'load',
            'queued_urls', 'queue_max_size', 'seconds_behind', 'threads',
            'rates_5min', 'rates_1min', 'unaccepted_requests', 'rates_15min',
            'active_requests','start_time','urls_processed',
            'warc_bytes_written', 'postfetch_chain',
            'earliest_still_active_fetch_start',}
    assert status['role'] == 'warcprox'
    assert status['version'] == warcprox.__version__
    assert status['port'] == warcprox_.proxy.server_port
    assert status['pid'] == os.getpid()
    assert status['threads'] == warcprox_.proxy.pool._max_workers

def test_svcreg_status(warcprox_):
    if warcprox_.service_registry:
        start = time.time()
        while time.time() - start < 15:
            status = warcprox_.service_registry.available_service('warcprox')
            if status:
                break
            time.sleep(0.5)
        assert status
        assert set(status.keys()) == {
                'id', 'role', 'version', 'host', 'port', 'pid', 'load',
                'queued_urls', 'queue_max_size', 'seconds_behind',
                'first_heartbeat', 'ttl', 'last_heartbeat', 'threads',
                'rates_5min', 'rates_1min', 'unaccepted_requests',
                'rates_15min', 'active_requests','start_time','urls_processed',
                'warc_bytes_written', 'postfetch_chain',
                'earliest_still_active_fetch_start',}
        assert status['id'] == 'warcprox:{}:{}'.format(
                socket.gethostname(), warcprox_.proxy.server_port)
        assert status['role'] == 'warcprox'
        assert status['version'] == warcprox.__version__
        assert status['host'] == socket.gethostname()
        assert status['port'] == warcprox_.proxy.server_port
        assert status['pid'] == os.getpid()
        assert status['threads'] == warcprox_.proxy.pool._max_workers

def test_controller_with_defaults():
    # tests some initialization code that we rarely touch otherwise
    controller = warcprox.controller.WarcproxController()
    assert controller.proxy
    assert not controller.proxy_thread
    assert not controller.playback_proxy
    assert not controller.playback_proxy_thread
    assert controller.proxy.RequestHandlerClass == warcprox.warcproxy.WarcProxyHandler
    assert controller.proxy.ca
    assert controller.proxy.digest_algorithm == 'sha1'
    assert controller.proxy.pool
    assert controller.proxy.recorded_url_q
    assert controller.proxy.server_address == ('127.0.0.1', 8000)
    assert controller.proxy.server_port == 8000
    assert controller.proxy.running_stats
    assert not controller.proxy.stats_db
    wwp = controller.warc_writer_processor
    assert wwp
    assert wwp.inq
    assert wwp.outq
    assert wwp.writer_pool
    assert wwp.writer_pool.default_warc_writer
    assert wwp.writer_pool.default_warc_writer.gzip is False
    assert wwp.writer_pool.default_warc_writer.record_builder
    assert not wwp.writer_pool.default_warc_writer.record_builder.base32
    assert wwp.writer_pool.default_warc_writer.record_builder.digest_algorithm == 'sha1'

class EarlyPlugin(warcprox.BaseStandardPostfetchProcessor):
    CHAIN_POSITION = 'early'
    def _process_url(self):
        pass

def test_load_plugin():
    options = warcprox.Options(port=0, plugins=[
        'warcprox.stats.RunningStats',
        'warcprox.BaseStandardPostfetchProcessor',
        'warcprox.BaseBatchPostfetchProcessor',
        '{}.{}'.format(__name__, EarlyPlugin.__name__),])
    controller = warcprox.controller.WarcproxController(options)
    assert isinstance(
            controller._postfetch_chain[-1],
            warcprox.ListenerPostfetchProcessor)
    assert isinstance(
            controller._postfetch_chain[-1].listener,
            warcprox.stats.RunningStats)

    assert isinstance(
            controller._postfetch_chain[-2],
            warcprox.BaseBatchPostfetchProcessor)
    assert isinstance(
            controller._postfetch_chain[-3],
            warcprox.BaseStandardPostfetchProcessor)
    assert isinstance(
            controller._postfetch_chain[-4],
            warcprox.ListenerPostfetchProcessor)
    assert isinstance(
            controller._postfetch_chain[-4].listener,
            warcprox.stats.RunningStats)
    assert isinstance(
            controller._postfetch_chain[0],
            EarlyPlugin)

def test_choose_a_port_for_me(warcprox_):
    options = warcprox.Options()
    options.port = 0
    if warcprox_.service_registry:
        options.rethinkdb_services_url = 'rethinkdb://localhost/test0/services'
    controller = warcprox.controller.WarcproxController(options)
    assert controller.proxy.server_port != 0
    assert controller.proxy.server_port != 8000
    assert controller.proxy.server_address == (
            '127.0.0.1', controller.proxy.server_port)

    th = threading.Thread(target=controller.run_until_shutdown)
    controller.start()
    th.start()
    try:
        # check that the status api lists the correct port
        url = 'http://localhost:%s/status' % controller.proxy.server_port
        response = requests.get(url)
        assert response.status_code == 200
        status = json.loads(response.content.decode('ascii'))
        assert status['port'] == controller.proxy.server_port

        if warcprox_.service_registry:
            # check that service registry entry lists the correct port
            start = time.time()
            ports = []
            while time.time() - start < 30:
                svcs = warcprox_.service_registry.available_services('warcprox')
                ports = [svc['port'] for svc in svcs]
                if controller.proxy.server_port in ports:
                    break
            assert controller.proxy.server_port in ports

    finally:
        controller.stop.set()
        th.join()

def test_via_response_header(warcprox_, http_daemon, archiving_proxies, playback_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    url = 'http://localhost:%s/a/z' % http_daemon.server_port
    response = requests.get(url, proxies=archiving_proxies)
    assert response.headers['via'] == '1.1 warcprox'

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    playback_response = requests.get(
            url, proxies=playback_proxies, verify=False)
    assert response.status_code == 200
    assert not 'via' in playback_response

    warc = warcprox_.warc_writer_processor.writer_pool.default_warc_writer.path
    with open(warc, 'rb') as f:
        for record in warcio.archiveiterator.ArchiveIterator(f):
            if record.rec_headers.get_header('warc-target-uri') == url:
                if record.rec_type == 'response':
                    assert not record.http_headers.get_header('via')
                elif record.rec_type == 'request':
                    assert record.http_headers.get_header('via') == '1.1 warcprox'

def test_slash_in_warc_prefix(warcprox_, http_daemon, archiving_proxies):
    url = 'http://localhost:%s/b/b' % http_daemon.server_port
    headers = {"Warcprox-Meta": json.dumps({"warc-prefix":"../../../../etc/a"})}
    response = requests.get(url, proxies=archiving_proxies, headers=headers)
    assert response.status_code == 400
    assert response.reason == 'request rejected by warcprox: slash and backslash are not permitted in warc-prefix'

    url = 'http://localhost:%s/b/c' % http_daemon.server_port
    headers = {"Warcprox-Meta": json.dumps({"warc-prefix":"..\\..\\..\\derp\\monkey"})}
    response = requests.get(url, proxies=archiving_proxies, headers=headers)
    assert response.status_code == 400
    assert response.reason == 'request rejected by warcprox: slash and backslash are not permitted in warc-prefix'

def test_crawl_log(warcprox_, http_daemon, archiving_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    hostname = socket.gethostname().split('.', 1)[0]
    port = warcprox_.proxy.server_port
    default_crawl_log_path = os.path.join(
            warcprox_.options.crawl_log_dir,
            'crawl-{}-{}.log'.format(hostname, port))

    try:
        os.unlink(default_crawl_log_path)
    except:
        pass

    # should go to default crawl log
    url = 'http://localhost:%s/b/aa' % http_daemon.server_port
    response = requests.get(url, proxies=archiving_proxies)
    assert response.status_code == 200

    # should go to test_crawl_log_1.log
    url = 'http://localhost:%s/b/bb' % http_daemon.server_port
    headers = {
        "Warcprox-Meta": json.dumps({"warc-prefix":"test_crawl_log_1"}),
        "Referer": "http://example.com/referer",
    }
    response = requests.get(url, proxies=archiving_proxies, headers=headers)
    assert response.status_code == 200

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 2)

    file = os.path.join(
            warcprox_.options.crawl_log_dir,
            'test_crawl_log_1-{}-{}.log'.format(hostname, port))
    assert os.path.exists(file)
    assert os.stat(file).st_size > 0
    assert os.path.exists(default_crawl_log_path)

    crawl_log = open(default_crawl_log_path, 'rb').read()
    # tests will fail in year 3000 :)
    assert re.match(br'\A2[^\n]+\n\Z', crawl_log)
    assert crawl_log[24:31] == b'   200 '
    assert crawl_log[31:42] == b'        54 '
    fields = crawl_log.split()
    assert len(fields) == 13
    assert fields[3].endswith(b'/b/aa')
    assert fields[4] == b'-'
    assert fields[5] == b'-'
    assert fields[6] == b'text/plain'
    assert fields[7] == b'-'
    assert re.match(br'^\d{17}[+]\d{3}', fields[8])
    assert fields[9] == b'sha1:69d51a46e44a04e8110da0c91897cece979fa70f'
    assert fields[10] == b'-'
    assert fields[11] == b'-'
    extra_info = json.loads(fields[12].decode('utf-8'))
    assert set(extra_info.keys()) == {
            'contentSize', 'warcFilename', 'warcFileOffset'}
    assert extra_info['contentSize'] == 145

    crawl_log_1 = open(file, 'rb').read()
    assert re.match(br'\A2[^\n]+\n\Z', crawl_log_1)
    assert crawl_log_1[24:31] == b'   200 '
    assert crawl_log_1[31:42] == b'        54 '
    fields = crawl_log_1.split()
    assert len(fields) == 13
    assert fields[3].endswith(b'/b/bb')
    assert fields[4] == b'-'
    assert fields[5] == b'http://example.com/referer'
    assert fields[6] == b'text/plain'
    assert fields[7] == b'-'
    assert re.match(br'^\d{17}[+]\d{3}', fields[8])
    assert fields[9] == b'sha1:9aae6acb797c75ca8eb5dded9be2127cc61b3fbb'
    assert fields[10] == b'-'
    assert fields[11] == b'-'
    extra_info = json.loads(fields[12].decode('utf-8'))
    assert set(extra_info.keys()) == {
            'contentSize', 'warcFilename', 'warcFileOffset'}
    assert extra_info['contentSize'] == 145

    # should be deduplicated
    url = 'http://localhost:%s/b/aa' % http_daemon.server_port
    headers = {"Warcprox-Meta": json.dumps({
        "warc-prefix": "test_crawl_log_2",
        "metadata": {"seed": "http://example.com/seed"}})}
    response = requests.get(url, proxies=archiving_proxies, headers=headers)
    assert response.status_code == 200

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 3)

    file = os.path.join(
            warcprox_.options.crawl_log_dir,
            'test_crawl_log_2-{}-{}.log'.format(hostname, port))
    assert os.path.exists(file)
    assert os.stat(file).st_size > 0

    crawl_log_2 = open(file, 'rb').read()

    assert re.match(br'\A2[^\n]+\n\Z', crawl_log_2)
    assert crawl_log_2[24:31] == b'   200 '
    assert crawl_log_2[31:42] == b'        54 '
    fields = crawl_log_2.split()
    assert len(fields) == 13
    assert fields[3].endswith(b'/b/aa')
    assert fields[4] == b'-'
    assert fields[5] == b'-'
    assert fields[6] == b'text/plain'
    assert fields[7] == b'-'
    assert re.match(br'^\d{17}[+]\d{3}', fields[8])
    assert fields[9] == b'sha1:69d51a46e44a04e8110da0c91897cece979fa70f'
    assert fields[10] == b'http://example.com/seed'
    assert fields[11] == b'duplicate:digest'
    extra_info = json.loads(fields[12].decode('utf-8'))
    assert set(extra_info.keys()) == {
            'contentSize', 'warcFilename', 'warcFileOffset'}
    assert extra_info['contentSize'] == 145

    # a request that is not saved to a warc (because of --method-filter)
    url = 'http://localhost:%s/b/cc' % http_daemon.server_port
    headers = {'Warcprox-Meta': json.dumps({'warc-prefix': 'test_crawl_log_3'})}
    response = requests.head(url, proxies=archiving_proxies, headers=headers)

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 4)

    file = os.path.join(
            warcprox_.options.crawl_log_dir,
            'test_crawl_log_3-{}-{}.log'.format(hostname, port))

    assert os.path.exists(file)
    crawl_log_3 = open(file, 'rb').read()
    assert re.match(br'\A2[^\n]+\n\Z', crawl_log_3)
    assert crawl_log_3[24:31] == b'   200 '
    assert crawl_log_3[31:42] == b'         0 '
    fields = crawl_log_3.split()
    assert len(fields) == 13
    assert fields[3].endswith(b'/b/cc')
    assert fields[4] == b'-'
    assert fields[5] == b'-'
    assert fields[6] == b'text/plain'
    assert fields[7] == b'-'
    assert re.match(br'^\d{17}[+]\d{3}', fields[8])
    assert fields[9] == b'sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709'
    assert fields[10] == b'-'
    assert fields[11] == b'-'
    extra_info = json.loads(fields[12].decode('utf-8'))
    assert extra_info == {'contentSize': 91, 'method': 'HEAD'}

    # WARCPROX_WRITE_RECORD
    url = 'http://fakeurl/'
    payload = b'I am the WARCPROX_WRITE_RECORD payload'
    headers = {
        'Content-Type': 'text/plain',
        'WARC-Type': 'metadata',
        'Host': 'N/A',
        'Warcprox-Meta': json.dumps({'warc-prefix': 'test_crawl_log_4'}),
    }
    response = requests.request(
            method='WARCPROX_WRITE_RECORD', url=url, data=payload,
            headers=headers, proxies=archiving_proxies)
    assert response.status_code == 204

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 5)

    file = os.path.join(
            warcprox_.options.crawl_log_dir,
            'test_crawl_log_4-{}-{}.log'.format(hostname, port))
    assert os.path.exists(file)
    crawl_log_4 = open(file, 'rb').read()

    assert re.match(br'\A2[^\n]+\n\Z', crawl_log_4)
    assert crawl_log_4[24:31] == b'   204 '
    assert crawl_log_4[31:42] == b'        38 '
    fields = crawl_log_4.split()
    assert len(fields) == 13
    assert fields[3] == b'http://fakeurl/'
    assert fields[4] == b'-'
    assert fields[5] == b'-'
    assert fields[6] == b'text/plain'
    assert fields[7] == b'-'
    assert re.match(br'^\d{17}[+]\d{3}', fields[8])
    assert fields[9] == b'sha1:bb56497c17d2684f5eca4af9df908c78ba74ca1c'
    assert fields[10] == b'-'
    assert fields[11] == b'-'
    extra_info = json.loads(fields[12].decode('utf-8'))
    assert set(extra_info.keys()) == {
            'contentSize', 'warcFilename', 'warcFileOffset', 'method'}
    assert extra_info['contentSize'] == 38
    assert extra_info['method'] == 'WARCPROX_WRITE_RECORD'

    #Empty spae for Content Type
    url = 'http://localhost:%s/space_in_content_type' % http_daemon.server_port
    headers = {'Warcprox-Meta': json.dumps({'warc-prefix': 'test_crawl_log_5'})}
    response = requests.get(url, proxies=archiving_proxies, headers=headers)

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 6)

    file = os.path.join(
            warcprox_.options.crawl_log_dir,
            'test_crawl_log_5-{}-{}.log'.format(hostname, port))

    assert os.path.exists(file)
    crawl_log_5 = open(file, 'rb').read()
    assert re.match(br'\A2[^\n]+\n\Z', crawl_log_5)
    assert crawl_log_5[24:31] == b'   200 '
    assert crawl_log_5[31:42] == b'         4 '
    fields = crawl_log_5.split()
    assert len(fields) == 13
    assert fields[3].endswith(b'/space_in_content_type')
    assert fields[4] == b'-'
    assert fields[5] == b'-'
    assert fields[6] == b'-'
    assert fields[7] == b'-'
    assert re.match(br'^\d{17}[+]\d{3}', fields[8])
    assert fields[9] == b'sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'
    assert fields[10] == b'-'
    assert fields[11] == b'-'
    extra_info = json.loads(fields[12].decode('utf-8'))
    assert set(extra_info.keys()) == {
            'contentSize', 'warcFilename', 'warcFileOffset'}
    assert extra_info['contentSize'] == 59


    #Fetch Exception
    url = 'http://localhost-doesnt-exist:%s/connection-error' % http_daemon.server_port
    headers = {'Warcprox-Meta': json.dumps({'warc-prefix': 'test_crawl_log_6'})}
    response = requests.get(url, proxies=archiving_proxies, headers=headers)

    #Verify the connection is cleaned up properly after the exception
    url = 'http://localhost:%s/b/aa' % http_daemon.server_port
    response = requests.get(url, proxies=archiving_proxies)
    assert response.status_code == 200

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 7)

    file = os.path.join(
            warcprox_.options.crawl_log_dir,
            'test_crawl_log_6-{}-{}.log'.format(hostname, port))

    assert os.path.exists(file)
    crawl_log_6 = open(file, 'rb').read()
    assert re.match(br'\A2[^\n]+\n\Z', crawl_log_6)

    #seems to vary depending on the environment
    assert crawl_log_6[24:31] == b'    -6 ' or crawl_log_6[24:31] == b'    -2 ' 
    assert crawl_log_6[31:42] == b'         0 '
    fields = crawl_log_6.split()
    assert len(fields) == 13
    assert fields[3].endswith(b'/connection-error')
    assert fields[4] == b'-'
    assert fields[5] == b'-'
    assert fields[6] == b'-'
    assert fields[7] == b'-'
    assert fields[8] == b'-'
    assert fields[9] == b'-'
    assert fields[10] == b'-'
    assert fields[11] == b'-'
    extra_info = json.loads(fields[12].decode('utf-8'))
    assert set(extra_info.keys()) == {'exception'}

    #Test the same bad server to check for -404
    url = 'http://localhost-doesnt-exist:%s/connection-error' % http_daemon.server_port
    headers = {'Warcprox-Meta': json.dumps({'warc-prefix': 'test_crawl_log_7'})}
    response = requests.get(url, proxies=archiving_proxies, headers=headers)

    #Verify the connection is cleaned up properly after the exception
    url = 'http://localhost:%s/b/aa' % http_daemon.server_port
    response = requests.get(url, proxies=archiving_proxies)
    assert response.status_code == 200

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 8)

    file = os.path.join(
        warcprox_.options.crawl_log_dir,
        'test_crawl_log_7-{}-{}.log'.format(hostname, port))

    assert os.path.exists(file)
    crawl_log_7 = open(file, 'rb').read()
    assert re.match(br'\A2[^\n]+\n\Z', crawl_log_7)
    assert crawl_log_7[24:31] == b'  -404 '
    assert crawl_log_7[31:42] == b'         0 '
    fields = crawl_log_7.split()
    assert len(fields) == 13
    assert fields[3].endswith(b'/connection-error')
    assert fields[4] == b'-'
    assert fields[5] == b'-'
    assert fields[6] == b'-'
    assert fields[7] == b'-'
    assert fields[8] == b'-'
    assert fields[9] == b'-'
    assert fields[10] == b'-'
    assert fields[11] == b'-'
    extra_info = json.loads(fields[12].decode('utf-8'))
    assert set(extra_info.keys()) == {'exception'}

    #Verify non-ascii urls are encoded properly
    url = 'http://localhost:%s/b/¶-non-ascii' % http_daemon.server_port
    headers = {
        "Warcprox-Meta": json.dumps({"warc-prefix":"test_crawl_log_8",
                                     "metadata":{'seed': 'http://example.com/¶-non-ascii', 'hop_path': 'L', 'brozzled_url': 'http://localhost:%s/b/¶-non-ascii' % http_daemon.server_port, 'hop_via_url': 'http://чунджа.kz/b/¶-non-ascii'}}),
    }
    response = requests.get(url, proxies=archiving_proxies, headers=headers)
    assert response.status_code == 200

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 9)

    file = os.path.join(
        warcprox_.options.crawl_log_dir,
        'test_crawl_log_8-{}-{}.log'.format(hostname, port))

    assert os.path.exists(file)
    crawl_log_8 = open(file, 'rb').read()
    assert re.match(br'\A2[^\n]+\n\Z', crawl_log_8)
    assert crawl_log_8[24:31] == b'   200 '
    assert crawl_log_8[31:42] == b'       154 '
    fields = crawl_log_8.split()
    assert len(fields) == 13
    assert fields[3].endswith(b'/b/%C2%B6-non-ascii')
    assert fields[4] == b'L'
    assert fields[5].endswith(b'http://xn--80ahg0a3ax.kz/b/%C2%B6-non-ascii')
    assert fields[6] == b'text/plain'
    assert fields[7] == b'-'
    assert re.match(br'^\d{17}[+]\d{3}', fields[8])
    assert fields[9] == b'sha1:cdd841ea7c5e46fde3fba56b2e45e4df5aeec439'
    assert fields[10].endswith('/¶-non-ascii'.encode())
    assert fields[11] == b'-'
    extra_info = json.loads(fields[12].decode('utf-8'))

def test_crawl_log_canonicalization():
    assert crawl_log.canonicalize_url(None) is None
    assert crawl_log.canonicalize_url("") == ''
    assert crawl_log.canonicalize_url("-") == '-'
    assert crawl_log.canonicalize_url("http://чунджа.kz/b/¶-non-ascii") == "http://xn--80ahg0a3ax.kz/b/%C2%B6-non-ascii"
    assert crawl_log.canonicalize_url("Not a URL") == "Not a URL"

def test_long_warcprox_meta(
        warcprox_, http_daemon, archiving_proxies, playback_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    url = 'http://localhost:%s/b/g' % http_daemon.server_port

    # create a very long warcprox-meta header
    headers = {'Warcprox-Meta': json.dumps({
        'x':'y'*1000000, 'warc-prefix': 'test_long_warcprox_meta'})}
    response = requests.get(
            url, proxies=archiving_proxies, headers=headers, verify=False)
    assert response.status_code == 200

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    # check that warcprox-meta was parsed and honored ("warc-prefix" param)
    assert warcprox_.warc_writer_processor.writer_pool.warc_writers["test_long_warcprox_meta"]
    writer = warcprox_.warc_writer_processor.writer_pool.warc_writers["test_long_warcprox_meta"]
    warc_path = os.path.join(writer.directory, writer.finalname)
    warcprox_.warc_writer_processor.writer_pool.warc_writers["test_long_warcprox_meta"].close()
    assert os.path.exists(warc_path)

    # read the warc
    with open(warc_path, 'rb') as f:
        rec_iter = iter(warcio.archiveiterator.ArchiveIterator(f))
        record = next(rec_iter)
        assert record.rec_type == 'warcinfo'
        record = next(rec_iter)
        assert record.rec_type == 'response'
        assert record.rec_headers.get_header('warc-target-uri') == url
        record = next(rec_iter)
        assert record.rec_type == 'request'
        assert record.rec_headers.get_header('warc-target-uri') == url
        with pytest.raises(StopIteration):
            next(rec_iter)

def test_socket_timeout_response(
        warcprox_, http_daemon, https_daemon, archiving_proxies,
        playback_proxies):
    """Response will timeout because we use --socket-timeout=4 whereas the
    target URL will return after 6 sec.
    """
    urls_before = warcprox_.proxy.running_stats.urls

    url = 'http://localhost:%s/slow-response' % http_daemon.server_port
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 502

    # test that the connection is cleaned up properly after truncating a
    # response (no hang or timeout)
    url = 'http://localhost:%s/' % http_daemon.server_port
    response = requests.get(
        url, proxies=archiving_proxies, verify=False, timeout=10)
    assert response.status_code == 404
    assert response.content == b'404 Not Found\n'

    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

def test_empty_response(
        warcprox_, http_daemon, https_daemon, archiving_proxies,
        playback_proxies):
    # localhost:server_port was added to the `bad_hostnames_ports` cache by
    # previous tests and this causes subsequent tests to fail. We clear it.
    warcprox_.proxy.bad_hostnames_ports.clear()

    url = 'http://localhost:%s/empty-response' % http_daemon.server_port
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 502
    # this is the reason in python >= 3.5 but not in 3.4 and 2.7
    # assert response.reason == 'Remote end closed connection without response'

    url = 'https://localhost:%s/empty-response' % https_daemon.server_port
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 502

def test_payload_digest(warcprox_, http_daemon):
    '''
    Tests that digest is of RFC2616 "entity body"
    (transfer-decoded but not content-decoded)
    '''
    # localhost:server_port was added to the `bad_hostnames_ports` cache by
    # previous tests and this causes subsequent tests to fail. We clear it.
    warcprox_.proxy.bad_hostnames_ports.clear()

    class HalfMockedMitm(warcprox.mitmproxy.MitmProxyHandler):
        def __init__(self, url):
            self.path = url
            self.request_version = 'HTTP/1.1'
            self.client_address = mock.MagicMock()
            self.headers = email.message.Message()
            self.headers.add_header('Host', 'localhost:%s' % http_daemon.server_port)
            self.server = warcprox_.proxy
            self.command = 'GET'
            self.connection = mock.Mock()

    PLAIN_SHA1 = b'sha1:881289333370aa4e3214505f1173423cc5a896b7'
    GZIP_SHA1 = b'sha1:634e25de71ae01edb5c5d9e2e99c4836bbe94129'
    GZIP_GZIP_SHA1 = b'sha1:cecbf3a5c4975072f5e4c5e0489f808ef246c2b4'

    # plain
    mitm = HalfMockedMitm('http://localhost:%s/test_payload_digest-plain' % http_daemon.server_port)
    req, prox_rec_res = mitm.do_GET()
    assert warcprox.digest_str(prox_rec_res.payload_digest) == PLAIN_SHA1

    # content-type: application/gzip
    mitm = HalfMockedMitm('http://localhost:%s/test_payload_digest-gzip' % http_daemon.server_port)
    req, prox_rec_res = mitm.do_GET()
    assert warcprox.digest_str(prox_rec_res.payload_digest) == GZIP_SHA1

    # content-encoding: gzip
    mitm = HalfMockedMitm('http://localhost:%s/test_payload_digest-ce-gzip' % http_daemon.server_port)
    req, prox_rec_res = mitm.do_GET()
    assert warcprox.digest_str(prox_rec_res.payload_digest) == GZIP_SHA1

    # content-type: application/gzip && content-encoding: gzip
    mitm = HalfMockedMitm('http://localhost:%s/test_payload_digest-gzip-ce-gzip' % http_daemon.server_port)
    req, prox_rec_res = mitm.do_GET()
    assert warcprox.digest_str(prox_rec_res.payload_digest) == GZIP_GZIP_SHA1

    # chunked plain
    mitm = HalfMockedMitm('http://localhost:%s/test_payload_digest-te-chunked' % http_daemon.server_port)
    req, prox_rec_res = mitm.do_GET()
    assert warcprox.digest_str(prox_rec_res.payload_digest) == PLAIN_SHA1

    # chunked content-type: application/gzip
    mitm = HalfMockedMitm('http://localhost:%s/test_payload_digest-gzip-te-chunked' % http_daemon.server_port)
    req, prox_rec_res = mitm.do_GET()
    assert warcprox.digest_str(prox_rec_res.payload_digest) == GZIP_SHA1

    # chunked content-encoding: gzip
    mitm = HalfMockedMitm('http://localhost:%s/test_payload_digest-ce-gzip-te-chunked' % http_daemon.server_port)
    req, prox_rec_res = mitm.do_GET()
    assert warcprox.digest_str(prox_rec_res.payload_digest) == GZIP_SHA1

    # chunked content-type: application/gzip && content-encoding: gzip
    mitm = HalfMockedMitm('http://localhost:%s/test_payload_digest-gzip-ce-gzip-te-chunked' % http_daemon.server_port)
    req, prox_rec_res = mitm.do_GET()
    assert warcprox.digest_str(prox_rec_res.payload_digest) == GZIP_GZIP_SHA1

def test_dedup_min_text_size(http_daemon, warcprox_, archiving_proxies):
    """We use options --dedup-min-text-size=3 --dedup-min-binary-size=5 and we
    try to download content smaller than these limits to make sure that it is
    not deduplicated. We create the digest_str with the following code:
    ```
    payload_digest = hashlib.new('sha1')
    payload_digest.update(b'aa')
    warcprox.digest_str(payload_digest)
    ```
    """
    urls_before = warcprox_.proxy.running_stats.urls

    # start a fresh warc
    warcprox_.warc_writer_processor.writer_pool.close_writers()

    # fetch small text
    url = 'http://localhost:%s/text-2bytes' % http_daemon.server_port
    response = requests.get(
        url, proxies=archiving_proxies, verify=False, timeout=10)
    assert len(response.content) == 2
    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)
    # check no dedup was saved (except RethinkCapturesDedup which always saves)
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:e0c9035898dd52fc65c41454cec9c4d2611bfb37')
    if not isinstance(warcprox_.dedup_db, warcprox.bigtable.RethinkCapturesDedup):
        assert dedup_lookup is None

        # fetch again saving dedup info so that we can test dedup info ignored
        orig_should_dedup = warcprox_.dedup_db.should_dedup
        warcprox_.dedup_db.should_dedup = lambda *args, **kwargs: True
        try:
            response = requests.get(
                url, proxies=archiving_proxies, verify=False, timeout=10)
            assert len(response.content) == 2
            wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 2)
            # check dedup was saved
            dedup_lookup = warcprox_.dedup_db.lookup(
                    b'sha1:e0c9035898dd52fc65c41454cec9c4d2611bfb37')
            assert dedup_lookup
        finally:
            warcprox_.dedup_db.should_dedup = orig_should_dedup
    else:
        assert dedup_lookup

    # fetch again and check that it was not deduped
    urls_before = warcprox_.proxy.running_stats.urls
    response = requests.get(
        url, proxies=archiving_proxies, verify=False, timeout=10)
    assert len(response.content) == 2
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    # check that response records were written
    warc = warcprox_.warc_writer_processor.writer_pool.default_warc_writer.path
    with open(warc, 'rb') as f:
        rec_iter = iter(warcio.archiveiterator.ArchiveIterator(f))
        record = next(rec_iter)
        assert record.rec_type == 'warcinfo'
        record = next(rec_iter)
        assert record.rec_type == 'response'
        assert record.rec_headers.get_header('warc-target-uri') == url
        record = next(rec_iter)
        assert record.rec_type == 'request'
        assert record.rec_headers.get_header('warc-target-uri') == url
        record = next(rec_iter)
        assert record.rec_type == 'response'
        assert record.rec_headers.get_header('warc-target-uri') == url
        record = next(rec_iter)
        assert record.rec_type == 'request'
        assert record.rec_headers.get_header('warc-target-uri') == url
        if not isinstance(warcprox_.dedup_db, warcprox.bigtable.RethinkCapturesDedup):
            record = next(rec_iter)
            assert record.rec_type == 'response'
            assert record.rec_headers.get_header('warc-target-uri') == url
            record = next(rec_iter)
            assert record.rec_type == 'request'
            assert record.rec_headers.get_header('warc-target-uri') == url
        with pytest.raises(StopIteration):
            next(rec_iter)

def test_dedup_min_binary_size(http_daemon, warcprox_, archiving_proxies):
    """We use options --dedup-min-text-size=3 --dedup-min-binary-size=5 and we
    try to download content smaller than these limits to make sure that it is
    not deduplicated. We create the digest_str with the following code:
    ```
    payload_digest = hashlib.new('sha1')
    payload_digest.update(b'aa')
    warcprox.digest_str(payload_digest)
    ```
    """
    urls_before = warcprox_.proxy.running_stats.urls

    # start a fresh warc
    warcprox_.warc_writer_processor.writer_pool.close_writers()

    # fetch small binary
    url = 'http://localhost:%s/binary-4bytes' % http_daemon.server_port
    response = requests.get(
        url, proxies=archiving_proxies, verify=False, timeout=10)
    assert len(response.content) == 4
    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)
    # check no dedup was saved (except RethinkCapturesDedup which always saves)
    dedup_lookup = warcprox_.dedup_db.lookup(
            b'sha1:70c881d4a26984ddce795f6f71817c9cf4480e79')
    if not isinstance(warcprox_.dedup_db, warcprox.bigtable.RethinkCapturesDedup):
        assert dedup_lookup is None

        # fetch again saving dedup info so that we can test dedup info ignored
        orig_should_dedup = warcprox_.dedup_db.should_dedup
        warcprox_.dedup_db.should_dedup = lambda *args, **kwargs: True
        try:
            response = requests.get(
                url, proxies=archiving_proxies, verify=False, timeout=10)
            assert len(response.content) == 4
            wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 2)
            # check dedup was saved
            dedup_lookup = warcprox_.dedup_db.lookup(
                    b'sha1:70c881d4a26984ddce795f6f71817c9cf4480e79')
            assert dedup_lookup
        finally:
            warcprox_.dedup_db.should_dedup = orig_should_dedup
    else:
        assert dedup_lookup

    # fetch again and check that it was not deduped
    urls_before = warcprox_.proxy.running_stats.urls
    response = requests.get(
        url, proxies=archiving_proxies, verify=False, timeout=10)
    assert len(response.content) == 4
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

    # check that response records were written
    warc = warcprox_.warc_writer_processor.writer_pool.default_warc_writer.path
    with open(warc, 'rb') as f:
        rec_iter = iter(warcio.archiveiterator.ArchiveIterator(f))
        record = next(rec_iter)
        assert record.rec_type == 'warcinfo'
        record = next(rec_iter)
        assert record.rec_type == 'response'
        assert record.rec_headers.get_header('warc-target-uri') == url
        record = next(rec_iter)
        assert record.rec_type == 'request'
        assert record.rec_headers.get_header('warc-target-uri') == url
        record = next(rec_iter)
        assert record.rec_type == 'response'
        assert record.rec_headers.get_header('warc-target-uri') == url
        record = next(rec_iter)
        assert record.rec_type == 'request'
        assert record.rec_headers.get_header('warc-target-uri') == url
        if not isinstance(warcprox_.dedup_db, warcprox.bigtable.RethinkCapturesDedup):
            record = next(rec_iter)
            assert record.rec_type == 'response'
            assert record.rec_headers.get_header('warc-target-uri') == url
            record = next(rec_iter)
            assert record.rec_type == 'request'
            assert record.rec_headers.get_header('warc-target-uri') == url
        with pytest.raises(StopIteration):
            next(rec_iter)

def test_incomplete_read(http_daemon, warcprox_, archiving_proxies):
    urls_before = warcprox_.proxy.running_stats.urls

    # see https://github.com/internetarchive/warcprox/pull/123
    url = 'http://localhost:%s/incomplete-read' % http_daemon.server_port
    with pytest.raises(requests.exceptions.ChunkedEncodingError):
        response = requests.get(
            url, proxies=archiving_proxies, verify=False, timeout=10)

    # although `requests.get` raises exception here, other clients like
    # browsers put up with the server misbehavior; warcprox does too, and will
    # record the response verbatim in the warc; this `wait()` call tests
    # that a warc record is written

    # wait for postfetch chain
    wait(lambda: warcprox_.proxy.running_stats.urls - urls_before == 1)

if __name__ == '__main__':
    pytest.main()

