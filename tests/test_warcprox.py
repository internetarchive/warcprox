#!/usr/bin/env python
#
# tests/test_warcprox.py - automated tests for warcprox
#
# Copyright (C) 2013-2016 Internet Archive
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.
#

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
import rethinkstuff
from hanzo import warctools
import warnings
import pprint
import traceback
import signal
from collections import Counter

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

logging.basicConfig(stream=sys.stdout, level=logging.INFO,
        format='%(asctime)s %(process)d %(levelname)s %(threadName)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')
logging.getLogger("requests.packages.urllib3").setLevel(logging.WARN)
warnings.simplefilter("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)
warnings.simplefilter("ignore", category=requests.packages.urllib3.exceptions.InsecurePlatformWarning)

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

    logging.warn("dumping state (caught signal {})\n{}".format(signum, "\n".join(state_strs)))

signal.signal(signal.SIGQUIT, dump_state)

class _TestHttpRequestHandler(http_server.BaseHTTPRequestHandler):
    def do_GET(self):
        logging.info('GET {}'.format(self.path))

        m = re.match(r'^/([^/]+)/([^/]+)$', self.path)
        if m is not None:
            special_header = 'warcprox-test-header: {}!'.format(m.group(1)).encode('utf-8')
            payload = 'I am the warcprox test payload! {}!\n'.format(10*m.group(2)).encode('utf-8')
            headers = (b'HTTP/1.1 200 OK\r\n'
                    +  b'Content-Type: text/plain\r\n'
                    +  special_header + b'\r\n'
                    +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n'
                    +  b'\r\n')
        else:
            payload = b'404 Not Found\n'
            headers = (b'HTTP/1.1 404 Not Found\r\n'
                    +  b'Content-Type: text/plain\r\n'
                    +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n'
                    +  b'\r\n')

        self.connection.sendall(headers)
        self.connection.sendall(payload)

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

@pytest.fixture(scope="module")
def http_daemon(request):
    http_daemon = http_server.HTTPServer(('localhost', 0),
            RequestHandlerClass=_TestHttpRequestHandler)
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
    https_daemon = http_server.HTTPServer(('localhost', 0),
            RequestHandlerClass=_TestHttpRequestHandler)
    # https_daemon.socket = ssl.wrap_socket(httpd.socket, certfile='path/to/localhost.pem', server_side=True)
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

# @pytest.fixture(scope="module")
# def options(request):
#     return warcprox.Options(base32=True)

@pytest.fixture(scope="module")
def captures_db(request, rethinkdb_servers, rethinkdb_big_table):
    captures_db = None
    if rethinkdb_servers:
        servers = rethinkdb_servers.split(",")
        if rethinkdb_big_table:
            db = 'warcprox_test_captures_' + "".join(random.sample("abcdefghijklmnopqrstuvwxyz0123456789_",8))
            r = rethinkstuff.Rethinker(servers, db)
            captures_db = warcprox.bigtable.RethinkCaptures(r)

    def fin():
        if captures_db:
            captures_db.close()
            logging.info('dropping rethinkdb database {}'.format(db))
            result = captures_db.r.db_drop(db).run()
            logging.info("result=%s", result)
    request.addfinalizer(fin)

    return captures_db

@pytest.fixture(scope="module")
def rethink_dedup_db(request, rethinkdb_servers, captures_db):
    ddb = None
    if rethinkdb_servers:
        if captures_db:
            ddb = warcprox.bigtable.RethinkCapturesDedup(captures_db)
        else:
            servers = rethinkdb_servers.split(",")
            db = 'warcprox_test_dedup_' + "".join(random.sample("abcdefghijklmnopqrstuvwxyz0123456789_",8))
            r = rethinkstuff.Rethinker(servers, db)
            ddb = warcprox.dedup.RethinkDedupDb(r)

    def fin():
        if rethinkdb_servers:
            ddb.close()
            if not captures_db:
                logging.info('dropping rethinkdb database {}'.format(db))
                result = ddb.r.db_drop(db).run()
                logging.info("result=%s", result)
    request.addfinalizer(fin)

    return ddb

@pytest.fixture(scope="module")
def dedup_db(request, rethink_dedup_db):
    dedup_db_file = None
    ddb = rethink_dedup_db
    if not ddb:
        f = tempfile.NamedTemporaryFile(prefix='warcprox-test-dedup-', suffix='.db', delete=False)
        f.close()
        dedup_db_file = f.name
        ddb = warcprox.dedup.DedupDb(dedup_db_file)

    def fin():
        if dedup_db_file:
            logging.info('deleting file {}'.format(dedup_db_file))
            os.unlink(dedup_db_file)
    request.addfinalizer(fin)

    return ddb

@pytest.fixture(scope="module")
def stats_db(request, rethinkdb_servers):
    if rethinkdb_servers:
        servers = rethinkdb_servers.split(",")
        db = 'warcprox_test_stats_' + "".join(random.sample("abcdefghijklmnopqrstuvwxyz0123456789_",8))
        r = rethinkstuff.Rethinker(servers, db)
        sdb = warcprox.stats.RethinkStatsDb(r)
    else:
        f = tempfile.NamedTemporaryFile(prefix='warcprox-test-stats-', suffix='.db', delete=False)
        f.close()
        stats_db_file = f.name
        sdb = warcprox.stats.StatsDb(stats_db_file)

    def fin():
        sdb.close()
        if rethinkdb_servers:
            logging.info('dropping rethinkdb database {}'.format(db))
            result = sdb.r.db_drop(db).run()
            logging.info("result=%s", result)
        else:
            logging.info('deleting file {}'.format(stats_db_file))
            os.unlink(stats_db_file)
    request.addfinalizer(fin)

    return sdb

@pytest.fixture(scope="module")
def service_registry(request, rethinkdb_servers):
    if rethinkdb_servers:
        servers = rethinkdb_servers.split(",")
        db = 'warcprox_test_services_' + "".join(random.sample("abcdefghijklmnopqrstuvwxyz0123456789_",8))
        r = rethinkstuff.Rethinker(servers, db)

        def fin():
            logging.info('dropping rethinkdb database {}'.format(db))
            result = r.db_drop(db).run()
            logging.info("result=%s", result)
        request.addfinalizer(fin)

        return rethinkstuff.ServiceRegistry(r)
    else:
        return None

@pytest.fixture(scope="module")
def warcprox_(request, captures_db, dedup_db, stats_db, service_registry):
    f = tempfile.NamedTemporaryFile(prefix='warcprox-test-ca-', suffix='.pem', delete=True)
    f.close() # delete it, or CertificateAuthority will try to read it
    ca_file = f.name
    ca_dir = tempfile.mkdtemp(prefix='warcprox-test-', suffix='-ca')
    ca = certauth.certauth.CertificateAuthority(ca_file, ca_dir, 'warcprox-test')

    recorded_url_q = queue.Queue()

    options = warcprox.Options(port=0, playback_port=0,
            onion_tor_socks_proxy='localhost:9050')
    proxy = warcprox.warcproxy.WarcProxy(ca=ca, recorded_url_q=recorded_url_q,
            stats_db=stats_db, options=options)
    options.port = proxy.server_port

    options.directory = tempfile.mkdtemp(prefix='warcprox-test-warcs-')

    f = tempfile.NamedTemporaryFile(prefix='warcprox-test-playback-index-', suffix='.db', delete=False)
    f.close()
    playback_index_db_file = f.name
    playback_index_db = warcprox.playback.PlaybackIndexDb(playback_index_db_file)
    playback_proxy = warcprox.playback.PlaybackProxy(ca=ca,
            playback_index_db=playback_index_db, options=options)
    options.playback_proxy = playback_proxy.server_port

    writer_pool = warcprox.writer.WarcWriterPool(options)
    warc_writer_thread = warcprox.writerthread.WarcWriterThread(
            recorded_url_q=recorded_url_q, writer_pool=writer_pool,
            dedup_db=dedup_db, listeners=[captures_db or dedup_db, playback_index_db, stats_db])

    warcprox_ = warcprox.controller.WarcproxController(proxy=proxy,
        warc_writer_thread=warc_writer_thread, playback_proxy=playback_proxy,
        service_registry=service_registry, options=options)
    logging.info('starting warcprox')
    warcprox_thread = threading.Thread(name='WarcproxThread',
            target=warcprox_.run_until_shutdown)
    warcprox_thread.start()

    def fin():
        logging.info('stopping warcprox')
        warcprox_.stop.set()
        warcprox_thread.join()
        for f in (ca_file, ca_dir, options.directory, playback_index_db_file):
            if os.path.isdir(f):
                logging.info('deleting directory {}'.format(f))
                shutil.rmtree(f)
            else:
                logging.info('deleting file {}'.format(f))
                os.unlink(f)
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

def _poll_playback_until(playback_proxies, url, status, timeout_sec):
    start = time.time()
    # check playback (warc writing is asynchronous, give it up to 10 sec)
    while time.time() - start < timeout_sec:
        response = requests.get(url, proxies=playback_proxies, verify=False)
        if response.status_code == status:
            break
        time.sleep(0.5)
    return response

def test_archive_and_playback_http_url(http_daemon, archiving_proxies, playback_proxies):
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

    response = _poll_playback_until(playback_proxies, url, status=200, timeout_sec=10)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'a!'
    assert response.content == b'I am the warcprox test payload! bbbbbbbbbb!\n'

def test_archive_and_playback_https_url(https_daemon, archiving_proxies, playback_proxies):
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

    # test playback
    response = _poll_playback_until(playback_proxies, url, status=200, timeout_sec=10)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'c!'
    assert response.content == b'I am the warcprox test payload! dddddddddd!\n'

# test dedup of same http url with same payload
def test_dedup_http(http_daemon, warcprox_, archiving_proxies, playback_proxies):
    url = 'http://localhost:{}/e/f'.format(http_daemon.server_port)

    # ensure playback fails before archiving
    response = requests.get(url, proxies=playback_proxies, verify=False)
    assert response.status_code == 404
    assert response.content == b'404 Not in Archive\n'

    # check not in dedup db
    dedup_lookup = warcprox_.warc_writer_thread.dedup_db.lookup(b'sha1:65e1216acfd220f0292715e74bd7a1ec35c99dfc')
    assert dedup_lookup is None

    # archive
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'e!'
    assert response.content == b'I am the warcprox test payload! ffffffffff!\n'

    # test playback
    response = _poll_playback_until(playback_proxies, url, status=200, timeout_sec=10)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'e!'
    assert response.content == b'I am the warcprox test payload! ffffffffff!\n'

    # wait for writer thread to process
    time.sleep(0.5)
    while not warcprox_.warc_writer_thread.idle:
        time.sleep(0.5)
    time.sleep(0.5)

    # check in dedup db
    # {u'id': u'<urn:uuid:e691dc0f-4bb9-4ad8-9afb-2af836aa05e4>', u'url': u'https://localhost:62841/c/d', u'date': u'2013-11-22T00:14:37Z'}
    dedup_lookup = warcprox_.warc_writer_thread.dedup_db.lookup(b'sha1:65e1216acfd220f0292715e74bd7a1ec35c99dfc')
    assert dedup_lookup['url'] == url.encode('ascii')
    assert re.match(br'^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$', dedup_lookup['id'])
    assert re.match(br'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', dedup_lookup['date'])
    record_id = dedup_lookup['id']
    dedup_date = dedup_lookup['date']

    # need revisit to have a later timestamp than original, else playing
    # back the latest record might not hit the revisit
    time.sleep(1.5)

    # fetch & archive revisit
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'e!'
    assert response.content == b'I am the warcprox test payload! ffffffffff!\n'

    # wait for writer thread to process
    time.sleep(0.5)
    while not warcprox_.warc_writer_thread.idle:
        time.sleep(0.5)
    time.sleep(0.5)

    # check in dedup db (no change from prev)
    dedup_lookup = warcprox_.warc_writer_thread.dedup_db.lookup(b'sha1:65e1216acfd220f0292715e74bd7a1ec35c99dfc')
    assert dedup_lookup['url'] == url.encode('ascii')
    assert dedup_lookup['id'] == record_id
    assert dedup_lookup['date'] == dedup_date

    # test playback
    logging.debug('testing playback of revisit of {}'.format(url))
    response = _poll_playback_until(playback_proxies, url, status=200, timeout_sec=10)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'e!'
    assert response.content == b'I am the warcprox test payload! ffffffffff!\n'
    # XXX how to check dedup was used?

# test dedup of same https url with same payload
def test_dedup_https(https_daemon, warcprox_, archiving_proxies, playback_proxies):
    url = 'https://localhost:{}/g/h'.format(https_daemon.server_port)

    # ensure playback fails before archiving
    response = requests.get(url, proxies=playback_proxies, verify=False)
    assert response.status_code == 404
    assert response.content == b'404 Not in Archive\n'

    # check not in dedup db
    dedup_lookup = warcprox_.warc_writer_thread.dedup_db.lookup(b'sha1:5b4efa64fdb308ec06ae56a9beba155a6f734b89')
    assert dedup_lookup is None

    # archive
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'g!'
    assert response.content == b'I am the warcprox test payload! hhhhhhhhhh!\n'

    # test playback
    response = _poll_playback_until(playback_proxies, url, status=200, timeout_sec=10)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'g!'
    assert response.content == b'I am the warcprox test payload! hhhhhhhhhh!\n'

    # wait for writer thread to process
    time.sleep(0.5)
    while not warcprox_.warc_writer_thread.idle:
        time.sleep(0.5)
    time.sleep(0.5)

    # check in dedup db
    # {u'id': u'<urn:uuid:e691dc0f-4bb9-4ad8-9afb-2af836aa05e4>', u'url': u'https://localhost:62841/c/d', u'date': u'2013-11-22T00:14:37Z'}
    dedup_lookup = warcprox_.warc_writer_thread.dedup_db.lookup(b'sha1:5b4efa64fdb308ec06ae56a9beba155a6f734b89')
    assert dedup_lookup['url'] == url.encode('ascii')
    assert re.match(br'^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$', dedup_lookup['id'])
    assert re.match(br'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', dedup_lookup['date'])
    record_id = dedup_lookup['id']
    dedup_date = dedup_lookup['date']

    # need revisit to have a later timestamp than original, else playing
    # back the latest record might not hit the revisit
    time.sleep(1.5)

    # fetch & archive revisit
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'g!'
    assert response.content == b'I am the warcprox test payload! hhhhhhhhhh!\n'

    # wait for writer thread to process
    time.sleep(0.5)
    while not warcprox_.warc_writer_thread.idle:
        time.sleep(0.5)
    time.sleep(0.5)

    # check in dedup db (no change from prev)
    dedup_lookup = warcprox_.warc_writer_thread.dedup_db.lookup(b'sha1:5b4efa64fdb308ec06ae56a9beba155a6f734b89')
    assert dedup_lookup['url'] == url.encode('ascii')
    assert dedup_lookup['id'] == record_id
    assert dedup_lookup['date'] == dedup_date

    # test playback
    logging.debug('testing playback of revisit of {}'.format(url))
    response = _poll_playback_until(playback_proxies, url, status=200, timeout_sec=10)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'g!'
    assert response.content == b'I am the warcprox test payload! hhhhhhhhhh!\n'
    # XXX how to check dedup was used?

def test_limits(http_daemon, warcprox_, archiving_proxies):
    url = 'http://localhost:{}/i/j'.format(http_daemon.server_port)
    request_meta = {"stats":{"buckets":["job1"]},"limits":{"job1.total.urls":10}}
    headers = {"Warcprox-Meta": json.dumps(request_meta)}

    response = requests.get(url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'i!'
    assert response.content == b'I am the warcprox test payload! jjjjjjjjjj!\n'

    # wait for writer thread to process
    time.sleep(0.5)
    while not warcprox_.warc_writer_thread.idle:
        time.sleep(0.5)
    time.sleep(0.5)

    for i in range(9):
        response = requests.get(url, proxies=archiving_proxies, headers=headers, stream=True)
        assert response.status_code == 200
        assert response.headers['warcprox-test-header'] == 'i!'
        assert response.content == b'I am the warcprox test payload! jjjjjjjjjj!\n'

    # wait for writer thread to process
    time.sleep(0.5)
    while not warcprox_.warc_writer_thread.idle:
        time.sleep(0.5)
    time.sleep(2.5)

    response = requests.get(url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 420
    assert response.reason == "Reached limit"
    expected_response_meta = {'reached-limit': {'job1.total.urls': 10}, 'stats': {'job1': {'bucket': 'job1', 'revisit': {'wire_bytes': 1215, 'urls': 9}, 'total': {'wire_bytes': 1350, 'urls': 10}, 'new': {'wire_bytes': 135, 'urls': 1}}}}
    assert json.loads(response.headers["warcprox-meta"]) == expected_response_meta
    assert response.headers["content-type"] == "text/plain;charset=utf-8"
    assert response.raw.data == b"request rejected by warcprox: reached limit job1.total.urls=10\n"

def test_dedup_buckets(https_daemon, http_daemon, warcprox_, archiving_proxies, playback_proxies):
    url1 = 'http://localhost:{}/k/l'.format(http_daemon.server_port)
    url2 = 'https://localhost:{}/k/l'.format(https_daemon.server_port)

    # archive url1 bucket_a
    headers = {"Warcprox-Meta": json.dumps({"warc-prefix":"test_dedup_buckets","captures-bucket":"bucket_a"})}
    response = requests.get(url1, proxies=archiving_proxies, verify=False, headers=headers)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'k!'
    assert response.content == b'I am the warcprox test payload! llllllllll!\n'

    # wait for writer thread to process
    time.sleep(0.5)
    while not warcprox_.warc_writer_thread.idle:
        time.sleep(0.5)
    time.sleep(0.5)

    # check url1 in dedup db bucket_a
    dedup_lookup = warcprox_.warc_writer_thread.dedup_db.lookup(b'sha1:bc3fac8847c9412f49d955e626fb58a76befbf81', bucket="bucket_a")
    assert dedup_lookup['url'] == url1.encode('ascii')
    assert re.match(br'^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$', dedup_lookup['id'])
    assert re.match(br'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', dedup_lookup['date'])
    record_id = dedup_lookup['id']
    dedup_date = dedup_lookup['date']

    # check url1 not in dedup db bucket_b
    dedup_lookup = warcprox_.warc_writer_thread.dedup_db.lookup(b'sha1:bc3fac8847c9412f49d955e626fb58a76befbf81', bucket="bucket_b")
    assert dedup_lookup is None

    # archive url2 bucket_b
    headers = {"Warcprox-Meta": json.dumps({"warc-prefix":"test_dedup_buckets","captures-bucket":"bucket_b"})}
    response = requests.get(url2, proxies=archiving_proxies, verify=False, headers=headers)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'k!'
    assert response.content == b'I am the warcprox test payload! llllllllll!\n'

    # wait for writer thread to process
    time.sleep(0.5)
    while not warcprox_.warc_writer_thread.idle:
        time.sleep(0.5)
    time.sleep(0.5)

    # check url2 in dedup db bucket_b
    dedup_lookup = warcprox_.warc_writer_thread.dedup_db.lookup(b'sha1:bc3fac8847c9412f49d955e626fb58a76befbf81', bucket="bucket_b")
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

    # archive url1 bucket_b
    headers = {"Warcprox-Meta": json.dumps({"warc-prefix":"test_dedup_buckets","captures-bucket":"bucket_b"})}
    response = requests.get(url1, proxies=archiving_proxies, verify=False, headers=headers)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'k!'
    assert response.content == b'I am the warcprox test payload! llllllllll!\n'

    # wait for writer thread to process
    time.sleep(0.5)
    while not warcprox_.warc_writer_thread.idle:
        time.sleep(0.5)
    time.sleep(0.5)

    # close the warc
    assert warcprox_.warc_writer_thread.writer_pool.warc_writers["test_dedup_buckets"]
    writer = warcprox_.warc_writer_thread.writer_pool.warc_writers["test_dedup_buckets"]
    warc_path = os.path.join(writer.directory, writer._f_finalname)
    warcprox_.warc_writer_thread.writer_pool.warc_writers["test_dedup_buckets"].close_writer()
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

# XXX this test relies on a tor proxy running at localhost:9050 with a working
# connection to the internet, and relies on a third party site (facebook) being
# up and behaving a certain way
def _test_tor_onion(archiving_proxies):
    response = requests.get('http://www.facebookcorewwwi.onion/',
        proxies=archiving_proxies, verify=False, allow_redirects=False)
    assert response.status_code == 302

    response = requests.get('https://www.facebookcorewwwi.onion/',
        proxies=archiving_proxies, verify=False, allow_redirects=False)
    assert response.status_code == 200

if __name__ == '__main__':
    pytest.main()

