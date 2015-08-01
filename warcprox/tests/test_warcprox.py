#!/usr/bin/env python
# vim: set sw=4 et:

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

@pytest.fixture()
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

@pytest.fixture()
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

@pytest.fixture()
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

@pytest.fixture()
def warcprox_(request):
    f = tempfile.NamedTemporaryFile(prefix='warcprox-test-ca-', suffix='.pem', delete=True)
    f.close() # delete it, or CertificateAuthority will try to read it
    ca_file = f.name
    ca_dir = tempfile.mkdtemp(prefix='warcprox-test-', suffix='-ca')
    ca = certauth.certauth.CertificateAuthority(ca_file, ca_dir, 'warcprox-test')

    recorded_url_q = queue.Queue()

    f = tempfile.NamedTemporaryFile(prefix='warcprox-test-stats-', suffix='.db', delete=False)
    f.close()
    stats_db_file = f.name
    stats_db = warcprox.stats.StatsDb(stats_db_file)

    proxy = warcprox.warcproxy.WarcProxy(server_address=('localhost', 0), ca=ca,
            recorded_url_q=recorded_url_q, stats_db=stats_db)

    warcs_dir = tempfile.mkdtemp(prefix='warcprox-test-warcs-')

    f = tempfile.NamedTemporaryFile(prefix='warcprox-test-playback-index-', suffix='.db', delete=False)
    f.close()
    playback_index_db_file = f.name
    playback_index_db = warcprox.playback.PlaybackIndexDb(playback_index_db_file)
    playback_proxy = warcprox.playback.PlaybackProxy(server_address=('localhost', 0), ca=ca,
            playback_index_db=playback_index_db, warcs_dir=warcs_dir)

    f = tempfile.NamedTemporaryFile(prefix='warcprox-test-dedup-', suffix='.db', delete=False)
    f.close()
    dedup_db_file = f.name
    dedup_db = warcprox.dedup.DedupDb(dedup_db_file)

    default_warc_writer = warcprox.writer.WarcWriter(directory=warcs_dir,
            port=proxy.server_port)
    writer_pool = warcprox.writer.WarcWriterPool(default_warc_writer)
    warc_writer_thread = warcprox.writerthread.WarcWriterThread(
            recorded_url_q=recorded_url_q, writer_pool=writer_pool,
            dedup_db=dedup_db, playback_index_db=playback_index_db,
            stats_db=stats_db)

    warcprox_ = warcprox.controller.WarcproxController(proxy, warc_writer_thread, playback_proxy)
    logging.info('starting warcprox')
    warcprox_thread = threading.Thread(name='WarcproxThread',
            target=warcprox_.run_until_shutdown)
    warcprox_thread.start()

    def fin():
        logging.info('stopping warcprox')
        warcprox_.stop.set()
        warcprox_thread.join()
        for f in (ca_file, ca_dir, warcs_dir, playback_index_db_file, dedup_db_file, stats_db_file):
            if os.path.isdir(f):
                logging.info('deleting directory {}'.format(f))
                shutil.rmtree(f)
            else:
                logging.info('deleting file {}'.format(f))
                os.unlink(f)
    request.addfinalizer(fin)

    return warcprox_

@pytest.fixture()
def archiving_proxies(warcprox_):
    archiving_proxy = 'http://localhost:{}'.format(warcprox_.proxy.server_port)
    return {'http':archiving_proxy, 'https':archiving_proxy}

@pytest.fixture()
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

    # check in dedup db
    # {u'i': u'<urn:uuid:e691dc0f-4bb9-4ad8-9afb-2af836aa05e4>', u'u': u'https://localhost:62841/c/d', u'd': u'2013-11-22T00:14:37Z'}
    dedup_lookup = warcprox_.warc_writer_thread.dedup_db.lookup(b'sha1:65e1216acfd220f0292715e74bd7a1ec35c99dfc')
    assert dedup_lookup['u'] == url.encode('ascii')
    assert re.match(br'^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$', dedup_lookup['i'])
    assert re.match(br'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', dedup_lookup['d'])
    record_id = dedup_lookup['i']
    dedup_date = dedup_lookup['d']

    # need revisit to have a later timestamp than original, else playing
    # back the latest record might not hit the revisit
    time.sleep(1.5)

    # fetch & archive revisit
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'e!'
    assert response.content == b'I am the warcprox test payload! ffffffffff!\n'

    # XXX need to give warc writer thread a chance, and we don't have any change to poll for :-\
    time.sleep(2.0)

    # check in dedup db (no change from prev)
    dedup_lookup = warcprox_.warc_writer_thread.dedup_db.lookup(b'sha1:65e1216acfd220f0292715e74bd7a1ec35c99dfc')
    assert dedup_lookup['u'] == url.encode('ascii')
    assert dedup_lookup['i'] == record_id
    assert dedup_lookup['d'] == dedup_date

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

    # check in dedup db
    # {u'i': u'<urn:uuid:e691dc0f-4bb9-4ad8-9afb-2af836aa05e4>', u'u': u'https://localhost:62841/c/d', u'd': u'2013-11-22T00:14:37Z'}
    dedup_lookup = warcprox_.warc_writer_thread.dedup_db.lookup(b'sha1:5b4efa64fdb308ec06ae56a9beba155a6f734b89')
    assert dedup_lookup['u'] == url.encode('ascii')
    assert re.match(br'^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$', dedup_lookup['i'])
    assert re.match(br'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', dedup_lookup['d'])
    record_id = dedup_lookup['i']
    dedup_date = dedup_lookup['d']

    # need revisit to have a later timestamp than original, else playing
    # back the latest record might not hit the revisit
    time.sleep(1.5)

    # fetch & archive revisit
    response = requests.get(url, proxies=archiving_proxies, verify=False)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'g!'
    assert response.content == b'I am the warcprox test payload! hhhhhhhhhh!\n'

    # XXX need to give warc writer thread a chance, and we don't have any change to poll for :-\
    time.sleep(2.0)

    # check in dedup db (no change from prev)
    dedup_lookup = warcprox_.warc_writer_thread.dedup_db.lookup(b'sha1:5b4efa64fdb308ec06ae56a9beba155a6f734b89')
    assert dedup_lookup['u'] == url.encode('ascii')
    assert dedup_lookup['i'] == record_id
    assert dedup_lookup['d'] == dedup_date

    # test playback
    logging.debug('testing playback of revisit of {}'.format(url))
    response = _poll_playback_until(playback_proxies, url, status=200, timeout_sec=10)
    assert response.status_code == 200
    assert response.headers['warcprox-test-header'] == 'g!'
    assert response.content == b'I am the warcprox test payload! hhhhhhhhhh!\n'
    # XXX how to check dedup was used?

def test_limits(http_daemon, archiving_proxies):
    url = 'http://localhost:{}/a/b'.format(http_daemon.server_port)
    request_meta = {"stats":{"buckets":["job1"],"limits":{"job1.total.urls":10}}}
    headers = {"Warcprox-Meta": json.dumps(request_meta)}

    for i in range(10):
        response = requests.get(url, proxies=archiving_proxies, headers=headers, stream=True)
        assert response.status_code == 200
        assert response.headers['warcprox-test-header'] == 'a!'
        assert response.content == b'I am the warcprox test payload! bbbbbbbbbb!\n'

    # XXX give warc writer thread a chance to update stats
    time.sleep(2.0)

    response = requests.get(url, proxies=archiving_proxies, headers=headers, stream=True)
    assert response.status_code == 420
    assert response.reason == "Reached limit"
    expected_response_meta = {'reached-limit': {'job1.total.urls': 10}, 'stats': {'job1': {'revisit': {'wire_bytes': 1215, 'urls': 9}, 'total': {'wire_bytes': 1350, 'urls': 10}, 'new': {'wire_bytes': 135, 'urls': 1}}}}
    assert json.loads(response.headers["warcprox-meta"]) == expected_response_meta
    assert response.headers["content-type"] == "text/plain;charset=utf-8"
    assert response.raw.data == b"request rejected by warcprox: reached limit job1.total.urls=10\n"

if __name__ == '__main__':
    pytest.main()

