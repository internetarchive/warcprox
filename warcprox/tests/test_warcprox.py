#!/usr/bin/env python
# vim: set sw=4 et:

import unittest
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

try:
    import http.server as http_server
except ImportError:
    import BaseHTTPServer as http_server

try:
    import queue
except ImportError:
    import Queue as queue

import warcprox.controller
import warcprox.warcprox
import warcprox.certauth
import warcprox.playback
import warcprox.warcwriter
import warcprox.dedup

class TestHttpRequestHandler(http_server.BaseHTTPRequestHandler):
    logger = logging.getLogger('TestHttpRequestHandler')

    def do_GET(self):
        self.logger.info('GET {}'.format(self.path))

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


class WarcproxTest(unittest.TestCase):
    logger = logging.getLogger('WarcproxTest')

    def __init__(self, methodName='runTest'):
        self.__cert = None
        unittest.TestCase.__init__(self, methodName)

    @property
    def _cert(self):
        if self.__cert is None:
            f = tempfile.NamedTemporaryFile(prefix='warcprox-test-https-', suffix='.pem', delete=False)
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

                self.logger.info('generated self-signed certificate {}'.format(f.name))
                self.__cert = f.name
            finally:
                f.close()

        return self.__cert


    def _start_http_servers(self):
        self.http_daemon = http_server.HTTPServer(('localhost', 0),
                RequestHandlerClass=TestHttpRequestHandler)
        self.logger.info('starting http://{}:{}'.format(self.http_daemon.server_address[0], self.http_daemon.server_address[1]))
        self.http_daemon_thread = threading.Thread(name='HttpdThread',
                target=self.http_daemon.serve_forever)
        self.http_daemon_thread.start()

        # http://www.piware.de/2011/01/creating-an-https-server-in-python/
        self.https_daemon = http_server.HTTPServer(('localhost', 0),
                RequestHandlerClass=TestHttpRequestHandler)
        # self.https_daemon.socket = ssl.wrap_socket(httpd.socket, certfile='path/to/localhost.pem', server_side=True)
        self.https_daemon.socket = ssl.wrap_socket(self.https_daemon.socket, certfile=self._cert, server_side=True)
        self.logger.info('starting https://{}:{}'.format(self.https_daemon.server_address[0], self.https_daemon.server_address[1]))
        self.https_daemon_thread = threading.Thread(name='HttpdThread',
                target=self.https_daemon.serve_forever)
        self.https_daemon_thread.start()


    def _start_warcprox(self):
        f = tempfile.NamedTemporaryFile(prefix='warcprox-test-ca-', suffix='.pem', delete=True)
        f.close() # delete it, or CertificateAuthority will try to read it
        self._ca_file = f.name
        self._ca_dir = tempfile.mkdtemp(prefix='warcprox-test-', suffix='-ca')
        ca = warcprox.certauth.CertificateAuthority(self._ca_file, self._ca_dir)

        recorded_url_q = queue.Queue()

        proxy = warcprox.warcprox.WarcProxy(server_address=('localhost', 0), ca=ca,
                recorded_url_q=recorded_url_q)

        self._warcs_dir = tempfile.mkdtemp(prefix='warcprox-test-warcs-')

        f = tempfile.NamedTemporaryFile(prefix='warcprox-test-playback-index-', suffix='.db', delete=False)
        f.close()
        self._playback_index_db_file = f.name
        playback_index_db = warcprox.playback.PlaybackIndexDb(self._playback_index_db_file)
        playback_proxy = warcprox.playback.PlaybackProxy(server_address=('localhost', 0), ca=ca,
                playback_index_db=playback_index_db, warcs_dir=self._warcs_dir)

        f = tempfile.NamedTemporaryFile(prefix='warcprox-test-dedup-', suffix='.db', delete=False)
        f.close()
        self._dedup_db_file = f.name
        dedup_db = warcprox.dedup.DedupDb(self._dedup_db_file)

        warc_writer = warcprox.warcwriter.WarcWriter(directory=self._warcs_dir,
                port=proxy.server_port, dedup_db=dedup_db,
                playback_index_db=playback_index_db)
        warc_writer_thread = warcprox.warcwriter.WarcWriterThread(recorded_url_q=recorded_url_q,
                warc_writer=warc_writer)

        self.warcprox = warcprox.controller.WarcproxController(proxy, warc_writer_thread, playback_proxy)
        self.logger.info('starting warcprox')
        self.warcprox_thread = threading.Thread(name='WarcproxThread',
                target=self.warcprox.run_until_shutdown)
        self.warcprox_thread.start()


    def setUp(self):
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                format='%(asctime)s %(levelname)s %(process)d %(threadName)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')

        self._start_http_servers()
        self._start_warcprox()

        archiving_proxy = 'http://localhost:{}'.format(self.warcprox.proxy.server_port)
        self.archiving_proxies = {'http':archiving_proxy, 'https':archiving_proxy}

        playback_proxy = 'http://localhost:{}'.format(self.warcprox.playback_proxy.server_port)
        self.playback_proxies = {'http':playback_proxy, 'https':playback_proxy}


    def tearDown(self):
        self.logger.info('stopping warcprox')
        self.warcprox.stop.set()

        self.logger.info('stopping http and https daemons')
        self.http_daemon.shutdown()
        self.https_daemon.shutdown()
        self.http_daemon.server_close()
        self.https_daemon.server_close()

        # Have to wait for threads to finish or the threads will try to use
        # variables that no longer exist, resulting in errors like this:
        #   File "/usr/lib/python2.7/SocketServer.py", line 235, in serve_forever
        #       r, w, e = _eintr_retry(select.select, [self], [], [],
        #   AttributeError: 'NoneType' object has no attribute 'select'
        self.http_daemon_thread.join()
        self.https_daemon_thread.join()
        self.warcprox_thread.join()

        for f in (self.__cert, self._ca_file, self._ca_dir, self._warcs_dir, self._playback_index_db_file, self._dedup_db_file):
            if os.path.isdir(f):
                self.logger.info('deleting directory {}'.format(f))
                shutil.rmtree(f)
            else:
                self.logger.info('deleting file {}'.format(f))
                os.unlink(f)


    def _test_httpds_no_proxy(self):
        url = 'http://localhost:{}/'.format(self.http_daemon.server_port)
        response = requests.get(url)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b'404 Not Found\n')

        url = 'https://localhost:{}/'.format(self.https_daemon.server_port)
        response = requests.get(url, verify=False)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b'404 Not Found\n')

        url = 'http://localhost:{}/a/b'.format(self.http_daemon.server_port)
        response = requests.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'a!')
        self.assertEqual(response.content, b'I am the warcprox test payload! bbbbbbbbbb!\n')

        url = 'https://localhost:{}/c/d'.format(self.https_daemon.server_port)
        response = requests.get(url, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'c!')
        self.assertEqual(response.content, b'I am the warcprox test payload! dddddddddd!\n')


    def poll_playback_until(self, url, status, timeout_sec):
        start = time.time()
        # check playback (warc writing is asynchronous, give it up to 10 sec)
        while time.time() - start < timeout_sec:
            response = requests.get(url, proxies=self.playback_proxies, verify=False)
            if response.status_code == status:
                break
            time.sleep(0.5)

        return response


    def _test_archive_and_playback_http_url(self):
        url = 'http://localhost:{}/a/b'.format(self.http_daemon.server_port)

        # ensure playback fails before archiving
        response = requests.get(url, proxies=self.playback_proxies)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b'404 Not in Archive\n')

        # archive
        response = requests.get(url, proxies=self.archiving_proxies)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'a!')
        self.assertEqual(response.content, b'I am the warcprox test payload! bbbbbbbbbb!\n')

        response = self.poll_playback_until(url, status=200, timeout_sec=10)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'a!')
        self.assertEqual(response.content, b'I am the warcprox test payload! bbbbbbbbbb!\n')


    def _test_archive_and_playback_https_url(self):
        url = 'https://localhost:{}/c/d'.format(self.https_daemon.server_port)

        # ensure playback fails before archiving
        response = requests.get(url, proxies=self.playback_proxies, verify=False)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b'404 Not in Archive\n')

        # fetch & archive response
        response = requests.get(url, proxies=self.archiving_proxies, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'c!')
        self.assertEqual(response.content, b'I am the warcprox test payload! dddddddddd!\n')

        # test playback
        response = self.poll_playback_until(url, status=200, timeout_sec=10)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'c!')
        self.assertEqual(response.content, b'I am the warcprox test payload! dddddddddd!\n')


    # test dedup of same http url with same payload
    def _test_dedup_http(self):
        url = 'http://localhost:{}/e/f'.format(self.http_daemon.server_port)

        # ensure playback fails before archiving
        response = requests.get(url, proxies=self.playback_proxies, verify=False)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b'404 Not in Archive\n')

        # check not in dedup db
        dedup_lookup = self.warcprox.warc_writer_thread.warc_writer.dedup_db.lookup(b'sha1:65e1216acfd220f0292715e74bd7a1ec35c99dfc')
        self.assertIsNone(dedup_lookup)

        # archive
        response = requests.get(url, proxies=self.archiving_proxies, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'e!')
        self.assertEqual(response.content, b'I am the warcprox test payload! ffffffffff!\n')

        # test playback
        response = self.poll_playback_until(url, status=200, timeout_sec=10)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'e!')
        self.assertEqual(response.content, b'I am the warcprox test payload! ffffffffff!\n')

        # check in dedup db
        # {u'i': u'<urn:uuid:e691dc0f-4bb9-4ad8-9afb-2af836aa05e4>', u'u': u'https://localhost:62841/c/d', u'd': u'2013-11-22T00:14:37Z'}
        dedup_lookup = self.warcprox.warc_writer_thread.warc_writer.dedup_db.lookup(b'sha1:65e1216acfd220f0292715e74bd7a1ec35c99dfc')
        self.assertEqual(dedup_lookup['u'], url.encode('ascii'))
        self.assertRegexpMatches(dedup_lookup['i'], br'^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$')
        self.assertRegexpMatches(dedup_lookup['d'], br'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
        record_id = dedup_lookup['i']
        dedup_date = dedup_lookup['d']

        # need revisit to have a later timestamp than original, else playing
        # back the latest record might not hit the revisit
        time.sleep(1.5)

        # fetch & archive revisit
        response = requests.get(url, proxies=self.archiving_proxies, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'e!')
        self.assertEqual(response.content, b'I am the warcprox test payload! ffffffffff!\n')

        # XXX need to give warc writer thread a chance, and we don't have any change to poll for :-\
        time.sleep(2.0)

        # check in dedup db (no change from prev)
        dedup_lookup = self.warcprox.warc_writer_thread.warc_writer.dedup_db.lookup(b'sha1:65e1216acfd220f0292715e74bd7a1ec35c99dfc')
        self.assertEqual(dedup_lookup['u'], url.encode('ascii'))
        self.assertEqual(dedup_lookup['i'], record_id)
        self.assertEqual(dedup_lookup['d'], dedup_date)

        # test playback
        self.logger.debug('testing playback of revisit of {}'.format(url))
        response = self.poll_playback_until(url, status=200, timeout_sec=10)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'e!')
        self.assertEqual(response.content, b'I am the warcprox test payload! ffffffffff!\n')
        # XXX how to check dedup was used?


    # test dedup of same https url with same payload
    def _test_dedup_https(self):
        url = 'https://localhost:{}/g/h'.format(self.https_daemon.server_port)

        # ensure playback fails before archiving
        response = requests.get(url, proxies=self.playback_proxies, verify=False)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b'404 Not in Archive\n')

        # check not in dedup db
        dedup_lookup = self.warcprox.warc_writer_thread.warc_writer.dedup_db.lookup(b'sha1:5b4efa64fdb308ec06ae56a9beba155a6f734b89')
        self.assertIsNone(dedup_lookup)

        # archive
        response = requests.get(url, proxies=self.archiving_proxies, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'g!')
        self.assertEqual(response.content, b'I am the warcprox test payload! hhhhhhhhhh!\n')

        # test playback
        response = self.poll_playback_until(url, status=200, timeout_sec=10)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'g!')
        self.assertEqual(response.content, b'I am the warcprox test payload! hhhhhhhhhh!\n')

        # check in dedup db
        # {u'i': u'<urn:uuid:e691dc0f-4bb9-4ad8-9afb-2af836aa05e4>', u'u': u'https://localhost:62841/c/d', u'd': u'2013-11-22T00:14:37Z'}
        dedup_lookup = self.warcprox.warc_writer_thread.warc_writer.dedup_db.lookup(b'sha1:5b4efa64fdb308ec06ae56a9beba155a6f734b89')
        self.assertEqual(dedup_lookup['u'], url.encode('ascii'))
        self.assertRegexpMatches(dedup_lookup['i'], br'^<urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}>$')
        self.assertRegexpMatches(dedup_lookup['d'], br'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
        record_id = dedup_lookup['i']
        dedup_date = dedup_lookup['d']

        # need revisit to have a later timestamp than original, else playing
        # back the latest record might not hit the revisit
        time.sleep(1.5)

        # fetch & archive revisit
        response = requests.get(url, proxies=self.archiving_proxies, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'g!')
        self.assertEqual(response.content, b'I am the warcprox test payload! hhhhhhhhhh!\n')

        # XXX need to give warc writer thread a chance, and we don't have any change to poll for :-\
        time.sleep(2.0)

        # check in dedup db (no change from prev)
        dedup_lookup = self.warcprox.warc_writer_thread.warc_writer.dedup_db.lookup(b'sha1:5b4efa64fdb308ec06ae56a9beba155a6f734b89')
        self.assertEqual(dedup_lookup['u'], url.encode('ascii'))
        self.assertEqual(dedup_lookup['i'], record_id)
        self.assertEqual(dedup_lookup['d'], dedup_date)

        # test playback
        self.logger.debug('testing playback of revisit of {}'.format(url))
        response = self.poll_playback_until(url, status=200, timeout_sec=10)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'g!')
        self.assertEqual(response.content, b'I am the warcprox test payload! hhhhhhhhhh!\n')
        # XXX how to check dedup was used?


    # run everything from here, otherwise it wants to setUp() and tearDown
    # around each test
    def runTest(self):
        self._test_httpds_no_proxy()
        self._test_archive_and_playback_http_url()
        self._test_archive_and_playback_https_url()
        self._test_dedup_http()
        self._test_dedup_https()
        # self._test_dedup_mixed_http()
        # self._test_dedup_mixed_https()


if __name__ == '__main__':
    unittest.main()

