#!/usr/bin/env python
# vim: set sw=4 et:

from warcprox import warcprox
import unittest
import BaseHTTPServer
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
import Queue
import requests

class TestHttpRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    logger = logging.getLogger('TestHttpRequestHandler')

    def do_GET(self):
        self.logger.info('GET {}'.format(self.path))

        m = re.match(r'^/([^/]+)/([^/]+)$', self.path)
        if m is not None:
            special_header = 'warcprox-test-header: {}!'.format(m.group(1))
            payload = 'I am the warcprox test payload! {}!\n'.format(10*m.group(2))
            headers = ('HTTP/1.1 200 OK\r\n'
                     +  'Content-Type: text/plain\r\n'
                     +  '{}\r\n'
                     +  'Content-Length: {}\r\n'
                     +  '\r\n').format(special_header, len(payload))
        else:
            payload = '404 Not Found\n'
            headers = ('HTTP/1.1 404 Not Found\r\n'
                     +  'Content-Type: text/plain\r\n'
                     +  'Content-Length: {}\r\n'
                     +  '\r\n').format(len(payload))

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
            f = tempfile.NamedTemporaryFile(prefix='warcprox-test', suffix='-https.pem', delete=False)
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
                self.__cert = f.name
            finally:
                f.close()

        return self.__cert


    def _start_http_servers(self):
        self.http_daemon = BaseHTTPServer.HTTPServer(('localhost', 0), 
                RequestHandlerClass=TestHttpRequestHandler)
        self.logger.info('starting http://{}:{}'.format(self.http_daemon.server_address[0], self.http_daemon.server_address[1]))
        self.http_daemon_thread = threading.Thread(name='HttpdThread',
                target=self.http_daemon.serve_forever)
        self.http_daemon_thread.start()

        # http://www.piware.de/2011/01/creating-an-https-server-in-python/
        self.https_daemon = BaseHTTPServer.HTTPServer(('localhost', 0), 
                RequestHandlerClass=TestHttpRequestHandler)
        # self.https_daemon.socket = ssl.wrap_socket(httpd.socket, certfile='path/to/localhost.pem', server_side=True)
        self.https_daemon.socket = ssl.wrap_socket(self.https_daemon.socket, certfile=self._cert, server_side=True)
        self.logger.info('starting https://{}:{}'.format(self.https_daemon.server_address[0], self.https_daemon.server_address[1]))
        self.https_daemon_thread = threading.Thread(name='HttpdThread',
                target=self.https_daemon.serve_forever)
        self.https_daemon_thread.start()


    def _start_warcprox(self):
        f = tempfile.NamedTemporaryFile(prefix='warcprox-test-', suffix='-ca.pem', delete=True)
        f.close() # delete it, or CertificateAuthority will try to read it
        self._ca_file = f.name
        self._ca_dir = tempfile.mkdtemp(prefix='warcprox-test-', suffix='-ca')
        ca = warcprox.CertificateAuthority(self._ca_file, self._ca_dir)

        recorded_url_q = Queue.Queue()

        proxy = warcprox.WarcProxy(server_address=('localhost', 0), ca=ca, 
                recorded_url_q=recorded_url_q)

        self._warcs_dir = tempfile.mkdtemp(prefix='warcprox-test-', suffix='-warcs')

        f = tempfile.NamedTemporaryFile(prefix='warcprox-test-', suffix='-playback-index.db', delete=False)
        f.close()
        self._playback_index_db_file = f.name
        playback_index_db = warcprox.PlaybackIndexDb(self._playback_index_db_file)
        playback_proxy = warcprox.PlaybackProxy(server_address=('localhost', 0), ca=ca, 
                playback_index_db=playback_index_db, warcs_dir=self._warcs_dir)

        f = tempfile.NamedTemporaryFile(prefix='warcprox-test-', suffix='-dedup.db', delete=False)
        f.close()
        self._dedup_db_file = f.name
        dedup_db = warcprox.DedupDb(self._dedup_db_file)

        warc_writer = warcprox.WarcWriterThread(recorded_url_q=recorded_url_q,
                directory=self._warcs_dir, port=proxy.server_port, 
                dedup_db=dedup_db, playback_index_db=playback_index_db)

        self.warcprox = warcprox.WarcproxController(proxy, warc_writer, playback_proxy)
        self.logger.info('starting warcprox')
        self.warcprox_thread = threading.Thread(name='WarcproxThread',
                target=self.warcprox.run_until_shutdown)
        self.warcprox_thread.start()


    def setUp(self):
        logging.basicConfig(stream=sys.stdout, level=logging.INFO, 
                format='%(asctime)s %(process)d %(threadName)s %(levelname)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')

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
                logging.info('deleting directory {}'.format(f))
                shutil.rmtree(f)
            else:
                logging.info('deleting file {}'.format(f))
                os.unlink(f)


    def _test_httpds_no_proxy(self):
        url = 'http://localhost:{}/'.format(self.http_daemon.server_port)
        response = requests.get(url)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, '404 Not Found\n')

        url = 'https://localhost:{}/'.format(self.https_daemon.server_port)
        response = requests.get(url, verify=False)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, '404 Not Found\n')

        url = 'http://localhost:{}/a/b'.format(self.http_daemon.server_port)
        response = requests.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'a!')
        self.assertEqual(response.content, 'I am the warcprox test payload! bbbbbbbbbb!\n')

        url = 'https://localhost:{}/c/d'.format(self.https_daemon.server_port)
        response = requests.get(url, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'c!')
        self.assertEqual(response.content, 'I am the warcprox test payload! dddddddddd!\n')


    def _test_archive_and_playback_http_url(self):
        url = 'http://localhost:{}/a/b'.format(self.http_daemon.server_port)

        # ensure playback fails before archiving
        response = requests.get(url, proxies=self.playback_proxies)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, '404 Not in Archive\n')

        # archive
        response = requests.get(url, proxies=self.archiving_proxies)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'a!')
        self.assertEqual(response.content, 'I am the warcprox test payload! bbbbbbbbbb!\n')

        # check playback (warc writing is asynchronous, give it up to 10 sec)
        for i in xrange(0,20):
            response = requests.get(url, proxies=self.playback_proxies)
            if response.status_code != 404:
                break
            time.sleep(0.5)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'a!')
        self.assertEqual(response.content, 'I am the warcprox test payload! bbbbbbbbbb!\n')


    def _test_archive_and_playback_https_url(self):
        url = 'https://localhost:{}/c/d'.format(self.https_daemon.server_port)

        # ensure playback fails before archiving
        response = requests.get(url, proxies=self.playback_proxies, verify=False)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, '404 Not in Archive\n')

        # archive
        response = requests.get(url, proxies=self.archiving_proxies, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'c!')
        self.assertEqual(response.content, 'I am the warcprox test payload! dddddddddd!\n')

        # check playback (warc writing is asynchronous, give it up to 10 sec)
        for i in xrange(0,20):
            response = requests.get(url, proxies=self.playback_proxies, verify=False)
            if response.status_code != 404:
                break
            time.sleep(0.5)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['warcprox-test-header'], 'c!')
        self.assertEqual(response.content, 'I am the warcprox test payload! dddddddddd!\n')


    # run everything from here, otherwise it wants to setUp() and tearDown
    # around each test
    def runTest(self):
        self._test_httpds_no_proxy()
        self._test_archive_and_playback_http_url()
        self._test_archive_and_playback_https_url()


if __name__ == '__main__':
    unittest.main()

