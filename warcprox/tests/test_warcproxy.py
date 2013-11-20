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
            f = tempfile.NamedTemporaryFile(delete=False)
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


    def setUp(self):
        logging.basicConfig(stream=sys.stdout, level=logging.INFO, 
                format='%(asctime)s %(process)d %(threadName)s %(levelname)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')

        # start test http server
        self.http_daemon = BaseHTTPServer.HTTPServer(('localhost', 0), 
                RequestHandlerClass=TestHttpRequestHandler)
        self.logger.info('starting http_daemon on {}:{}'.format(self.http_daemon.server_address[0], self.http_daemon.server_address[1]))
        self.http_daemon_thread = threading.Thread(name='HttpdThread',
                target=self.http_daemon.serve_forever)
        self.http_daemon_thread.start()

        # start test https
        # http://www.piware.de/2011/01/creating-an-https-server-in-python/
        self.https_daemon = BaseHTTPServer.HTTPServer(('localhost', 0), 
                RequestHandlerClass=TestHttpRequestHandler)
        # self.https_daemon.socket = ssl.wrap_socket(httpd.socket, certfile='path/to/localhost.pem', server_side=True)
        self.https_daemon.socket = ssl.wrap_socket(self.https_daemon.socket, certfile=self._cert, server_side=True)
        self.logger.info('starting https_daemon on {}:{}'.format(self.https_daemon.server_address[0], self.https_daemon.server_address[1]))
        self.https_daemon_thread = threading.Thread(name='HttpdThread',
                target=self.https_daemon.serve_forever)
        self.https_daemon_thread.start()

        # start warcprox
        self.warcprox = warcprox.WarcproxController()
        self.logger.info('starting warcprox')
        self.warcprox_thread = threading.Thread(name='WarcproxThread',
                target=self.warcprox.run_until_shutdown)
        self.warcprox_thread.start()


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

        os.unlink(self._cert)
        self.__cert = None


    def test_something(self):
        self.logger.info('sleeping for 100 seconds...')
        try:
            time.sleep(100)
        except:
            self.logger.info('interrupted')
        self.logger.info('finished sleeping')

if __name__ == '__main__':
    unittest.main()

