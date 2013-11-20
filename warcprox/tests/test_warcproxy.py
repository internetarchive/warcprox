# vim: set sw=4 et:

import unittest
import BaseHTTPServer
import threading
import time
from warcprox import warcprox
import logging
import sys

class WarcproxTest(unittest.TestCase):
    logger = logging.getLogger('WarcproxTest')

    def setUp(self):
        logging.basicConfig(stream=sys.stdout, level=logging.INFO, 
                format='%(asctime)s %(process)d %(threadName)s %(levelname)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')

        self.httpd = BaseHTTPServer.HTTPServer(('localhost', 0), 
                RequestHandlerClass=BaseHTTPServer.BaseHTTPRequestHandler)
        self.logger.info('starting httpd on {}:{}'.format(self.httpd.server_address[0], self.httpd.server_address[1]))
        self.httpd_thread = threading.Thread(name='HttpdThread',
                target=self.httpd.serve_forever)
        self.httpd_thread.start()

        self.warcprox = warcprox.WarcproxController()
        self.logger.info('starting warcprox')
        self.warcprox_thread = threading.Thread(name='WarcproxThread',
                target=self.warcprox.run_until_shutdown)
        self.warcprox_thread.start()

    def tearDown(self):
        self.logger.info('stopping warcprox')
        self.warcprox.stop.set()

        self.logger.info('stopping httpd')
        self.httpd.shutdown()
        self.httpd.server_close()

        # Have to wait for threads to finish or the threads will try to use
        # variables that have been deleted, resulting in errors like this:
        #   File "/usr/lib/python2.7/SocketServer.py", line 235, in serve_forever
        #       r, w, e = _eintr_retry(select.select, [self], [], [],
        #   AttributeError: 'NoneType' object has no attribute 'select'
        self.httpd_thread.join()
        self.warcprox_thread.join()

    def test_something(self):
        self.logger.info('sleeping for 5 seconds...')
        try:
            time.sleep(5)
        except:
            self.logger.info('interrupted')
        self.logger.info('finished sleeping')

if __name__ == '__main__':
    unittest.main()

