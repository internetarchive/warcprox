#!/usr/bin/env python
"""Useful for debugging. Does not write warcs."""

from __future__ import absolute_import

import warcprox
import logging
import sys
import argparse
import certauth
import queue
import socket
import os

class FakeQueue(object):
    logger = logging.getLogger("FakeQueue")
    def __init__(self, maxsize=0): pass
    def join(self): pass
    def qsize(self): return 0
    def empty(self): return True
    def full(self): return False
    def get(self, block=True, timeout=None): raise queue.Empty
    def put_nowait(self, item): return self.put(item, block=False)
    def get_nowait(self): return self.get(block=False)
    def put(self, recorded_url, block=True, timeout=None):
        logging.info("{} {} {} {} {} size={} {}".format(
            recorded_url.client_ip, recorded_url.status, recorded_url.method,
            recorded_url.url.decode("utf-8"), recorded_url.mimetype,
            recorded_url.size, warcprox.digest_str(recorded_url.response_recorder.payload_digest, False).decode('utf-8')))

def parse_args():
    prog = os.path.basename(sys.argv[0])
    arg_parser = argparse.ArgumentParser(prog=prog,
        description='%s - single threaded mitm http/s proxy, for debugging' % prog,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('-p', '--port', dest='port', default='8000',
        type=int, help='port to listen on')
    arg_parser.add_argument('-b', '--address', dest='address',
        default='localhost', help='address to listen on')
    arg_parser.add_argument('-c', '--cacert', dest='cacert',
        default='./{0}-warcprox-ca.pem'.format(socket.gethostname()),
        help='CA certificate file; if file does not exist, it will be created')
    arg_parser.add_argument('--certs-dir', dest='certs_dir',
        default='./{0}-warcprox-ca'.format(socket.gethostname()),
        help='where to store and load generated certificates')
    arg_parser.add_argument('--version', action='version',
        version="warcprox {}".format(warcprox.__version__))
    arg_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true')
    arg_parser.add_argument('-q', '--quiet', dest='quiet', action='store_true')

    return arg_parser.parse_args(args=sys.argv[1:])

def init_logging(verbose):
    if args.verbose:
        loglevel = logging.DEBUG
    elif args.quiet:
        loglevel = logging.WARNING
    else:
        loglevel = logging.INFO

    logging.basicConfig(stream=sys.stdout, level=loglevel,
            format='%(asctime)s %(process)d %(levelname)s %(threadName)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')
            # format='%(asctime)s %(funcName) 21s() %(filename)15s:%(lineno)05d %(message)s')

def init_proxy(args):
    ca_name = 'Warcprox CA on {}'.format(socket.gethostname())[:64]
    ca = certauth.certauth.CertificateAuthority(args.cacert, args.certs_dir,
        ca_name=ca_name)
    options = warcprox.Options(**vars(args))
    proxy = warcprox.warcproxy.SingleThreadedWarcProxy(ca,
        recorded_url_q=FakeQueue(), options=options)
    return proxy

if __name__ == "__main__":
    args = parse_args()
    init_logging(args.verbose)
    proxy = init_proxy(args)

    proxy.serve_forever()

