#!/usr/bin/env python
"""
tests/single-threaded-proxy.py - single-threaded MITM proxy, useful for
debugging, does not write warcs

Copyright (C) 2015-2017 Internet Archive

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
"""
import warcprox
import logging
import sys
import argparse
import certauth
import queue
import socket
import os

class FakeQueue:
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
            recorded_url.size, warcprox.digest_str(recorded_url.payload_digest, False).decode('utf-8')))

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
        default='./{}-warcprox-ca.pem'.format(socket.gethostname()),
        help='CA certificate file; if file does not exist, it will be created')
    arg_parser.add_argument('--certs-dir', dest='certs_dir',
        default='./{}-warcprox-ca'.format(socket.gethostname()),
        help='where to store and load generated certificates')
    arg_parser.add_argument('--onion-tor-socks-proxy', dest='onion_tor_socks_proxy',
        default=None, help='host:port of tor socks proxy, used only to connect to .onion sites')
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

