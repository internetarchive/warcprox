#!/usr/bin/env python
'''
run-benchmarks.py - some benchmarking code for warcprox

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
'''

import aiohttp.web
import asyncio
import ssl
import OpenSSL.crypto
import OpenSSL.SSL
import tempfile
import random
import os
import logging
import sys
import time
import argparse
import hashlib
import datetime
import cryptography.hazmat.backends.openssl
import warcprox
import warcprox.main
import threading

# https://medium.com/@generativist/a-simple-streaming-http-server-in-aiohttp-4233dbc173c7
async def do_get(request):
    n = int(request.match_info.get('n'))
    response = aiohttp.web.StreamResponse(
            status=200, reason='OK', headers={
                'Content-Type': 'text/plain', 'Content-Length': str(n)})
    await response.prepare(request)
    for i in range(n // 80):
        # some random bytes at the beginning to avoid deduplication
        # XXX doesn't work for n < 80
        if i == 0:
            rando = bytes([random.choice(
                b'abcdefghijlkmopqrstuvwxyz') for i in range(30)])
            bs = rando + b'x' * 49 + b'\n'
        else:
            bs = b'x' * 79 + b'\n'
        await response.write(bs)
    if n % 80 > 0:
        await response.write(b'x' * (n % 80 - 1) + b'\n')

    return response

def self_signed_cert():
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    cert = OpenSSL.crypto.X509()
    cert.set_serial_number(random.randint(0, 2 ** 64 - 1))
    cert.get_subject().CN = '127.0.0.1'

    cert.set_version(2)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)

    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha1')

    return key, cert

def ssl_context():
    sslc = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    with tempfile.NamedTemporaryFile(delete=False) as certfile:
        key, cert = self_signed_cert()
        certfile.write(
                OpenSSL.crypto.dump_privatekey(OpenSSL.SSL.FILETYPE_PEM, key))
        certfile.write(
                OpenSSL.crypto.dump_certificate(OpenSSL.SSL.FILETYPE_PEM, cert))
    sslc.load_cert_chain(certfile.name)
    os.remove(certfile.name)
    return sslc

def start_servers():
    app = aiohttp.web.Application()
    app.router.add_get('/{n}', do_get)

    loop = asyncio.get_event_loop()

    http = loop.create_server(
            app.make_handler(access_log=None), '127.0.0.1', 4080)
    loop.run_until_complete(http)

    sslc = ssl_context()
    https = loop.create_server(
            app.make_handler(access_log=None), '127.0.0.1', 4443, ssl=sslc)
    loop.run_until_complete(https)

async def fetch(session, url, proxy=None):
    # logging.info('sending request to %s', url)
    n_bytes = 0
    async with session.get(url, proxy=proxy) as response:
        assert response.status == 200
        while True:
            chunk = await response.content.read(2**16)
            n_bytes += len(chunk)
            if not chunk:
                break
        # logging.info('finished receiving response from %s', url)
    return n_bytes

async def benchmarking_client(
        base_url, requests=200, payload_size=100000, proxy=None):
    start = time.time()
    connector = aiohttp.TCPConnector(ssl=False)
    n_urls = 0
    n_bytes = 0
    url = '%s/%s' % (base_url, payload_size)
    outstanding_requests = set()
    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(requests):
            future = asyncio.ensure_future(fetch(session, url, proxy))
            outstanding_requests.add(future)
            # logging.info('scheduled future fetch of %s', url)
        while True:
            done, pending = await asyncio.wait(
                    outstanding_requests, return_when=asyncio.FIRST_COMPLETED)
            for future in done:
                outstanding_requests.remove(future)
                n_urls += 1
                n_bytes += future.result()
            if not pending:
                return n_urls, n_bytes, time.time() - start

def build_arg_parser(tmpdir, prog=os.path.basename(sys.argv[0])):
    desc = '''
Warcprox benchmarker. Runs simple http and https servers and uses them to
benchmark warcprox. Runs 4 benchmarks:

    1. baseline http (no warcprox)
    2. baseline https (no warcprox)
    3. http with warcprox
    4. https with warcprox

Uses a temporary directory for warcs and other files. Otherwise, most warcprox
options can be specified on the command line. Useful for comparing performance
with different options.

Benchmarking code uses asyncio/aiohttp and requires python 3.5 or later.
'''
    arg_parser = warcprox.main._build_arg_parser()
    arg_parser.description = desc

    arg_parser.add_argument(
            '--requests', dest='requests', type=int, default=200,
            help='number of urls to fetch')
    arg_parser.add_argument(
            '--payload-size', dest='payload_size', type=int, default=100000,
            help='size of each response payload, in bytes')
    arg_parser.add_argument(
            '--skip-baseline', dest='skip_baseline', action='store_true',
            help='skip the baseline bechmarks')

    # filter out options that are not configurable for the benchmarks
    filtered = []
    for action in arg_parser._action_groups[1]._group_actions:
        if action.dest not in (
                'port', 'address', 'cacert', 'certs_dir', 'directory'):
            filtered.append(action)
    arg_parser._action_groups[1]._group_actions = filtered

    return arg_parser

if __name__ == '__main__':
    # see https://github.com/pyca/cryptography/issues/2911
    cryptography.hazmat.backends.openssl.backend.activate_builtin_random()

    # with tempfile.TemporaryDirectory() as tmpdir:
    tmpdir = tempfile.mkdtemp()
    if True:
        arg_parser = build_arg_parser(tmpdir)
        args = arg_parser.parse_args(args=sys.argv[1:])

        if args.trace:
            loglevel = logging.TRACE
        elif args.verbose:
            loglevel = logging.DEBUG
        else:
            loglevel = logging.INFO

        logging.basicConfig(
                stream=sys.stdout, level=loglevel, format=(
                    '%(asctime)s %(process)d %(levelname)s %(threadName)s '
                    '%(name)s.%(funcName)s(%(filename)s:%(lineno)d) '
                    '%(message)s'))
        logging.getLogger('warcprox').setLevel(loglevel + 5)

        logging.info('using temp dir %s', tmpdir)

        args.playback_port = None
        args.address = '127.0.0.1'
        args.port = 0
        args.cacert = os.path.join(tmpdir, 'benchmark-warcprox-ca.pem')
        args.certs_dir = os.path.join(tmpdir, 'benchmark-warcprox-ca')
        args.directory = os.path.join(tmpdir, 'warcs')
        # if args.rethinkdb_servers:
        #     args.rethinkdb_db = 'benchmarks_{:%Y%m%d%H%M%S}' % (
        #             datetime.datetime.utcnow())

        start_servers()
        logging.info(
                'servers running at http://127.0.0.1:4080 and '
                'https://127.0.0.1:4443')

        loop = asyncio.get_event_loop()

        logging.info('===== baseline benchmark starting (no proxy) =====')
        if not args.skip_baseline:
            n_urls, n_bytes, elapsed = loop.run_until_complete(
                    benchmarking_client(
                        'http://127.0.0.1:4080', args.requests,
                        args.payload_size))
            logging.info(
                    'http baseline (no proxy): n_urls=%s n_bytes=%s in %.1f '
                    'sec', n_urls, n_bytes, elapsed)

            n_urls, n_bytes, elapsed = loop.run_until_complete(
                    benchmarking_client(
                        'https://127.0.0.1:4443', args.requests,
                        args.payload_size))
            logging.info(
                    'https baseline (no proxy): n_urls=%s n_bytes=%s in %.1f '
                    'sec', n_urls, n_bytes, elapsed)
        else:
            logging.info('SKIPPED')
        logging.info('===== baseline benchmark finished =====')

        options = warcprox.Options(**vars(args))
        warcprox_controller = warcprox.controller.WarcproxController(options)

        warcprox_controller_thread = threading.Thread(
                target=warcprox_controller.run_until_shutdown)
        warcprox_controller_thread.start()

        proxy = 'http://%s:%s' % (
                warcprox_controller.proxy.server_address[0],
                warcprox_controller.proxy.server_address[1])
        logging.info('===== warcprox benchmark starting =====')
        n_urls, n_bytes, elapsed = loop.run_until_complete(
                benchmarking_client(
                    'http://127.0.0.1:4080', args.requests, args.payload_size,
                    proxy))
        logging.info(
                'http: n_urls=%s n_bytes=%s in %.1f sec',
                n_urls, n_bytes, elapsed)

        n_urls, n_bytes, elapsed = loop.run_until_complete(
                benchmarking_client(
                    'https://127.0.0.1:4443', args.requests, args.payload_size,
                    proxy))
        logging.info(
                'https: n_urls=%s n_bytes=%s in %.1f sec',
                n_urls, n_bytes, elapsed)

        start = time.time()
        warcprox_controller.stop.set()
        warcprox_controller_thread.join()
        logging.info(
                'waited %.1f sec for warcprox to finish', time.time() - start)
        logging.info('===== warcprox benchmark finished =====')
