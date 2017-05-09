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
    # return aiohttp.web.Response(text='foo=%s' % request.match_info.get('foo'))
    n = int(request.match_info.get('n'))
    response = aiohttp.web.StreamResponse(
            status=200, reason='OK', headers={'Content-Type': 'text/plain'})
    await response.prepare(request)
    for i in range(n):
        for i in range(10):
            response.write(b'x' * 99 + b'\n')
        await response.drain()

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

async def benchmarking_client(base_url, n, proxy=None):
    n_urls = 0
    n_bytes = 0
    for i in range(n):
        url = '%s/%s' % (base_url, i)
        connector = aiohttp.TCPConnector(verify_ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, proxy=proxy) as response:
                assert response.status == 200
                while True:
                    chunk = await response.content.read(2**16)
                    n_bytes += len(chunk)
                    if not chunk:
                        n_urls += 1
                        break
    return n_urls, n_bytes

def build_arg_parser(tmpdir, prog=os.path.basename(sys.argv[0])):
    arg_parser = argparse.ArgumentParser(
            prog=prog, description='warcprox benchmarker',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument(
            '-z', '--gzip', dest='gzip', action='store_true',
            help='write gzip-compressed warc records')
    arg_parser.add_argument(
            '-s', '--size', dest='size', default=1000*1000*1000, type=int,
            help='WARC file rollover size threshold in bytes')
    arg_parser.add_argument(
            '--rollover-idle-time', dest='rollover_idle_time', default=None,
            type=int, help=(
                'WARC file rollover idle time threshold in seconds (so that '
                "Friday's last open WARC doesn't sit there all weekend "
                'waiting for more data)'))
    try:
        hash_algos = hashlib.algorithms_guaranteed
    except AttributeError:
        hash_algos = hashlib.algorithms
    arg_parser.add_argument(
            '-g', '--digest-algorithm', dest='digest_algorithm',
            default='sha1', help='digest algorithm, one of %s' % hash_algos)
    arg_parser.add_argument('--base32', dest='base32', action='store_true',
            default=False, help='write digests in Base32 instead of hex')
    arg_parser.add_argument(
            '--method-filter', metavar='HTTP_METHOD',
            action='append', help=(
                'only record requests with the given http method(s) (can be '
                'used more than once)'))
    arg_parser.add_argument(
            '--stats-db-file', dest='stats_db_file',
            default=os.path.join(tmpdir, 'stats.db'), help=(
                'persistent statistics database file; empty string or '
                '/dev/null disables statistics tracking'))
    group = arg_parser.add_mutually_exclusive_group()
    group.add_argument(
        '-j', '--dedup-db-file', dest='dedup_db_file',
        default=os.path.join(tmpdir, 'dedup.db'), help=(
            'persistent deduplication database file; empty string or '
            '/dev/null disables deduplication'))
    group.add_argument(
            '--rethinkdb-servers', dest='rethinkdb_servers', help=(
                'rethinkdb servers, used for dedup and stats if specified; '
                'e.g. db0.foo.org,db0.foo.org:38015,db1.foo.org'))
    # arg_parser.add_argument(
    #         '--rethinkdb-db', dest='rethinkdb_db', default='warcprox', help=(
    #             'rethinkdb database name (ignored unless --rethinkdb-servers '
    #             'is specified)'))
    arg_parser.add_argument(
            '--rethinkdb-big-table', dest='rethinkdb_big_table',
            action='store_true', default=False, help=(
                'use a big rethinkdb table called "captures", instead of a '
                'small table called "dedup"; table is suitable for use as '
                'index for playback (ignored unless --rethinkdb-servers is '
                'specified)'))
    arg_parser.add_argument(
            '--kafka-broker-list', dest='kafka_broker_list', default=None,
            help='kafka broker list for capture feed')
    arg_parser.add_argument(
            '--kafka-capture-feed-topic', dest='kafka_capture_feed_topic',
            default=None, help='kafka capture feed topic')
    arg_parser.add_argument(
            '--queue-size', dest='queue_size', type=int, default=1)
    arg_parser.add_argument(
            '--max-threads', dest='max_threads', type=int)
    arg_parser.add_argument(
            '--version', action='version',
            version='warcprox %s' % warcprox.__version__)
    arg_parser.add_argument(
            '-v', '--verbose', dest='verbose', action='store_true')
    arg_parser.add_argument('--trace', dest='trace', action='store_true')
    arg_parser.add_argument('-q', '--quiet', dest='quiet', action='store_true')
    return arg_parser

if __name__ == '__main__':
    # see https://github.com/pyca/cryptography/issues/2911
    cryptography.hazmat.backends.openssl.backend.activate_builtin_random()

    with tempfile.TemporaryDirectory() as tmpdir:
        arg_parser = build_arg_parser(tmpdir)
        args = arg_parser.parse_args(args=sys.argv[1:])

        if args.trace:
            loglevel = warcprox.TRACE
        elif args.verbose:
            loglevel = logging.DEBUG
        elif args.quiet:
            loglevel = logging.WARNING
        else:
            loglevel = logging.INFO

        logging.basicConfig(
                stream=sys.stdout, level=loglevel, format=(
                    '%(asctime)s %(process)d %(levelname)s %(threadName)s '
                    '%(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s'))
        logging.getLogger('warcprox').setLevel(loglevel + 5)

        args.playback_port = None
        args.address = '127.0.0.1'
        args.port = 0
        args.cacert = os.path.join(tmpdir, 'benchmark-warcprox-ca.pem')
        args.certs_dir = os.path.join(tmpdir, 'benchmark-warcprox-ca')
        args.directory = os.path.join(tmpdir, 'warcs')
        if args.rethinkdb_servers:
            args.rethinkdb_db = 'benchmarks_{:%Y%m%d%H%M%S}' % (
                    datetime.datetime.utcnow())
        warcprox_controller = warcprox.main.init_controller(args)
        warcprox_controller_thread = threading.Thread(
                target=warcprox_controller.run_until_shutdown)
        warcprox_controller_thread.start()

        start_servers()
        logging.info(
                'servers running at http://127.0.0.1:4080 and '
                'https://127.0.0.1:4443')

        loop = asyncio.get_event_loop()

        logging.info("===== baseline benchmark starting (no proxy) =====")
        start = time.time()
        n_urls, n_bytes = loop.run_until_complete(
                benchmarking_client('http://127.0.0.1:4080', 100))
        finish = time.time()
        logging.info(
                'http baseline (no proxy): n_urls=%s n_bytes=%s in %.1f sec',
                n_urls, n_bytes, finish - start)

        start = time.time()
        n_urls, n_bytes = loop.run_until_complete(
                benchmarking_client('https://127.0.0.1:4443', 100))
        finish = time.time()
        logging.info(
                'https baseline (no proxy): n_urls=%s n_bytes=%s in %.1f sec',
                n_urls, n_bytes, finish - start)
        logging.info("===== baseline benchmark finished =====")

        proxy = "http://%s:%s" % (
                warcprox_controller.proxy.server_address[0],
                warcprox_controller.proxy.server_address[1])
        logging.info("===== warcprox benchmark starting =====")
        start = time.time()
        n_urls, n_bytes = loop.run_until_complete(
                benchmarking_client('http://127.0.0.1:4080', 100, proxy))
        finish = time.time()
        logging.info(
                'http: n_urls=%s n_bytes=%s in %.1f sec',
                n_urls, n_bytes, finish - start)

        start = time.time()
        n_urls, n_bytes = loop.run_until_complete(
                benchmarking_client('https://127.0.0.1:4443', 100, proxy))
        finish = time.time()
        logging.info(
                'https: n_urls=%s n_bytes=%s in %.1f sec',
                n_urls, n_bytes, finish - start)
        logging.info("===== warcprox benchmark finished =====")

        warcprox_controller.stop.set()
        warcprox_controller_thread.join()
