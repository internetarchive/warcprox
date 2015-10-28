#!/usr/bin/env python

import sys
import aiohttp
import aiohttp.server
import asyncio
import ssl
import tempfile
import OpenSSL.crypto
import OpenSSL.SSL
import random
import os
import threading
import time
import logging
import warcprox.main

logging.basicConfig(stream=sys.stdout, level=logging.INFO,
        format='%(asctime)s %(process)d %(levelname)s %(threadName)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')

def self_signed_cert():
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    cert = OpenSSL.crypto.X509()
    cert.set_serial_number(random.randint(0, 2 ** 64 - 1))
    cert.get_subject().CN = 'localhost'

    cert.set_version(2)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)

    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha1")

    return key, cert

class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):
    @asyncio.coroutine
    def handle_request(self, message, payload):
        response = aiohttp.Response(
            self.writer, 200, http_version=message.version
        )
        n = int(message.path.partition('/')[2])
        response.add_header('Content-Type', 'text/plain')
        # response.add_header('Content-Length', '18')
        response.send_headers()
        for i in range(n):
            response.write(b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n')
        yield from response.write_eof()

def run_servers():
    loop.run_forever()

def start_servers():
    loop = asyncio.get_event_loop()
    http = loop.create_server(lambda: HttpRequestHandler(debug=True, keep_alive=75), '127.0.0.1', '8080')
    sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    key, cert = self_signed_cert()
    with tempfile.NamedTemporaryFile(delete=False) as certfile:
        certfile.write(OpenSSL.crypto.dump_privatekey(OpenSSL.SSL.FILETYPE_PEM, key))
        certfile.write(OpenSSL.crypto.dump_certificate(OpenSSL.SSL.FILETYPE_PEM, cert))
    sslcontext.load_cert_chain(certfile.name)
    os.remove(certfile.name)
    https = loop.create_server(lambda: HttpRequestHandler(debug=True, keep_alive=75), '127.0.0.1', '8443', ssl=sslcontext)
    srv = loop.run_until_complete(http)
    srv = loop.run_until_complete(https)
    logging.info('serving on http://127.0.0.1:8080 and https://127.0.0.1:8443')

class AsyncClient(object):
    def __init__(self, proxy=None):
        self.n_urls = 0
        self.n_bytes = 0
        self.proxy = proxy
        if proxy:
            self.connector = aiohttp.connector.ProxyConnector(proxy, verify_ssl=False)
        else:
            self.connector = aiohttp.connector.TCPConnector(verify_ssl=False)

    @asyncio.coroutine
    def read_response(self, r, url):
        # time.sleep(random.random() * 10)
        while True:
            chunk = yield from r.content.read(2**16)
            self.n_bytes += len(chunk)
            if not chunk:
                self.n_urls += 1
                logging.info("finished reading from %s", url)
                r.close()
                break
    
    @asyncio.coroutine
    def one_request(self, url):
        logging.info("issuing request to %s", url)
        r = yield from aiohttp.get(url, connector=self.connector)
        logging.info("issued request to %s", url)
        yield from self.read_response(r, url)

def benchmark(client):
    try:
       start = time.time()
       tasks_https = [client.one_request('https://localhost:8443/%s' % int(1.1**i)) for i in range(120)]
       asyncio.get_event_loop().run_until_complete(asyncio.wait(tasks_https))
       tasks_http = [client.one_request('http://localhost:8080/%s' % int(1.1**i)) for i in range(120)]
       asyncio.get_event_loop().run_until_complete(asyncio.wait(tasks_http))
    finally:
        finish = time.time()
        logging.info("proxy=%s: %s urls totaling %s bytes in %s seconds", client.proxy, client.n_urls, client.n_bytes, (finish - start))

if __name__ == '__main__':
    args = warcprox.main.parse_args()

    start_servers()

    baseline_client = AsyncClient()
    logging.info("===== baseline benchmark starting (no proxy) =====")
    benchmark(baseline_client)
    logging.info("===== baseline benchmark finished =====")


    # Queue size of 1 makes warcprox behave as though it were synchronous (each
    # request blocks until the warc writer starts working on the last request).
    # This gives us a better sense of sustained max throughput. The
    # asynchronous nature of warcprox helps with bursty traffic, as long as the
    # average throughput stays below the sustained max.
    with TemporaryDirectory() as tmpdir:
        args.queue_size = 1
        args.cacert = os.path.join(tmpdir, "benchmark-warcprox-ca.pem")
        args.certs_dir = os.path.join(tmpdir, "benchmark-warcprox-ca")
        args.directory = os.path.join(tmpdir, "warcs")
        args.gzip = True
        args.base32 = True
        args.stats_db_file = os.path.join(tmpdir, "stats.db")
        args.dedup_db_file = os.path.join(tmpdir, "dedup.db")

        warcprox_controller = warcprox.main.init_controller(args)
        warcprox_controller_thread = threading.Thread(target=warcprox_controller.run_until_shutdown)
        warcprox_controller_thread.start()
        proxy = "http://%s:%s" % (args.address, args.port)
        proxied_client = AsyncClient(proxy=proxy)

        logging.info("===== warcprox benchmark starting =====")
        benchmark(proxied_client)
        logging.info("===== warcprox benchmark finished =====")

        warcprox_controller.stop.set()
        warcprox_controller_thread.join()

    asyncio.get_event_loop().stop()
    logging.info("finished")

