#!/usr/bin/python
# vim:set sw=4 et:
#

import BaseHTTPServer, SocketServer
import httplib
import socket
import urlparse
import OpenSSL
import ssl
import logging
import sys
from hanzo import warctools
import uuid
import hashlib
from datetime import datetime
import Queue
import threading
import os, os.path
import argparse


class UnsupportedSchemeException(Exception):
    pass


class ProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def __init__(self, request, client_address, server):
        self.is_connect = False
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _connect_to_host(self):
        # Get hostname and port to connect to
        if self.is_connect:
            self.hostname, self.port = self.path.split(':')
        else:
            self.url = self.path
            u = urlparse.urlparse(self.url)
            if u.scheme != 'http':
                raise UnsupportedSchemeException('Unknown scheme %s' % repr(u.scheme))
            self.hostname = u.hostname
            self.port = u.port or 80
            self.path = urlparse.urlunparse(
                urlparse.ParseResult(
                    scheme='',
                    netloc='',
                    params=u.params,
                    path=u.path or '/',
                    query=u.query,
                    fragment=u.fragment
                )
            )

        # Connect to destination
        self._proxy_sock = socket.socket()
        self._proxy_sock.settimeout(10)
        self._proxy_sock.connect((self.hostname, int(self.port)))

        # Wrap socket if SSL is required
        if self.is_connect:
            self._proxy_sock = ssl.wrap_socket(self._proxy_sock)


    def _transition_to_ssl(self):
        self.request = ssl.wrap_socket(self.request, server_side=True, certfile=self.server.certfile)


    def do_CONNECT(self):
        self.is_connect = True
        try:
            # Connect to destination first
            self._connect_to_host()

            # If successful, let's do this!
            self.send_response(200, 'Connection established')
            self.end_headers()
            #self.request.sendall('%s 200 Connection established\r\n\r\n' % self.request_version)
            self._transition_to_ssl()
        except Exception as e:
            self.send_error(500, str(e))
            return

        # Reload!
        self.setup()
        self.handle_one_request()
#         try:
#         except ssl.SSLError, e:
#             logging.warn("caught SSLError {0}".format(e))
#             pass


    def do_COMMAND(self):

        # Is this an SSL tunnel?
        if not self.is_connect:
            try:
                # Connect to destination
                self._connect_to_host()
            except Exception as e:
                self.send_error(500, str(e))
                return
            # Extract path

        # Build request
        req = '%s %s %s\r\n' % (self.command, self.path, self.request_version)
        
        # Add headers to the request
        req += '%s\r\n' % self.headers

        # Append message body if present to the request
        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))

        # Send it down the pipe!
        self._proxy_sock.sendall(self.mitm_request(req))

        # Parse response
        h = httplib.HTTPResponse(self._proxy_sock)
        h.begin()

        # Get rid of the pesky header
        del h.msg['Transfer-Encoding']

        # Time to relay the message across
        res = '%s %s %s\r\n' % (self.request_version, h.status, h.reason)
        res += '%s\r\n' % h.msg
        res += h.read()

        # Let's close off the remote end
        h.close()
        self._proxy_sock.close()

        # Relay the message
        self.request.sendall(self.mitm_response(res))


    def mitm_request(self, data):
        for p in self.server._req_plugins:
            data = p(self.server, self).do_request(data)
        return data


    def mitm_response(self, data):
        for p in self.server._res_plugins:
            data = p(self.server, self).do_response(data)
        return data


    def __getattr__(self, item):
        if item.startswith('do_'):
            return self.do_COMMAND


    def log_error(self, format, *args):
        logging.error("{0} - - [{1}] {2}".format(self.address_string(), 
            self.log_date_time_string(), format % args))


    def log_message(self, format, *args):
        logging.info("{0} - - [{1}] {2}".format(self.address_string(), 
            self.log_date_time_string(), format % args))


class InterceptorPlugin(object):

    def __init__(self, server, msg):
        self.server = server
        self.message = msg


class RequestInterceptorPlugin(InterceptorPlugin):

    def do_request(self, data):
        return data


class ResponseInterceptorPlugin(InterceptorPlugin):

    def do_response(self, data):
        return data


class InvalidInterceptorPluginException(Exception):
    pass


class MitmProxy(BaseHTTPServer.HTTPServer):

    def __init__(self, server_address, req_handler_class=ProxyHandler, bind_and_activate=True, certfile='warcprox.pem'):
        BaseHTTPServer.HTTPServer.__init__(self, server_address, req_handler_class, bind_and_activate)
        self._res_plugins = []
        self._req_plugins = []
        self.certfile = certfile

        if not os.path.exists(certfile):
           self._generate_cert(certfile)
    

    def _generate_cert(self, certfile):
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        cert = OpenSSL.crypto.X509()
        cert.set_version(3)
        cert.set_serial_number(1)
        cert.get_subject().CN = 'warcprox man-in-the-middle archiving http/s proxy'
        cert.gmtime_adj_notBefore(0)               # now
        cert.gmtime_adj_notAfter(100*365*24*60*60) # 100 yrs in future
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, "sha1")
 
        with open(certfile, 'wb+') as f:
             f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.SSL.FILETYPE_PEM, key))
             f.write(OpenSSL.crypto.dump_certificate(OpenSSL.SSL.FILETYPE_PEM, cert))


    def register_interceptor(self, interceptor_class):
        if not issubclass(interceptor_class, InterceptorPlugin):
            raise InvalidInterceptorPluginException('Expected type InterceptorPlugin got %s instead' % type(interceptor_class))
        if issubclass(interceptor_class, RequestInterceptorPlugin):
            self._req_plugins.append(interceptor_class)
        if issubclass(interceptor_class, ResponseInterceptorPlugin):
            self._res_plugins.append(interceptor_class)


    def server_activate(self):
        BaseHTTPServer.HTTPServer.server_activate(self)
        logging.info('listening on {0}:{1}'.format(self.server_address[0], self.server_address[1]))


    def server_close(self):
        BaseHTTPServer.HTTPServer.server_close(self)
        logging.info('shut down')


class AsyncMitmProxy(SocketServer.ThreadingMixIn, MitmProxy):
    pass


class WarcRecordQueuer(RequestInterceptorPlugin, ResponseInterceptorPlugin):

    warc_record_queue = Queue.Queue()

    def __init__(self, server, msg):
        InterceptorPlugin.__init__(self, server, msg)

        if msg.is_connect:
            assert not msg.url

            if int(msg.port) == 443:
                netloc = msg.hostname
            else:
                netloc = '{0}:{1}'.format(msg.hostname, msg.port)

            self.url = urlparse.urlunparse(
                urlparse.ParseResult(
                    scheme='https',
                    netloc=netloc,
                    params='',
                    path=msg.path,
                    query='',
                    fragment=''
                )
            )
        else:
            assert msg.url
            self.url = msg.url


    def do_request(self, data):
        logging.info('{0} >> {1}'.format(self.url, repr(data[:100])))
        return data


    @staticmethod
    def make_warc_uuid(text):
        return "<urn:uuid:{0}>".format(uuid.UUID(hashlib.sha1(text).hexdigest()[0:32]))


    def do_response(self, data):
        logging.info('{0} << {1}'.format(self.url, repr(data[:100])))

        warc_record_date = warctools.warc.warc_datetime_str(datetime.now())
        warc_record_id = WarcRecordQueuer.make_warc_uuid("{0} {1}".format(self.url, warc_record_date))
        logging.info('{0}: {1}'.format(warctools.WarcRecord.ID, warc_record_id))

        headers = []
        headers.append((warctools.WarcRecord.ID, warc_record_id))
        headers.append((warctools.WarcRecord.URL, self.url))
        headers.append((warctools.WarcRecord.DATE, warc_record_date))
        # headers.append((warctools.WarcRecord.IP_ADDRESS, ip))
        headers.append((warctools.WarcRecord.TYPE, warctools.WarcRecord.RESPONSE))

        warcrecord = warctools.WarcRecord(headers=headers, content=("application/http;msgtype=response", data))

        # warcrecord.write_to(sys.stdout, gzip=False)
        WarcRecordQueuer.warc_record_queue.put(warcrecord)
        
        return data


class WarcWriterThread(threading.Thread):

    def __init__(self, warc_record_queue, directory, gzip, prefix, size, port):
        threading.Thread.__init__(self, name='WarcWriterThread')

        self.warc_record_queue = warc_record_queue

        self.directory = directory
        self.gzip = gzip
        self.prefix = prefix
        self.size = size
        self.port = port

        self._f = None
        self._fpath = None
        self._serial = 0
        
        if not os.path.exists(directory):
            logging.info("warc destination directory {0} doesn't exist, creating it".format(directory))
            os.mkdir(directory)

        self.stop = threading.Event()


    def timestamp17(self):
        now = datetime.now()
        return '{0}{1}'.format(now.strftime('%Y%m%d%H%M%S'), now.microsecond//1000)


    def _close_writer(self):
        if self._fpath:
            final_name = self._fpath[:-5]
            logging.info('closing {0}'.format(final_name))
            self._f.close()
            os.rename(self._fpath, final_name)

            self._fpath = None
            self._f = None

    # WARC/1.0
    # WARC-Type: warcinfo
    # WARC-Date: 2013-10-15T22:11:29Z
    # WARC-Filename: ARCHIVEIT-3714-WEEKLY-14487-20131015221129606-00000-wbgrp-crawl105.us.archive.org-6442.warc.gz
    # WARC-Record-ID: <urn:uuid:8c5d5d7d-11df-4a83-9999-8d6c8244316b>
    # Content-Type: application/warc-fields
    # Content-Length: 713
    # 
    # software: Heritrix/3.1.2-SNAPSHOT-20131011-0101 http://crawler.archive.org
    # ip: 207.241.226.68
    # hostname: wbgrp-crawl105.us.archive.org
    # format: WARC File Format 1.0
    # conformsTo: http://bibnum.bnf.fr/WARC/WARC_ISO_28500_version1_latestdraft.pdf
    # isPartOf: 3714-20131015221121926
    # description: recurrence=WEEKLY, maxDuration=259200, maxDocumentCount=null, isTestCrawl=false, isPatchCrawl=false, oneTimeSubtype=null, seedCount=1, accountId
    # robots: obey
    # http-header-user-agent: Mozilla/5.0 (compatible; archive.org_bot; Archive-It; +http://archive-it.org/files/site-owners.html)
    def _make_warcinfo_record(self, filename):
        warc_record_date = warctools.warc.warc_datetime_str(datetime.now())
        warc_record_id = WarcRecordQueuer.make_warc_uuid("{0} {1}".format(filename, warc_record_date))

        headers = []
        headers.append((warctools.WarcRecord.ID, warc_record_id))
        headers.append((warctools.WarcRecord.TYPE, warctools.WarcRecord.WARCINFO))
        headers.append((warctools.WarcRecord.FILENAME, filename))
        headers.append((warctools.WarcRecord.DATE, warc_record_date))
        # headers.append((warctools.WarcRecord.IP_ADDRESS, ip))

        warcinfo_fields = []
        warcinfo_fields.append('software: warcprox.py https://github.com/nlevitt/warcprox')
        hostname = socket.gethostname()
        warcinfo_fields.append('hostname: {0}'.format(hostname))
        warcinfo_fields.append('ip: {0}'.format(socket.gethostbyname(hostname)))
        warcinfo_fields.append('format: WARC File Format 1.0')
        warcinfo_fields.append('robots: ignore')   # XXX implement robots support
        # warcinfo_fields.append('description: {0}'.format(self.description))   
        # warcinfo_fields.append('isPartOf: {0}'.format(self.is_part_of))   
        data = '\r\n'.join(warcinfo_fields) + '\r\n'

        warcrecord = warctools.WarcRecord(headers=headers, content=('application/warc-fields', data))

        return warcrecord


    # <!-- <property name="template" value="${prefix}-${timestamp17}-${serialno}-${heritrix.pid}~${heritrix.hostname}~${heritrix.port}" /> -->
    def _writer(self):
        if self._fpath and os.path.getsize(self._fpath) > self.size:
            self._close_writer()

        if self._f == None:
            filename = '{}-{}-{:05d}-{}-{}-{}.warc{}'.format(
                    self.prefix, self.timestamp17(), self._serial, os.getpid(),
                    socket.gethostname(), self.port, '.gz' if self.gzip else '')
            self._fpath = '{0}/{1}.open'.format(self.directory, filename)
            self._f = open(self._fpath, 'wb')

            warcinfo_record = self._make_warcinfo_record(filename)
            warcinfo_record.write_to(self._f, gzip=self.gzip)

            self._serial += 1

        return self._f


    def run(self):
        logging.info('WarcWriterThread starting, directory={0} gzip={1} prefix={2} size={3} port={4}'.format(self.directory, self.gzip, self.prefix, self.size, self.port))

        while not self.stop.is_set():
            try:
                warc_record = self.warc_record_queue.get(block=True, timeout=0.5)
                logging.info('got warc record to write from the queue: {0}'.format(warc_record))
                warc_record.write_to(self._writer(), gzip=self.gzip)
                self._f.flush()
            except Queue.Empty:
                pass

        logging.info('WarcWriterThread shutting down')
        self._close_writer();


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s %(process)d %(threadName)s %(levelname)s %(funcName)s(%(filename)s:%(lineno)d) %(message)s')

    arg_parser = argparse.ArgumentParser(description='warcprox - WARC writing MITM HTTP/S proxy',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('-p', '--port', dest='port', default='8080', help='port to listen on')
    arg_parser.add_argument('-b', '--address', dest='address', default='localhost', help='address to listen on')
    arg_parser.add_argument('-c', '--certfile', dest='certfile', default='warcprox.pem', help='SSL certificate file; if file does not exist, it will be created')
    arg_parser.add_argument('-d', '--dir', dest='directory', default='warcs', help='where to write warcs')
    arg_parser.add_argument('-z', '--gzip', dest='gzip', action='store_true', help='write gzip-compressed warc records')
    arg_parser.add_argument('-n', '--prefix', dest='prefix', default='WARCPROX', help='WARC filename prefix')
    arg_parser.add_argument('-s', '--size', dest='size', default=1000*1000*1000, help='WARC file rollover size threshold in bytes')
    # --max-file-size=maxArcFileSize]
    # [--ispartof=warcinfo ispartof]
    # [--description=warcinfo description]
    # [--operator=warcinfo operator]
    # [--httpheader=warcinfo httpheader]
    args = arg_parser.parse_args()

    proxy = AsyncMitmProxy(server_address=(args.address, int(args.port)), certfile=args.certfile)
    proxy.register_interceptor(WarcRecordQueuer)

    warc_writer = WarcWriterThread(WarcRecordQueuer.warc_record_queue, directory=args.directory, gzip=args.gzip, prefix=args.prefix, size=int(args.size), port=int(args.port))
    warc_writer.start()

    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        warc_writer.stop.set()
        proxy.server_close()

