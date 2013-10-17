#!/usr/bin/python
# vim:set sw=4 et:
#

import BaseHTTPServer, SocketServer
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
import os
import argparse
import random
import httplib

class CertificateAuthority(object):

    def __init__(self, ca_file='warcprox-ca.pem', certs_dir='./warcprox-ca'):
        self.ca_file = ca_file
        self.certs_dir = certs_dir

        if not os.path.exists(ca_file):
            self._generate_ca()
        else:
            self._read_ca(ca_file)

        if not os.path.exists(certs_dir):
            logging.info("directory for generated certs {} doesn't exist, creating it".format(certs_dir))
            os.mkdir(certs_dir)


    def _generate_ca(self):
        # Generate key
        self.key = OpenSSL.crypto.PKey()
        self.key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        # Generate certificate
        self.cert = OpenSSL.crypto.X509()
        self.cert.set_version(3)
        # avoid sec_error_reused_issuer_and_serial
        self.cert.set_serial_number(random.randint(0,2**64-1))
        self.cert.get_subject().CN = 'CA for warcprox MITM archiving proxy'
        self.cert.gmtime_adj_notBefore(0)                # now
        self.cert.gmtime_adj_notAfter(100*365*24*60*60)  # 100 yrs in future
        self.cert.set_issuer(self.cert.get_subject())
        self.cert.set_pubkey(self.key)
        self.cert.add_extensions([
            OpenSSL.crypto.X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
            OpenSSL.crypto.X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
            OpenSSL.crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=self.cert),
            ])
        self.cert.sign(self.key, "sha1")

        with open(self.ca_file, 'wb+') as f:
            f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.SSL.FILETYPE_PEM, self.key))
            f.write(OpenSSL.crypto.dump_certificate(OpenSSL.SSL.FILETYPE_PEM, self.cert))

        logging.info('generated CA key+cert and wrote to {}'.format(self.ca_file))


    def _read_ca(self, file):
        self.cert = OpenSSL.crypto.load_certificate(OpenSSL.SSL.FILETYPE_PEM, open(file).read())
        self.key = OpenSSL.crypto.load_privatekey(OpenSSL.SSL.FILETYPE_PEM, open(file).read())
        logging.info('read CA key+cert from {}'.format(self.ca_file))

    def __getitem__(self, cn):
        cnp = os.path.sep.join([self.certs_dir, '%s.pem' % cn])
        if not os.path.exists(cnp):
            # create certificate
            key = OpenSSL.crypto.PKey()
            key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

            # Generate CSR
            req = OpenSSL.crypto.X509Req()
            req.get_subject().CN = cn
            req.set_pubkey(key)
            req.sign(key, 'sha1')

            # Sign CSR
            cert = OpenSSL.crypto.X509()
            cert.set_subject(req.get_subject())
            cert.set_serial_number(random.randint(0,2**64-1))
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(10*365*24*60*60)
            cert.set_issuer(self.cert.get_subject())
            cert.set_pubkey(req.get_pubkey())
            cert.sign(self.key, 'sha1')

            with open(cnp, 'wb+') as f:
                f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.SSL.FILETYPE_PEM, key))
                f.write(OpenSSL.crypto.dump_certificate(OpenSSL.SSL.FILETYPE_PEM, cert))

            logging.info('wrote generated key+cert to {}'.format(cnp))

        return cnp


class UnsupportedSchemeException(Exception):
    pass


class Recorder:

    def __init__(self, fp):
        self.fp = fp
        self.recorded = bytearray('')

    def read(self, size=-1):
        result = self.fp.read(size=size)
        self.recorded.extend(result)
        return result

    def readline(self, size=-1):
        return self.fp.readline(size=size)

    def close(self):
        return self.fp.close()


class RecordingHTTPResponse(httplib.HTTPResponse):

    def __init__(self, sock, debuglevel=0, strict=0, method=None, buffering=False):
        httplib.HTTPResponse.__init__(self, sock, debuglevel=debuglevel, strict=strict, method=method, buffering=buffering)

        # Keep around extra reference to self.fp because HTTPResponse sets
        # self.fp=None after it finishes reading, but we still need it
        self.recorder = Recorder(self.fp)
        self.fp = self.recorder

    def recorded(self):
        return self.recorder.recorded


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
        self.request = ssl.wrap_socket(self.request, server_side=True, certfile=self.server.ca[self.hostname])


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
        try:
            logging.debug("host={} port={} path={} calling self.handle_one_request()".format(self.hostname, self.port, self.path))
            self.handle_one_request()
        except ssl.SSLError, e:
            logging.error("host={} port={} path={} caught SSLError {}".format(self.hostname, self.port, self.path, e))
            pass


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

        interceptors = [p(self.server, self) for p in self.server._interceptors]

        # Send it down the pipe!
        self._proxy_sock.sendall(self.mitm_request(req, interceptors))

        # Parse response
        h = RecordingHTTPResponse(self._proxy_sock)
        h.begin()

        # Get rid of the pesky header
        del h.msg['Transfer-Encoding']

        # Time to relay the message across
        headers = '%s %s %s\r\n' % (self.request_version, h.status, h.reason)
        headers += '%s\r\n' % h.msg
        self.request.sendall(headers)

        buf = h.read(4096) 
        while buf != '':
            self.request.sendall(buf)
            buf = h.read(4096) 

        self.mitm_response(h.recorded(), interceptors)

        # Let's close off the remote end
        h.close()
        self._proxy_sock.close()


    def mitm_request(self, data, interceptors):
        for i in interceptors:
            data = i.do_request(data)
        return data


    def mitm_response(self, data, interceptors):
        for i in interceptors:
            data = i.do_response(data)
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


# InterceptorPlugin modified from pymiproxy to send the request and response
# from a single transaction through the same instance of the interceptor
class InterceptorPlugin(object):

    def __init__(self, server, msg):
        self.server = server
        self.message = msg

    def do_request(self, data):
        return data

    def do_response(self, data):
        return data


class InvalidInterceptorPluginException(Exception):
    pass


class MitmProxy(BaseHTTPServer.HTTPServer):

    def __init__(self, server_address, req_handler_class=ProxyHandler, bind_and_activate=True, ca_file='./warcprox-ca.pem', certs_dir='./warcprox-ca'):
        BaseHTTPServer.HTTPServer.__init__(self, server_address, req_handler_class, bind_and_activate)
        self._interceptors = []
        self.ca = CertificateAuthority(ca_file, certs_dir)


    def register_interceptor(self, interceptor_class):
        if not issubclass(interceptor_class, InterceptorPlugin):
            raise InvalidInterceptorPluginException('Expected type InterceptorPlugin got %s instead' % type(interceptor_class))
        self._interceptors.append(interceptor_class)


    def server_activate(self):
        BaseHTTPServer.HTTPServer.server_activate(self)
        logging.info('listening on {0}:{1}'.format(self.server_address[0], self.server_address[1]))


    def server_close(self):
        BaseHTTPServer.HTTPServer.server_close(self)
        logging.info('shut down')


class AsyncMitmProxy(SocketServer.ThreadingMixIn, MitmProxy):
    pass


# assumes do_request happens before do_response
class WarcRecordQueuer(InterceptorPlugin):

    # Each item in the queue is a tuple of warc records which should be written
    # together, e.g. (reponse, request) where request has WARC-Concurrent-To
    # pointing to response.
    warc_record_group_queue = Queue.Queue()

    @staticmethod
    def make_warc_uuid(text):
        return "<urn:uuid:{0}>".format(uuid.UUID(hashlib.sha1(text).hexdigest()[0:32]))


    def __init__(self, server, msg):
        InterceptorPlugin.__init__(self, server, msg)

        if msg.is_connect:
            # have to construct the url if proxy request is a CONNECT
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


    def _warc_date(self):
        try:
            return self._d
        except AttributeError:
            self._d = warctools.warc.warc_datetime_str(datetime.now())
            return self._d


    def do_request(self, data):
        logging.info('{0} >> {1}'.format(self.url, repr(data[:100])))

        record_id = WarcRecordQueuer.make_warc_uuid("{0} {1}".format(self.url, self._warc_date()))

        headers = []
        headers.append((warctools.WarcRecord.ID, record_id))
        headers.append((warctools.WarcRecord.TYPE, warctools.WarcRecord.REQUEST))
        headers.append((warctools.WarcRecord.URL, self.url))
        headers.append((warctools.WarcRecord.DATE, self._warc_date()))
        # headers.append((warctools.WarcRecord.IP_ADDRESS, ip))

        content_tuple = "application/http;msgtype=request", data
        self._request_record = warctools.WarcRecord(headers=headers, content=content_tuple)

        return data


    def do_response(self, data):
        logging.info('{0} << {1}'.format(self.url, repr(data[:100])))

        record_id = WarcRecordQueuer.make_warc_uuid("{0} {1}".format(self.url, self._warc_date()))

        headers = []
        headers.append((warctools.WarcRecord.ID, record_id))
        headers.append((warctools.WarcRecord.TYPE, warctools.WarcRecord.RESPONSE))
        headers.append((warctools.WarcRecord.URL, self.url))
        headers.append((warctools.WarcRecord.DATE, self._warc_date()))
        # headers.append((warctools.WarcRecord.IP_ADDRESS, ip))

        content_tuple = ("application/http;msgtype=response", data)

        response_record = warctools.WarcRecord(headers=headers, content=content_tuple)

        try:
            self._request_record.set_header(warctools.WarcRecord.CONCURRENT_TO, record_id)
            record_group = response_record, self._request_record
        except AttributeError:
            record_group = response_record,   # tuple with one item

        WarcRecordQueuer.warc_record_group_queue.put(record_group)
        
        return data


class WarcWriterThread(threading.Thread):

    def __init__(self, warc_record_group_queue, directory, gzip, prefix, size, port):
        threading.Thread.__init__(self, name='WarcWriterThread')

        self.warc_record_group_queue = warc_record_group_queue

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
        record_id = WarcRecordQueuer.make_warc_uuid("{0} {1}".format(filename, warc_record_date))

        headers = []
        headers.append((warctools.WarcRecord.ID, record_id))
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

        record = warctools.WarcRecord(headers=headers, content=('application/warc-fields', data))

        return record


    # <!-- <property name="template" value="${prefix}-${timestamp17}-${serialno}-${heritrix.pid}~${heritrix.hostname}~${heritrix.port}" /> -->
    def _writer(self):
        if self._fpath and os.path.getsize(self._fpath) > self.size:
            self._close_writer()

        if self._f == None:
            filename = '{}-{}-{:05d}-{}-{}-{}.warc{}'.format(
                    self.prefix, self.timestamp17(), self._serial, os.getpid(),
                    socket.gethostname(), self.port, '.gz' if self.gzip else '')
            self._fpath = os.path.sep.join([self.directory, filename + '.open'])

            self._f = open(self._fpath, 'wb')

            warcinfo_record = self._make_warcinfo_record(filename)
            warcinfo_record.write_to(self._f, gzip=self.gzip)

            self._serial += 1

        return self._f


    def run(self):
        logging.info('WarcWriterThread starting, directory={0} gzip={1} prefix={2} size={3} port={4}'.format(
            os.path.abspath(self.directory), self.gzip, self.prefix, self.size, self.port))

        while not self.stop.is_set():
            try:
                warc_record_group = self.warc_record_group_queue.get(block=True, timeout=0.5)
                logging.debug('got warc record group to write from the queue: {0}'.format(warc_record_group))
                for record in warc_record_group:
                    record.write_to(self._writer(), gzip=self.gzip)
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
    arg_parser.add_argument('-c', '--cacert', dest='cacert', default='./warcprox-ca.pem', help='CA certificate file; if file does not exist, it will be created')
    arg_parser.add_argument('--certs-dir', dest='certs_dir', default='./warcprox-ca', help='where to store and load generated certificates')
    arg_parser.add_argument('-d', '--dir', dest='directory', default='./warcs', help='where to write warcs')
    arg_parser.add_argument('-z', '--gzip', dest='gzip', action='store_true', help='write gzip-compressed warc records')
    arg_parser.add_argument('-n', '--prefix', dest='prefix', default='WARCPROX', help='WARC filename prefix')
    arg_parser.add_argument('-s', '--size', dest='size', default=1000*1000*1000, help='WARC file rollover size threshold in bytes')
    # [--ispartof=warcinfo ispartof]
    # [--description=warcinfo description]
    # [--operator=warcinfo operator]
    # [--httpheader=warcinfo httpheader]
    args = arg_parser.parse_args()

    proxy = AsyncMitmProxy(server_address=(args.address, int(args.port)), ca_file=args.cacert, certs_dir=args.certs_dir)
    proxy.register_interceptor(WarcRecordQueuer)

    warc_writer = WarcWriterThread(WarcRecordQueuer.warc_record_group_queue, directory=args.directory, gzip=args.gzip, prefix=args.prefix, size=int(args.size), port=int(args.port))
    warc_writer.start()

    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        warc_writer.stop.set()
        proxy.server_close()

