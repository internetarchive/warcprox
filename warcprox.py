#!/usr/bin/python
# vim:set sw=4 et:
#
"""
WARC writing MITM HTTP/S proxy

See README.md or https://github.com/internetarchive/warcprox
"""

import BaseHTTPServer, SocketServer
import socket
import urlparse
import OpenSSL
import ssl
import logging
import sys
from hanzo import warctools, httptools
import hashlib
from datetime import datetime
import Queue
import threading
import os
import argparse
import random
import httplib
import re
import signal
import time
import tempfile
import base64
import json
import traceback
import gdbm

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
        self.cert.get_subject().CN = 'warcprox certificate authority on {}'.format(socket.gethostname())
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


    def _read_ca(self, filename):
        self.cert = OpenSSL.crypto.load_certificate(OpenSSL.SSL.FILETYPE_PEM, open(filename).read())
        self.key = OpenSSL.crypto.load_privatekey(OpenSSL.SSL.FILETYPE_PEM, open(filename).read())
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


class ProxyingRecorder:
    """
    Wraps a socket._fileobject, recording the bytes as they are read,
    calculating digests, and sending them on to the proxy client.
    """

    def __init__(self, fp, proxy_dest, digest_algorithm='sha1'):
        self.fp = fp
        # "The file has no name, and will cease to exist when it is closed."
        self.tempfile = tempfile.SpooledTemporaryFile(max_size=512*1024)
        self.digest_algorithm = digest_algorithm
        self.block_digest = hashlib.new(digest_algorithm)
        self.payload_offset = None
        self.payload_digest = None
        self.proxy_dest = proxy_dest
        self._proxy_dest_conn_open = True
        self._prev_hunk_last_two_bytes = ''
        self.len = 0

    def _update(self, hunk):
        if self.payload_digest is None:
            # convoluted handling of two newlines crossing hunks
            # XXX write tests for this
            if self._prev_hunk_last_two_bytes.endswith('\n'):
                if hunk.startswith('\n'):
                    self.payload_digest = hashlib.new(self.digest_algorithm)
                    self.payload_digest.update(hunk[1:])
                    self.payload_offset = self.len + 1
                elif hunk.startswith('\r\n'):
                    self.payload_digest = hashlib.new(self.digest_algorithm)
                    self.payload_digest.update(hunk[2:])
                    self.payload_offset = self.len + 2
            elif self._prev_hunk_last_two_bytes == '\n\r':
                if hunk.startswith('\n'):
                    self.payload_digest = hashlib.new(self.digest_algorithm)
                    self.payload_digest.update(hunk[1:])
                    self.payload_offset = self.len + 1
            else:
                m = re.search(r'\n\r?\n', hunk)
                if m is not None:
                    self.payload_digest = hashlib.new(self.digest_algorithm)
                    self.payload_digest.update(hunk[m.end():])
                    self.payload_offset = self.len + m.end()

            # if we still haven't found start of payload hold on to these bytes
            if self.payload_digest is None:
                self._prev_hunk_last_two_bytes = hunk[-2:]
        else:
            self.payload_digest.update(hunk)

        self.block_digest.update(hunk)

        self.tempfile.write(hunk)

        if self._proxy_dest_conn_open:
            try:
                self.proxy_dest.sendall(hunk)
            except BaseException as e:
                self._proxy_dest_conn_open = False
                logging.warn('{} sending data to proxy client'.format(e))
                logging.info('will continue downloading from remote server without sending to client')

        self.len += len(hunk)


    def read(self, size=-1):
        hunk = self.fp.read(size=size)
        self._update(hunk)
        return hunk

    def readline(self, size=-1):
        # XXX depends on implementation details of self.fp.readline(), in
        # particular that it doesn't call self.fp.read()
        hunk = self.fp.readline(size=size)
        self._update(hunk)
        return hunk

    def close(self):
        return self.fp.close()

    def __len__(self):
        return self.len

    def payload_size(self):
        if self.payload_offset is not None:
            return self.len - self.payload_offset
        else:
            return 0


class ProxyingRecordingHTTPResponse(httplib.HTTPResponse):

    def __init__(self, sock, debuglevel=0, strict=0, method=None, buffering=False, proxy_dest=None, digest_algorithm='sha1'):
        httplib.HTTPResponse.__init__(self, sock, debuglevel=debuglevel, strict=strict, method=method, buffering=buffering)

        # Keep around extra reference to self.fp because HTTPResponse sets
        # self.fp=None after it finishes reading, but we still need it
        self.recorder = ProxyingRecorder(self.fp, proxy_dest, digest_algorithm)
        self.fp = self.recorder


class MitmProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def __init__(self, request, client_address, server):
        self.is_connect = False
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _determine_host_port(self):
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


    def _connect_to_host(self):
        # Connect to destination
        self._proxy_sock = socket.socket()
        self._proxy_sock.settimeout(10)
        self._proxy_sock.connect((self.hostname, int(self.port)))

        # Wrap socket if SSL is required
        if self.is_connect:
            self._proxy_sock = ssl.wrap_socket(self._proxy_sock)


    def _transition_to_ssl(self):
        self.request = self.connection = ssl.wrap_socket(self.connection, 
                server_side=True, certfile=self.server.ca[self.hostname])


    def do_CONNECT(self):
        self.is_connect = True
        try:
            # Connect to destination first
            self._determine_host_port()
            self._connect_to_host()

            # If successful, let's do this!
            self.send_response(200, 'Connection established')
            self.end_headers()
            self._transition_to_ssl()
        except Exception as e:
            self.send_error(500, str(e))
            return

        # Reload!
        self.setup()
        self.handle_one_request()


    def _construct_tunneled_url(self):
        if int(self.port) == 443:
            netloc = self.hostname
        else:
            netloc = '{}:{}'.format(self.hostname, self.port)

        result = urlparse.urlunparse(
            urlparse.ParseResult(
                scheme='https',
                netloc=netloc,
                params='',
                path=self.path,
                query='',
                fragment=''
            )
        )

        return result


    def do_COMMAND(self):
        if not self.is_connect:
            try:
                # Connect to destination
                self._determine_host_port()
                self._connect_to_host()
                assert self.url
            except Exception as e:
                self.send_error(500, str(e))
                return
        else:
            # if self.is_connect we already connected in do_CONNECT
            self.url = self._construct_tunneled_url()

        self._proxy_request()


    def _proxy_request(self):
        raise Exception('_proxy_request() not implemented in MitmProxyHandler, must be implemented in subclass!')

    def __getattr__(self, item):
        if item.startswith('do_'):
            return self.do_COMMAND

    def log_error(self, fmt, *args):
        logging.error("{0} - - [{1}] {2}".format(self.address_string(), 
            self.log_date_time_string(), fmt % args))

    def log_message(self, fmt, *args):
        logging.info("{} {} - - [{}] {}".format(self.__class__.__name__,
            self.address_string(), self.log_date_time_string(), fmt % args))


class WarcProxyHandler(MitmProxyHandler):

    def _proxy_request(self):
        # Build request
        req = '%s %s %s\r\n' % (self.command, self.path, self.request_version)
        
        # Add headers to the request
        req += '%s\r\n' % self.headers

        # Append message body if present to the request
        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))
            
        # Send it down the pipe!
        self._proxy_sock.sendall(req)

        # We want HTTPResponse's smarts about http and handling of
        # non-compliant servers. But HTTPResponse.read() doesn't return the raw
        # bytes read from the server, it unchunks them if they're chunked, and
        # might do other stuff. We want to send the raw bytes back to the
        # client. So we ignore the values returned by h.read() below. Instead
        # the ProxyingRecordingHTTPResponse takes care of sending the raw bytes
        # to the proxy client.
        
        # Proxy and record the response
        h = ProxyingRecordingHTTPResponse(self._proxy_sock, 
                proxy_dest=self.connection, 
                digest_algorithm=self.server.digest_algorithm)
        h.begin()
        
        buf = h.read(8192) 
        while buf != '':
            buf = h.read(8192)

        self.log_request(h.status, h.recorder.len)

        remote_ip = self._proxy_sock.getpeername()[0]

        # Let's close off the remote end
        h.close()
        self._proxy_sock.close()

        recorded_url = RecordedUrl(url=self.url, request_data=req,
                response_recorder=h.recorder, remote_ip=remote_ip)
        self.server.recorded_url_q.put(recorded_url)


class RecordedUrl:
    def __init__(self, url, request_data, response_recorder, remote_ip):
        self.url = url
        self.request_data = request_data
        self.response_recorder = response_recorder
        self.remote_ip = remote_ip


class WarcProxy(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):

    def __init__(self, server_address, req_handler_class=WarcProxyHandler, 
            bind_and_activate=True, ca=None, recorded_url_q=None,
            digest_algorithm='sha1'):
        BaseHTTPServer.HTTPServer.__init__(self, server_address, req_handler_class, bind_and_activate)
        self.ca = ca
        self.recorded_url_q = recorded_url_q
        self.digest_algorithm = digest_algorithm

    def server_activate(self):
        BaseHTTPServer.HTTPServer.server_activate(self)
        logging.info('WarcProxy listening on {0}:{1}'.format(self.server_address[0], self.server_address[1]))

    def server_close(self):
        logging.info('WarcProxy shutting down')
        BaseHTTPServer.HTTPServer.server_close(self)


class PlaybackProxyHandler(MitmProxyHandler):

    def _connect_to_host(self):
        # don't connect to host!
        pass

    def _proxy_request(self):
        date, location = self.server.playback_index_db.lookup_latest(self.url)
        logging.debug('lookup_latest returned {}:{}'.format(date, location))

        status = None
        if location is not None:
            try:
                response = self.gather_response(location['f'], location['o'])
            except:
                status = 500
                logging.error('PlaybackProxyHandler problem playing back {}'.format(self.url), exc_info=1)
                payload = '500 Warcprox Error\n\n{}\n'.format(traceback.format_exc())
                response = ('HTTP/1.1 500 Internal Server Error\r\n'
                        +   'Content-Type: text/plain\r\n'
                        +   'Content-Length: {}\r\n'
                        +   '\r\n'
                        +   '{}').format(len(payload), payload)
        else:
            status = 404
            response = ('HTTP/1.1 404 Not Found\r\n'
                    +   'Content-Type: text/plain\r\n'
                    +   'Content-Length: 19\r\n'
                    +   '\r\n'
                    +   '404 Not in Archive\n')

        self.connection.sendall(response)

        self.log_request(status, len(response))


    def open_warc_at_offset(self, warcfilename, offset):
        logging.debug('opening {} at offset {}'.format(warcfilename, offset))

        warcpath = None
        for p in (os.path.sep.join([self.server.warcs_dir, warcfilename]),
                os.path.sep.join([self.server.warcs_dir, '{}.open'.format(warcfilename)])):
            if os.path.exists(p):
                warcpath = p

        if warcpath is None:
            raise Exception('{} not found'.format(warcfilename))

        return warctools.warc.WarcRecord.open_archive(filename=warcpath, mode='rb', offset=offset)


    # returns payload starting after http headers
    def warc_record_http_payload(self, warcfilename, offset):
        fh = self.open_warc_at_offset(warcfilename, offset)
        try:
            for (offset, record, errors) in fh.read_records(limit=1, offsets=True):
                pass

            if errors:
                raise Exception('warc errors at {}:{} -- {}'.format(warcfilename, offset, errors))

            warc_type = record.get_header(warctools.WarcRecord.TYPE)
            if warc_type != warctools.WarcRecord.RESPONSE:
                raise Exception('invalid attempt to retrieve http payload of "{}" record'.format(warc_type))

            m = re.search(r'\n\r?\n', record.content[1])
            if m is None:
                raise Exception('end of http headers not found in record at {} offset {}'.format(warcfilename, offset))
            return record.content[1][m.end():]

        finally:
            fh.close()


    def gather_response(self, warcfilename, offset):
        fh = self.open_warc_at_offset(warcfilename, offset)
        try:
            for (offset, record, errors) in fh.read_records(limit=1, offsets=True):
                pass

            if errors:
                raise Exception('warc errors at {}:{} -- {}'.format(warcfilename, offset, errors))
                
            warc_type = record.get_header(warctools.WarcRecord.TYPE)

            if warc_type == warctools.WarcRecord.RESPONSE:
                return record.content[1]

            elif warc_type == warctools.WarcRecord.REVISIT:
                # response consists of http headers from revisit record and
                # payload from the referenced record
                warc_profile = record.get_header(warctools.WarcRecord.PROFILE)
                if warc_profile != warctools.WarcRecord.PROFILE_IDENTICAL_PAYLOAD_DIGEST:
                    raise Exception('unknown revisit record profile {}'.format(warc_profile))

                refers_to_target_uri = record.get_header(warctools.WarcRecord.REFERS_TO_TARGET_URI)
                refers_to_date = record.get_header(warctools.WarcRecord.REFERS_TO_DATE)

                logging.debug('revisit record references {} capture of {}'.format(refers_to_date, refers_to_target_uri))
                location = self.server.playback_index_db.lookup_exact(refers_to_target_uri, refers_to_date)
                logging.debug('loading http payload from {}'.format(location))
                http_payload = self.warc_record_http_payload(location['f'], location['o'])

                return record.content[1] + http_payload

            else:
                raise Exception('unknown warc record type {}'.format(warc_type))

        finally:
            fh.close()

        raise Exception('should not reach this point')


class PlaybackProxy(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):

    def __init__(self, server_address, req_handler_class=PlaybackProxyHandler, 
            bind_and_activate=True, ca=None, playback_index_db=None, 
            warcs_dir=None):
        BaseHTTPServer.HTTPServer.__init__(self, server_address, req_handler_class, bind_and_activate)
        self.ca = ca
        self.playback_index_db = playback_index_db
        self.warcs_dir = warcs_dir

    def server_activate(self):
        BaseHTTPServer.HTTPServer.server_activate(self)
        logging.info('PlaybackProxy listening on {0}:{1}'.format(self.server_address[0], self.server_address[1]))

    def server_close(self):
        logging.info('PlaybackProxy shutting down')
        BaseHTTPServer.HTTPServer.server_close(self)


class DedupDb:

    def __init__(self, dbm_file='./warcprox-dedup.db'):
        if os.path.exists(dbm_file):
            logging.info('opening existing deduplication database {}'.format(dbm_file))
        else:
            logging.info('creating new deduplication database {}'.format(dbm_file))

        self.db = gdbm.open(dbm_file, 'c')

    def close(self):
        self.db.close()

    def sync(self):
        self.db.sync()

    def save(self, key, response_record, offset):
        record_id = response_record.get_header(warctools.WarcRecord.ID)
        url = response_record.get_header(warctools.WarcRecord.URL)
        date = response_record.get_header(warctools.WarcRecord.DATE)

        py_value = {'i':record_id, 'u':url, 'd':date}
        json_value = json.dumps(py_value, separators=(',',':'))

        self.db[key] = json_value
        logging.debug('dedup db saved {}:{}'.format(key, json_value))


    def lookup(self, key):
        if key in self.db:
            json_result = self.db[key]
            result = json.loads(json_result)
            return result
        else:
            return None


class WarcWriterThread(threading.Thread):

    # port is only used for warc filename 
    def __init__(self, recorded_url_q, directory, rollover_size=1000000000, 
            rollover_idle_time=None, gzip=False, prefix='WARCPROX', port=0, 
            digest_algorithm='sha1', base32=False, dedup_db=None,
            playback_index_db=None):
        threading.Thread.__init__(self, name='WarcWriterThread')

        self.recorded_url_q = recorded_url_q

        self.rollover_size = rollover_size
        self.rollover_idle_time = rollover_idle_time

        self.gzip = gzip
        self.digest_algorithm = digest_algorithm
        self.base32 = base32
        self.dedup_db = dedup_db

        self.playback_index_db = playback_index_db

        # warc path and filename stuff
        self.directory = directory
        self.prefix = prefix
        self.port = port

        self._f = None
        self._fpath = None
        self._serial = 0
        
        if not os.path.exists(directory):
            logging.info("warc destination directory {} doesn't exist, creating it".format(directory))
            os.mkdir(directory)

        self.stop = threading.Event()

        self.listeners = []

    # returns a tuple (principal_record, request_record) where principal_record is either a response or revisit record
    def build_warc_records(self, recorded_url):
        warc_date = warctools.warc.warc_datetime_str(datetime.now())

        dedup_info = None
        if dedup_db is not None and recorded_url.response_recorder.payload_digest is not None:
            key = self.digest_str(recorded_url.response_recorder.payload_digest)
            dedup_info = dedup_db.lookup(key)

        if dedup_info is not None:
            # revisit record
            recorded_url.response_recorder.tempfile.seek(0)
            if recorded_url.response_recorder.payload_offset is not None:
                response_header_block = recorded_url.response_recorder.tempfile.read(recorded_url.response_recorder.payload_offset)
            else:
                response_header_block = recorded_url.response_recorder.tempfile.read()

            principal_record, principal_record_id = self.build_warc_record(
                    url=recorded_url.url, warc_date=warc_date,
                    data=response_header_block,
                    warc_type=warctools.WarcRecord.REVISIT,
                    refers_to=dedup_info['i'],
                    refers_to_target_uri=dedup_info['u'],
                    refers_to_date=dedup_info['d'],
                    profile=warctools.WarcRecord.PROFILE_IDENTICAL_PAYLOAD_DIGEST,
                    content_type=httptools.ResponseMessage.CONTENT_TYPE,
                    remote_ip=recorded_url.remote_ip)
        else:
            # response record
            principal_record, principal_record_id = self.build_warc_record(
                    url=recorded_url.url, warc_date=warc_date, 
                    recorder=recorded_url.response_recorder, 
                    warc_type=warctools.WarcRecord.RESPONSE,
                    content_type=httptools.ResponseMessage.CONTENT_TYPE,
                    remote_ip=recorded_url.remote_ip)

        request_record, request_record_id = self.build_warc_record(
                url=recorded_url.url, warc_date=warc_date, 
                data=recorded_url.request_data, 
                warc_type=warctools.WarcRecord.REQUEST, 
                content_type=httptools.RequestMessage.CONTENT_TYPE,
                concurrent_to=principal_record_id)

        return principal_record, request_record


    def digest_str(self, hash_obj):
        return '{}:{}'.format(hash_obj.name,
                base64.b32encode(hash_obj.digest()) if self.base32 else hash_obj.hexdigest())


    def build_warc_record(self, url, warc_date=None, recorder=None, data=None,
        concurrent_to=None, warc_type=None, content_type=None, remote_ip=None,
        profile=None, refers_to=None, refers_to_target_uri=None,
        refers_to_date=None):

        if warc_date is None:
            warc_date = warctools.warc.warc_datetime_str(datetime.now())

        record_id = warctools.WarcRecord.random_warc_uuid()

        headers = []
        if warc_type is not None:
            headers.append((warctools.WarcRecord.TYPE, warc_type))
        headers.append((warctools.WarcRecord.ID, record_id))
        headers.append((warctools.WarcRecord.DATE, warc_date))
        headers.append((warctools.WarcRecord.URL, url))
        if remote_ip is not None:
            headers.append((warctools.WarcRecord.IP_ADDRESS, remote_ip))
        if profile is not None:
            headers.append((warctools.WarcRecord.PROFILE, profile))
        if refers_to is not None:
            headers.append((warctools.WarcRecord.REFERS_TO, refers_to))
        if refers_to_target_uri is not None:
            headers.append((warctools.WarcRecord.REFERS_TO_TARGET_URI, refers_to_target_uri))
        if refers_to_date is not None:
            headers.append((warctools.WarcRecord.REFERS_TO_DATE, refers_to_date))
        if concurrent_to is not None:
            headers.append((warctools.WarcRecord.CONCURRENT_TO, concurrent_to))
        if content_type is not None:
            headers.append((warctools.WarcRecord.CONTENT_TYPE, content_type))

        if recorder is not None:
            headers.append((warctools.WarcRecord.CONTENT_LENGTH, str(len(recorder))))
            headers.append((warctools.WarcRecord.BLOCK_DIGEST, 
                self.digest_str(recorder.block_digest)))
            if recorder.payload_digest is not None:
                headers.append((warctools.WarcRecord.PAYLOAD_DIGEST, 
                    self.digest_str(recorder.payload_digest)))

            recorder.tempfile.seek(0)
            record = warctools.WarcRecord(headers=headers, content_file=recorder.tempfile)

        else:
            headers.append((warctools.WarcRecord.CONTENT_LENGTH, str(len(data))))
            block_digest = hashlib.new(self.digest_algorithm, data)
            headers.append((warctools.WarcRecord.BLOCK_DIGEST, 
                self.digest_str(block_digest)))

            content_tuple = content_type, data
            record = warctools.WarcRecord(headers=headers, content=content_tuple)

        return record, record_id


    def timestamp17(self):
        now = datetime.now()
        return '{}{}'.format(now.strftime('%Y%m%d%H%M%S'), now.microsecond//1000)

    def _close_writer(self):
        if self._fpath:
            logging.info('closing {0}'.format(self._f_finalname))
            self._f.close()
            finalpath = os.path.sep.join([self.directory, self._f_finalname])
            os.rename(self._fpath, finalpath)

            self._fpath = None
            self._f = None

    def _build_warcinfo_record(self, filename):
        warc_record_date = warctools.warc.warc_datetime_str(datetime.now())
        record_id = warctools.WarcRecord.random_warc_uuid()

        headers = []
        headers.append((warctools.WarcRecord.ID, record_id))
        headers.append((warctools.WarcRecord.TYPE, warctools.WarcRecord.WARCINFO))
        headers.append((warctools.WarcRecord.FILENAME, filename))
        headers.append((warctools.WarcRecord.DATE, warc_record_date))

        warcinfo_fields = []
        warcinfo_fields.append('software: warcprox.py https://github.com/internetarchive/warcprox')
        hostname = socket.gethostname()
        warcinfo_fields.append('hostname: {0}'.format(hostname))
        warcinfo_fields.append('ip: {0}'.format(socket.gethostbyname(hostname)))
        warcinfo_fields.append('format: WARC File Format 1.0')
        # warcinfo_fields.append('robots: ignore')
        # warcinfo_fields.append('description: {0}'.format(self.description))   
        # warcinfo_fields.append('isPartOf: {0}'.format(self.is_part_of))   
        data = '\r\n'.join(warcinfo_fields) + '\r\n'

        record = warctools.WarcRecord(headers=headers, content=('application/warc-fields', data))

        return record


    # <!-- <property name="template" value="${prefix}-${timestamp17}-${serialno}-${heritrix.pid}~${heritrix.hostname}~${heritrix.port}" /> -->
    def _writer(self):
        if self._fpath and os.path.getsize(self._fpath) > self.rollover_size:
            self._close_writer()

        if self._f == None:
            self._f_finalname = '{}-{}-{:05d}-{}-{}-{}.warc{}'.format(
                    self.prefix, self.timestamp17(), self._serial, os.getpid(),
                    socket.gethostname(), self.port, '.gz' if self.gzip else '')
            self._fpath = os.path.sep.join([self.directory, self._f_finalname + '.open'])

            self._f = open(self._fpath, 'wb')

            warcinfo_record = self._build_warcinfo_record(self._f_finalname)
            warcinfo_record.write_to(self._f, gzip=self.gzip)

            self._serial += 1

        return self._f


    def _final_tasks(self, recorded_url, recordset, recordset_offset):
        if (self.dedup_db is not None
                and recordset[0].get_header(warctools.WarcRecord.TYPE) == warctools.WarcRecord.RESPONSE
                and recorded_url.response_recorder.payload_size() > 0):
            key = self.digest_str(recorded_url.response_recorder.payload_digest)
            self.dedup_db.save(key, recordset[0], recordset_offset)

        if self.playback_index_db is not None:
            playback_index_db.save(self._f_finalname, recordset, recordset_offset)

        recorded_url.response_recorder.tempfile.close()

    def run(self):
        logging.info('WarcWriterThread starting, directory={} gzip={} rollover_size={} rollover_idle_time={} prefix={} port={}'.format(
                os.path.abspath(self.directory), self.gzip, self.rollover_size, 
                self.rollover_idle_time, self.prefix, self.port))

        self._last_sync = self._last_activity = time.time()

        while not self.stop.is_set():
            try:
                recorded_url = self.recorded_url_q.get(block=True, timeout=0.5)

                self._last_activity = time.time()
                
                recordset = self.build_warc_records(recorded_url)
            
                writer = self._writer()
                recordset_offset = writer.tell()

                for record in recordset:
                    offset = writer.tell()
                    record.write_to(writer, gzip=self.gzip)
                    logging.debug('wrote warc record: warc_type={} content_length={} url={} warc={} offset={}'.format(
                            record.get_header(warctools.WarcRecord.TYPE),
                            record.get_header(warctools.WarcRecord.CONTENT_LENGTH),
                            record.get_header(warctools.WarcRecord.URL),
                            self._fpath, offset))

                self._f.flush()

                self._final_tasks(recorded_url, recordset, recordset_offset)

            except Queue.Empty:
                if (self._fpath is not None 
                        and self.rollover_idle_time is not None 
                        and self.rollover_idle_time > 0
                        and time.time() - self._last_activity > self.rollover_idle_time):
                    logging.debug('rolling over warc file after {} seconds idle'.format(time.time() - self._last_activity))
                    self._close_writer()

                if time.time() - self._last_sync > 60:
                    if self.dedup_db: 
                        self.dedup_db.sync()
                    if self.playback_index_db: 
                        self.playback_index_db.sync()
                    self._last_sync = time.time()

        logging.info('WarcWriterThread shutting down')
        self._close_writer();


class PlaybackIndexDb:

    def __init__(self, dbm_file='./warcprox-playback-index.db'):
        if os.path.exists(dbm_file):
            logging.info('opening existing playback index database {}'.format(dbm_file))
        else:
            logging.info('creating new playback index database {}'.format(dbm_file))

        self.db = gdbm.open(dbm_file, 'c')


    def close(self):
        self.db.close()

    def sync(self):
        self.db.sync()

    def save(self, warcfile, recordset, offset):
        response_record = recordset[0]
        # XXX canonicalize url?
        url = response_record.get_header(warctools.WarcRecord.URL)
        date = response_record.get_header(warctools.WarcRecord.DATE)

        # url:{date1:{'f':warcfile,'o':response_offset,'q':request_offset,'t':response/revisit,'u':revisit_target_url,'d':revisit_target_date},date2:{...},...}
        if url in self.db:
            existing_json_value = self.db[url]
            py_value = json.loads(existing_json_value)
        else:
            py_value = {}

        py_value[date] = {'f':warcfile, 'o':offset}

        json_value = json.dumps(py_value, separators=(',',':'))

        self.db[url] = json_value

        logging.debug('playback index saved: {}:{}'.format(url, json_value))


    def lookup_latest(self, url):
        if url not in self.db:
            return None, None

        json_value = self.db[url]
        py_value = json.loads(json_value)

        latest_date = max(py_value)
        return latest_date, py_value[latest_date]


    def lookup_exact(self, url, warc_date):
        if url not in self.db:
            return None

        json_value = self.db[url]
        py_value = json.loads(json_value)

        if warc_date in py_value:
            return py_value[warc_date]
        else:
            return None


if __name__ == '__main__':

    arg_parser = argparse.ArgumentParser(
            description='warcprox - WARC writing MITM HTTP/S proxy',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('-p', '--port', dest='port', default='8000', 
            help='port to listen on')
    arg_parser.add_argument('-b', '--address', dest='address', 
            default='localhost', help='address to listen on')
    arg_parser.add_argument('-c', '--cacert', dest='cacert', 
            default='./{0}-warcprox-ca.pem'.format(socket.gethostname()), 
            help='CA certificate file; if file does not exist, it will be created')
    arg_parser.add_argument('--certs-dir', dest='certs_dir', 
            default='./{0}-warcprox-ca'.format(socket.gethostname()), 
            help='where to store and load generated certificates')
    arg_parser.add_argument('-d', '--dir', dest='directory', 
            default='./warcs', help='where to write warcs')
    arg_parser.add_argument('-z', '--gzip', dest='gzip', action='store_true', 
            help='write gzip-compressed warc records')
    arg_parser.add_argument('-n', '--prefix', dest='prefix', 
            default='WARCPROX', help='WARC filename prefix')
    arg_parser.add_argument('-s', '--size', dest='size', 
            default=1000*1000*1000, 
            help='WARC file rollover size threshold in bytes')
    arg_parser.add_argument('--rollover-idle-time', 
            dest='rollover_idle_time', default=None, 
            help="WARC file rollover idle time threshold in seconds (so that Friday's last open WARC doesn't sit there all weekend waiting for more data)")
    arg_parser.add_argument('-g', '--digest-algorithm', dest='digest_algorithm', 
            default='sha1', help='digest algorithm, one of {}'.format(', '.join(hashlib.algorithms)))
    arg_parser.add_argument('--base32', dest='base32', action='store_true',
            default=False, help='write digests in Base32 instead of hex')
    arg_parser.add_argument('-j', '--dedup-db-file', dest='dedup_db_file',
            default='./warcprox-dedup.db', help='persistent deduplication database file; empty string or /dev/null disables deduplication')
    arg_parser.add_argument('-P', '--playback-port', dest='playback_port',
            default=None, help='port to listen on for instant playback')
    arg_parser.add_argument('--playback-index-db-file', dest='playback_index_db_file',
            default='./warcprox-playback-index.db', 
            help='playback index database file (only used if --playback-port is specified)')
    arg_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true')
    arg_parser.add_argument('-q', '--quiet', dest='quiet', action='store_true')
    # [--ispartof=warcinfo ispartof]
    # [--description=warcinfo description]
    # [--operator=warcinfo operator]
    # [--httpheader=warcinfo httpheader]
    args = arg_parser.parse_args()

    if args.verbose:
        loglevel = logging.DEBUG
    elif args.quiet:
        loglevel = logging.WARNING
    else:
        loglevel = logging.INFO

    logging.basicConfig(stream=sys.stdout, level=loglevel, 
            format='%(asctime)s %(process)d %(threadName)s %(levelname)s %(funcName)s(%(filename)s:%(lineno)d) %(message)s')

    try:
        hashlib.new(args.digest_algorithm)
    except Exception as e:
        logging.fatal(e)
        exit(1)

    if args.dedup_db_file in (None, '', '/dev/null'):
        logging.info('deduplication disabled')
        dedup_db = None
    else:
        dedup_db = DedupDb(args.dedup_db_file)

    recorded_url_q = Queue.Queue()

    ca = CertificateAuthority(args.cacert, args.certs_dir)

    proxy = WarcProxy(server_address=(args.address, int(args.port)),
            ca=ca, recorded_url_q=recorded_url_q,
            digest_algorithm=args.digest_algorithm)

    if args.playback_port is not None:
        playback_index_db = PlaybackIndexDb(args.playback_index_db_file)
        playback_server_address=(args.address, int(args.playback_port))
        playback_proxy = PlaybackProxy(server_address=playback_server_address,
                ca=ca, playback_index_db=playback_index_db, 
                warcs_dir=args.directory)
        playback_proxy_thread = threading.Thread(target=playback_proxy.serve_forever, name='PlaybackProxyThread')
        playback_proxy_thread.start()
    else:
        playback_index_db = None
        playback_proxy = None

    warc_writer = WarcWriterThread(recorded_url_q=recorded_url_q,
            directory=args.directory, gzip=args.gzip, prefix=args.prefix,
            port=int(args.port), rollover_size=int(args.size), 
            rollover_idle_time=int(args.rollover_idle_time) if args.rollover_idle_time is not None else None,
            base32=args.base32, dedup_db=dedup_db,
            digest_algorithm=args.digest_algorithm,
            playback_index_db=playback_index_db)

    proxy_thread = threading.Thread(target=proxy.serve_forever, name='ProxyThread')
    proxy_thread.start()
    warc_writer.start()

    stop = threading.Event()
    signal.signal(signal.SIGTERM, stop.set)

    try:
        while not stop.is_set():
            time.sleep(0.5)
    except:
        pass
    finally:
        warc_writer.stop.set()
        proxy.shutdown()
        proxy.server_close()

        if playback_proxy is not None:
            playback_proxy.shutdown()
            playback_proxy.server_close()

        if dedup_db is not None:
            dedup_db.close()

        if playback_index_db is not None:
            playback_index_db.close()

