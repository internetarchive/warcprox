'''
warcprox/playback.py - rudimentary support for playback of urls archived by
warcprox (not much used or maintained)

Copyright (C) 2013-2017 Internet Archive

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
import http.server as http_server
import socketserver
import logging
import os
from hanzo import warctools
import json
import traceback
import re
from warcprox.mitmproxy import MitmProxyHandler
import warcprox
import sqlite3
import threading
from cachetools import TTLCache

class PlaybackProxyHandler(MitmProxyHandler):
    logger = logging.getLogger("warcprox.playback.PlaybackProxyHandler")

    # @Override
    def _connect_to_remote_server(self):
        # don't connect to any remote server!
        pass

    # @Override
    def _proxy_request(self):
        date, location = self.server.playback_index_db.lookup_latest(self.url)
        self.logger.debug('lookup_latest returned {}:{}'.format(date, location))

        status = None
        if location is not None:
            try:
                status, sz = self._send_response_from_warc(location['f'], location['o'])
            except:
                status = 500
                self.logger.error('PlaybackProxyHandler problem playing back {}'.format(self.url), exc_info=1)
                payload = '500 Warcprox Error\n\n{}\n'.format(traceback.format_exc()).encode('utf-8')
                headers = (b'HTTP/1.1 500 Internal Server Error\r\n'
                        +  b'Content-Type: text/plain;charset=utf-8\r\n'
                        +  b'Content-Length: ' + str(len(payload)).encode('utf-8') + b'\r\n'
                        +  b'\r\n')
                self.connection.sendall(headers)
                self.connection.sendall(payload)
                sz = len(headers) + len(payload)
        else:
            status = 404
            payload = b'404 Not in Archive\n'
            headers = (b'HTTP/1.1 404 Not Found\r\n'
                    +  b'Content-Type: text/plain;charset=utf-8\r\n'
                    +  b'Content-Length: ' + str(len(payload)).encode('ascii') + b'\r\n'
                    +  b'\r\n')
            self.connection.sendall(headers)
            self.connection.sendall(payload)
            sz = len(headers) + len(payload)

        self.log_message('%r %s %s %s',
                         self.requestline, str(status), str(sz),
                         repr(location) if location else '-')


    def _open_warc_at_offset(self, warcfilename, offset):
        self.logger.debug('opening {} at offset {}'.format(warcfilename, offset))

        warcpath = None
        for p in (os.path.sep.join([self.server.warcs_dir, warcfilename]),
                os.path.sep.join([self.server.warcs_dir, '{}.open'.format(warcfilename)])):
            if os.path.exists(p):
                warcpath = p

        if warcpath is None:
            raise Exception('{} not found'.format(warcfilename))

        return warctools.warc.WarcRecord.open_archive(filename=warcpath, mode='rb', offset=offset)

    def _send_response(self, headers, payload_fh):
        status = '-'
        m = re.match(br'^HTTP/\d\.\d (\d{3})', headers)
        if m is not None:
            status = m.group(1)

        self.connection.sendall(headers)
        sz = len(headers)

        while True:
            buf = payload_fh.read(8192)
            if buf == b'': break
            self.connection.sendall(buf)
            sz += len(buf)

        return status, sz


    def _send_headers_and_refd_payload(
            self, headers, refers_to_target_uri, refers_to_date, payload_digest):
        location = self.server.playback_index_db.lookup_exact(
                refers_to_target_uri, refers_to_date, payload_digest)
        self.logger.debug('loading http payload from {}'.format(location))

        fh = self._open_warc_at_offset(location['f'], location['o'])
        try:
            for (offset, record, errors) in fh.read_records(limit=1, offsets=True):
                pass

            if not record:
                raise Exception('failed to read record at offset {} from {}'.format(offset, warcfilename))

            if errors:
                raise Exception('warc errors at {}:{} -- {}'.format(location['f'], offset, errors))

            if record.type != warctools.WarcRecord.RESPONSE:
                raise Exception('invalid attempt to retrieve http payload of "{}" record'.format(warc_type))

            # find end of headers
            while True:
                line = record.content_file.readline()
                if line == b'' or re.match(br'^\r?\n$', line):
                    break

            return self._send_response(headers, record.content_file)

        finally:
            fh.close()


    def _send_response_from_warc(self, warcfilename, offset):
        fh = self._open_warc_at_offset(warcfilename, offset)
        try:
            for (offset, record, errors) in fh.read_records(limit=1, offsets=True):
                pass

            if not record:
                raise Exception('failed to read record at offset {} from {}'.format(offset, warcfilename))

            if errors:
                raise Exception('warc errors at {}:{} -- {}'.format(warcfilename, offset, errors))

            if record.type == warctools.WarcRecord.RESPONSE:
                headers_buf = bytearray()
                while True:
                    line = record.content_file.readline()
                    headers_buf.extend(line)
                    if line == b'' or re.match(b'^\r?\n$', line):
                        break

                return self._send_response(headers_buf, record.content_file)

            elif record.type == warctools.WarcRecord.REVISIT:
                # response consists of http headers from revisit record and
                # payload from the referenced record
                warc_profile = record.get_header(warctools.WarcRecord.PROFILE)
                if warc_profile != warctools.WarcRecord.PROFILE_IDENTICAL_PAYLOAD_DIGEST:
                    raise Exception('unknown revisit record profile {}'.format(warc_profile))

                refers_to_target_uri = record.get_header(
                        warctools.WarcRecord.REFERS_TO_TARGET_URI).decode(
                                'latin1')
                refers_to_date = record.get_header(
                        warctools.WarcRecord.REFERS_TO_DATE).decode('latin1')
                payload_digest = record.get_header(
                        warctools.WarcRecord.PAYLOAD_DIGEST).decode('latin1')
                self.logger.debug(
                        'revisit record references %s:%s capture of %s',
                        refers_to_date, payload_digest, refers_to_target_uri)
                return self._send_headers_and_refd_payload(
                        record.content[1], refers_to_target_uri, refers_to_date,
                        payload_digest)

            else:
                # send it back raw, whatever it is
                headers_buf = bytearray()
                headers_buf.extend(b'HTTP/1.0 200 OK\r\n')
                headers_buf.extend(b'content-length: ' + record.get_header(b'content-length') + b'\r\n')
                headers_buf.extend(b'content-type: ' + record.get_header(b'content-type') + b'\r\n')
                headers_buf.extend(b'\r\n')
                return self._send_response(headers_buf, record.content_file)

        finally:
            fh.close()

        raise Exception('should not reach this point')


class PlaybackProxy(socketserver.ThreadingMixIn, http_server.HTTPServer):
    logger = logging.getLogger("warcprox.playback.PlaybackProxy")

    def __init__(self, ca=None, playback_index_db=None, options=warcprox.Options()):
        server_address = (options.address or 'localhost', options.playback_port if options.playback_port is not None else 8001)
        http_server.HTTPServer.__init__(self, server_address, PlaybackProxyHandler, bind_and_activate=True)
        self.ca = ca
        self.playback_index_db = playback_index_db
        self.warcs_dir = options.directory
        self.options = options
        self.bad_hostnames_ports = TTLCache(maxsize=1024, ttl=60)
        self.bad_hostnames_ports_lock = threading.RLock()

    def server_activate(self):
        http_server.HTTPServer.server_activate(self)
        self.logger.info('PlaybackProxy listening on {}:{}'.format(self.server_address[0], self.server_address[1]))

    def server_close(self):
        self.logger.info('PlaybackProxy shutting down')
        http_server.HTTPServer.server_close(self)


class PlaybackIndexDb:
    logger = logging.getLogger("warcprox.playback.PlaybackIndexDb")

    def __init__(self, file='./warcprox.sqlite', options=warcprox.Options()):
        self.file = file
        self._lock = threading.RLock()

        if os.path.exists(self.file):
            self.logger.info(
                    'opening existing playback index database %s', self.file)
        else:
            self.logger.info(
                    'creating new playback index database %s', self.file)

        conn = sqlite3.connect(self.file)
        conn.execute(
                'create table if not exists playback ('
                '  url varchar(4000) primary key,'
                '  value varchar(4000)'
                ');')
        conn.commit()
        conn.close()

    def close(self):
        pass

    def sync(self):
        pass

    def notify(self, recorded_url, records):
        if records:
            self.save(records[0].warc_filename, records, records[0].offset)

    def save(self, warcfile, recordset, offset):
        response_record = recordset[0]
        # XXX canonicalize url?
        url = response_record.get_header(warctools.WarcRecord.URL).decode('latin1')
        date_str = response_record.get_header(warctools.WarcRecord.DATE).decode('latin1')
        payload_digest_str = response_record.get_header(warctools.WarcRecord.PAYLOAD_DIGEST).decode('latin1')

        # there could be two visits of same url in the same second, and WARC-Date is
        # prescribed as YYYY-MM-DDThh:mm:ssZ, so we have to handle it :-\

        # url:{date1:[record1={'f':warcfile,'o':response_offset,'q':request_offset,'d':payload_digest},record2,...],date2:[{...}],...}

        with self._lock:
            conn = sqlite3.connect(self.file)
            cursor = conn.execute(
                    'select value from playback where url = ?', (url,))
            result_tuple = cursor.fetchone()
            if result_tuple:
                py_value = json.loads(result_tuple[0])
            else:
                py_value = {}

            if date_str in py_value:
                py_value[date_str].append(
                        {'f': warcfile, 'o': offset, 'd': payload_digest_str})
            else:
                py_value[date_str] = [
                        {'f': warcfile, 'o': offset, 'd': payload_digest_str}]

            json_value = json.dumps(py_value, separators=(',',':'))

            conn.execute(
                    'insert or replace into playback (url, value) '
                    'values (?, ?)', (url, json_value))
            conn.commit()
            conn.close()

        self.logger.debug('playback index saved: {}:{}'.format(url, json_value))

    def lookup_latest(self, url):
        conn = sqlite3.connect(self.file)
        cursor = conn.execute(
                'select value from playback where url = ?', (url,))
        result_tuple = cursor.fetchone()
        conn.close()

        if not result_tuple:
            return None, None

        json_value = result_tuple[0]
        self.logger.debug('%r:%r', url, json_value)
        py_value = json.loads(json_value)

        latest_date = max(py_value)
        result = py_value[latest_date][0]
        result['d'] = result['d'].encode('ascii')
        return latest_date, result

    # in python3 params are bytes
    def lookup_exact(self, url, warc_date, payload_digest):
        conn = sqlite3.connect(self.file)
        cursor = conn.execute(
                'select value from playback where url = ?', (url,))
        result_tuple = cursor.fetchone()
        conn.close()

        if not result_tuple:
            return None

        json_value = result_tuple[0]
        self.logger.debug('%r:%r', url, json_value)
        py_value = json.loads(json_value)

        if warc_date in py_value:
            for record in py_value[warc_date]:
                if record['d'] == payload_digest:
                    self.logger.debug(
                            "found exact match for (%r,%r,%r)",
                            warc_date, payload_digest, url)
                    record['d'] = record['d']
                    return record
        else:
            self.logger.info(
                    "match not found for (%r,%r,%r)", warc_date, payload_digest, url)
            return None
