'''
warcprox/playback.py - rudimentary support for playback of urls archived by
warcprox (not much used or maintained)

Copyright (C) 2013-2016 Internet Archive

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

from __future__ import absolute_import

try:
    import http.server as http_server
except ImportError:
    import BaseHTTPServer as http_server

try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

import logging
import os
from hanzo import warctools
import json
import traceback
import re
from warcprox.mitmproxy import MitmProxyHandler
import warcprox

class PlaybackProxyHandler(MitmProxyHandler):
    logger = logging.getLogger("warcprox.playback.PlaybackProxyHandler")

    # @Override
    def _connect_to_remote_server(self):
        # don't connect to any remote server!
        pass


    # @Override
    def _proxy_request(self):
        date, location = self.server.playback_index_db.lookup_latest(self.url.encode('utf-8'))
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

        self.log_message('"%s" %s %s %s',
                         self.requestline, str(status), str(sz), repr(location) if location else '-')


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


    def _send_headers_and_refd_payload(self, headers, refers_to, refers_to_target_uri, refers_to_date):
        location = self.server.playback_index_db.lookup_exact(refers_to_target_uri, refers_to_date, record_id=refers_to)
        self.logger.debug('loading http payload from {}'.format(location))

        fh = self._open_warc_at_offset(location['f'], location['o'])
        try:
            for (offset, record, errors) in fh.read_records(limit=1, offsets=True):
                pass

            if errors:
                raise Exception('warc errors at {}:{} -- {}'.format(warcfilename, offset, errors))

            warc_type = record.get_header(warctools.WarcRecord.TYPE)
            if warc_type != warctools.WarcRecord.RESPONSE:
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

            if errors:
                raise Exception('warc errors at {}:{} -- {}'.format(warcfilename, offset, errors))

            warc_type = record.get_header(warctools.WarcRecord.TYPE)

            if warc_type == warctools.WarcRecord.RESPONSE:
                headers_buf = bytearray()
                while True:
                    line = record.content_file.readline()
                    headers_buf.extend(line)
                    if line == b'' or re.match(b'^\r?\n$', line):
                        break

                return self._send_response(headers_buf, record.content_file)

            elif warc_type == warctools.WarcRecord.REVISIT:
                # response consists of http headers from revisit record and
                # payload from the referenced record
                warc_profile = record.get_header(warctools.WarcRecord.PROFILE)
                if warc_profile != warctools.WarcRecord.PROFILE_IDENTICAL_PAYLOAD_DIGEST:
                    raise Exception('unknown revisit record profile {}'.format(warc_profile))

                refers_to = record.get_header(warctools.WarcRecord.REFERS_TO)
                refers_to_target_uri = record.get_header(warctools.WarcRecord.REFERS_TO_TARGET_URI)
                refers_to_date = record.get_header(warctools.WarcRecord.REFERS_TO_DATE)

                self.logger.debug('revisit record references {}:{} capture of {}'.format(refers_to_date, refers_to, refers_to_target_uri))
                return self._send_headers_and_refd_payload(record.content[1], refers_to, refers_to_target_uri, refers_to_date)

            else:
                raise Exception('unknown warc record type {}'.format(warc_type))

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

    def server_activate(self):
        http_server.HTTPServer.server_activate(self)
        self.logger.info('PlaybackProxy listening on {0}:{1}'.format(self.server_address[0], self.server_address[1]))

    def server_close(self):
        self.logger.info('PlaybackProxy shutting down')
        http_server.HTTPServer.server_close(self)


class PlaybackIndexDb(object):
    logger = logging.getLogger("warcprox.playback.PlaybackIndexDb")

    def __init__(self, dbm_file='./warcprox-playback-index.db'):
        try:
            import dbm.gnu as dbm_gnu
        except ImportError:
            try:
                import gdbm as dbm_gnu
            except ImportError:
                import anydbm as dbm_gnu

        if os.path.exists(dbm_file):
            self.logger.info('opening existing playback index database {}'.format(dbm_file))
        else:
            self.logger.info('creating new playback index database {}'.format(dbm_file))

        self.db = dbm_gnu.open(dbm_file, 'c')

    def close(self):
        self.db.close()

    def sync(self):
        try:
            self.db.sync()
        except:
            pass

    def notify(self, recorded_url, records):
        self.save(records[0].warc_filename, records, records[0].offset)

    def save(self, warcfile, recordset, offset):
        response_record = recordset[0]
        # XXX canonicalize url?
        url = response_record.get_header(warctools.WarcRecord.URL)
        date_str = response_record.get_header(warctools.WarcRecord.DATE).decode('latin1')
        record_id_str = response_record.get_header(warctools.WarcRecord.ID).decode('latin1')

        # there could be two visits of same url in the same second, and WARC-Date is
        # prescribed as YYYY-MM-DDThh:mm:ssZ, so we have to handle it :-\

        # url:{date1:[record1={'f':warcfile,'o':response_offset,'q':request_offset,'i':record_id},record2,...],date2:[{...}],...}
        if url in self.db:
            existing_json_value = self.db[url].decode('utf-8')
            py_value = json.loads(existing_json_value)
        else:
            py_value = {}

        if date_str in py_value:
            py_value[date_str].append({'f':warcfile, 'o':offset, 'i':record_id_str})
        else:
            py_value[date_str] = [{'f':warcfile, 'o':offset, 'i':record_id_str}]

        json_value = json.dumps(py_value, separators=(',',':'))

        self.db[url] = json_value.encode('utf-8')

        self.logger.debug('playback index saved: {}:{}'.format(url, json_value))


    def lookup_latest(self, url):
        if url not in self.db:
            return None, None

        json_value = self.db[url].decode('utf-8')
        self.logger.debug("{}:{}".format(repr(url), repr(json_value)))
        py_value = json.loads(json_value)

        latest_date = max(py_value)
        result = py_value[latest_date][0]
        result['i'] = result['i'].encode('ascii')
        return latest_date, result


    # in python3 params are bytes
    def lookup_exact(self, url, warc_date, record_id):
        if url not in self.db:
            return None

        json_value = self.db[url].decode('utf-8')
        self.logger.debug("{}:{}".format(repr(url), repr(json_value)))
        py_value = json.loads(json_value)

        warc_date_str = warc_date.decode('ascii')

        if warc_date_str in py_value:
            for record in py_value[warc_date_str]:
                if record['i'].encode('ascii') == record_id:
                    self.logger.debug("found exact match for ({},{},{})".format(repr(warc_date), repr(record_id), repr(url)))
                    record['i'] = record['i'].encode('ascii')
                    return record
        else:
            self.logger.info("match not found for ({},{},{})".format(repr(warc_date), repr(record_id), repr(url)))
            return None


