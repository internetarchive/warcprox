#!/usr/bin/env python
'''
warcprox/crawl_log.py - heritrix-style crawl logger

Copyright (C) 2017 Internet Archive

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
import logging
import datetime
import json
import os
import warcprox
import socket

class CrawlLogger(object):
    def __init__(self, dir_, options=warcprox.Options()):
        self.dir = dir_
        self.options = options
        self.hostname = socket.gethostname().split('.', 1)[0]

    def start(self):
        if not os.path.exists(self.dir):
            logging.info('creating directory %r', self.dir)
            os.mkdir(self.dir)

    def notify(self, recorded_url, records):
        # 2017-08-03T21:45:24.496Z   200       2189 https://autismcouncil.wisconsin.gov/robots.txt P https://autismcouncil.wisconsin.gov/ text/plain #001 20170803214523617+365 sha1:PBS2CEF7B4OSEXZZF3QE2XN2VHYCPNPX https://autismcouncil.wisconsin.gov/ duplicate:digest {"warcFileOffset":942,"contentSize":2495,"warcFilename":"ARCHIVEIT-2159-TEST-JOB319150-20170803214522386-00000.warc.gz"}
        now = datetime.datetime.utcnow()
        extra_info = {'contentSize': recorded_url.size,}
        if records:
            extra_info['warcFilename'] = records[0].warc_filename
            extra_info['warcFileOffset'] = records[0].offset
        if recorded_url.method != 'GET':
            extra_info['method'] = recorded_url.method
        if recorded_url.response_recorder:
            content_length = recorded_url.response_recorder.len - recorded_url.response_recorder.payload_offset
            payload_digest = warcprox.digest_str(
                recorded_url.payload_digest,
                self.options.base32)
        else:
            # WARCPROX_WRITE_RECORD request
            content_length = int(records[0].get_header(b'Content-Length'))
            payload_digest = records[0].get_header(b'WARC-Payload-Digest')
        fields = [
            '{:%Y-%m-%dT%H:%M:%S}.{:03d}Z'.format(now, now.microsecond//1000),
            '% 5s' % recorded_url.status,
            '% 10s' % content_length,
            recorded_url.url,
            '-', # hop path
            recorded_url.referer or '-',
            recorded_url.mimetype or '-',
            '-',
            '{:%Y%m%d%H%M%S}{:03d}+{:03d}'.format(
                recorded_url.timestamp,
                recorded_url.timestamp.microsecond//1000,
                recorded_url.duration.microseconds//1000),
            payload_digest,
            recorded_url.warcprox_meta.get('metadata', {}).get('seed', '-'),
            'duplicate:digest' if records and records[0].type == b'revisit' else '-',
            json.dumps(extra_info, separators=(',',':')),
        ]
        for i in range(len(fields)):
            # `fields` is a mix of `bytes` and `unicode`, make them all `bytes`
            try:
                fields[i] = fields[i].encode('utf-8')
            except:
                pass
        line = b' '.join(fields) + b'\n'

        prefix = recorded_url.warcprox_meta.get('warc-prefix', 'crawl')
        filename = '%s-%s-%s.log' % (
                prefix, self.hostname, self.options.server_port)
        crawl_log_path = os.path.join(self.dir, filename)

        with open(crawl_log_path, 'ab') as f:
            f.write(line)

