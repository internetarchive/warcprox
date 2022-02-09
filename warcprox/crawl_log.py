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
from urllib3.exceptions import TimeoutError, HTTPError, NewConnectionError, MaxRetryError

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
        status = self.get_artificial_status(recorded_url)
        extra_info = {'contentSize': recorded_url.size,} if recorded_url.size is not None and recorded_url.size > 0 else {}
        if hasattr(recorded_url, 'exception') and recorded_url.exception is not None:
            extra_info['exception'] = str(recorded_url.exception).replace(" ", "_")
            if(hasattr(recorded_url, 'message') and recorded_url.message is not None):
                extra_info['exceptionMessage'] = str(recorded_url.message).replace(" ", "_")
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
        elif records is not None and len(records) > 0:
            # WARCPROX_WRITE_RECORD request
            content_length = int(records[0].get_header(b'Content-Length'))
            payload_digest = records[0].get_header(b'WARC-Payload-Digest')
        else:
            content_length = 0
            payload_digest = '-'
        logging.info('metadata %s', recorded_url.warcprox_meta)
        hop_path = recorded_url.warcprox_meta["hop_path"] if "hop_path" in recorded_url.warcprox_meta and recorded_url.warcprox_meta["hop_path"] and len(recorded_url.warcprox_meta["hop_path"].strip()) > 0 else '-'
        hop_path_parent = recorded_url.warcprox_meta["hop_path_parent"] if "hop_path_parent" in recorded_url.warcprox_meta else None
        if hop_path_parent and hop_path_parent != recorded_url.url:
            hop_path = str(hop_path if hop_path and hop_path != "-" else "") + "B"
        fields = [
            '{:%Y-%m-%dT%H:%M:%S}.{:03d}Z'.format(now, now.microsecond//1000),
            '% 5s' % status,
            '% 10s' % content_length,
            recorded_url.url,
            hop_path,
            recorded_url.referer or '-',
            recorded_url.mimetype if recorded_url.mimetype is not None and recorded_url.mimetype.strip() else '-',
            '-',
            '{:%Y%m%d%H%M%S}{:03d}+{:03d}'.format(
                recorded_url.timestamp,
                recorded_url.timestamp.microsecond//1000,
                recorded_url.duration.microseconds//1000) if (recorded_url.timestamp is not None and recorded_url.duration is not None) else '-',
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

    def get_artificial_status(self, recorded_url):
        # urllib3 Does not specify DNS errors. We must parse them from the exception string.
        # Unfortunately, the errors are reported differently on different systems.
        # https://stackoverflow.com/questions/40145631

        if hasattr(recorded_url, 'exception') and isinstance(recorded_url.exception, (MaxRetryError, )):
            return '-8'
        elif hasattr(recorded_url, 'exception') and isinstance(recorded_url.exception, (NewConnectionError, )):
            exception_string=str(recorded_url.exception)
            if ("[Errno 11001] getaddrinfo failed" in exception_string or                   # Windows
                "[Errno -2] Name or service not known" in exception_string or               # Linux
                "[Errno -3] Temporary failure in name resolution" in exception_string or    # Linux
                "[Errno 8] nodename nor servname " in exception_string):                    # OS X
                return '-6' # DNS Failure
            else:
                return '-2' # Other Connection Failure
        elif hasattr(recorded_url, 'exception') and isinstance(recorded_url.exception, (socket.timeout, TimeoutError, )):
            return '-2' # Connection Timeout
        elif isinstance(recorded_url, warcprox.warcproxy.FailedUrl):
            # synthetic status, used when some other status (such as connection-lost)
            # is considered by policy the same as a document-not-found
            # Cached failures result in FailedUrl with no Exception
            return '-404'
        else:
            return recorded_url.status

