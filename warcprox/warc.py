'''
warcprox/warc.py - assembles warc records

Copyright (C) 2013-2018 Internet Archive

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
import warcprox
import hashlib
import socket
import hanzo.httptools
from hanzo import warctools
import datetime

class WarcRecordBuilder:
    logger = logging.getLogger("warcprox.warc.WarcRecordBuilder")

    def __init__(self, digest_algorithm="sha1", base32=False):
        self.digest_algorithm = digest_algorithm
        self.base32 = base32

    def format_warc_date(self, dt):
        return dt.strftime('%Y-%m-%dT%H:%M:%SZ').encode('ascii')

    def _build_response_principal_record(self, recorded_url, warc_date):
        """Builds response or revisit record, whichever is appropriate."""
        if hasattr(recorded_url, "dedup_info") and recorded_url.dedup_info:
            # revisit record
            recorded_url.response_recorder.tempfile.seek(0)
            if recorded_url.response_recorder.payload_offset is not None:
                response_header_block = recorded_url.response_recorder.tempfile.read(recorded_url.response_recorder.payload_offset)
            else:
                response_header_block = recorded_url.response_recorder.tempfile.read()

            return self.build_warc_record(
                    url=recorded_url.url, warc_date=warc_date,
                    data=response_header_block,
                    warc_type=warctools.WarcRecord.REVISIT,
                    refers_to=recorded_url.dedup_info.get('id'),
                    refers_to_target_uri=recorded_url.dedup_info['url'],
                    refers_to_date=recorded_url.dedup_info['date'],
                    payload_digest=warcprox.digest_str(
                        recorded_url.payload_digest, self.base32),
                    profile=warctools.WarcRecord.PROFILE_IDENTICAL_PAYLOAD_DIGEST,
                    content_type=hanzo.httptools.ResponseMessage.CONTENT_TYPE,
                    remote_ip=recorded_url.remote_ip)
        else:
            # response record
            return self.build_warc_record(
                    url=recorded_url.url, warc_date=warc_date,
                    recorder=recorded_url.response_recorder,
                    warc_type=warctools.WarcRecord.RESPONSE,
                    content_type=hanzo.httptools.ResponseMessage.CONTENT_TYPE,
                    remote_ip=recorded_url.remote_ip,
                    payload_digest=warcprox.digest_str(
                        recorded_url.payload_digest, self.base32),
                    truncated=recorded_url.truncated)

    def build_warc_records(self, recorded_url):
        """Returns a tuple of hanzo.warctools.warc.WarcRecord (principal_record, ...)"""
        warc_date = self.format_warc_date(recorded_url.timestamp)

        if recorded_url.response_recorder:
            principal_record = self._build_response_principal_record(recorded_url, warc_date)
            request_record = self.build_warc_record(url=recorded_url.url,
                    warc_date=warc_date, data=recorded_url.request_data,
                    warc_type=warctools.WarcRecord.REQUEST,
                    content_type=hanzo.httptools.RequestMessage.CONTENT_TYPE,
                    concurrent_to=principal_record.id)
            return principal_record, request_record
        else:
            principal_record = self.build_warc_record(
                    url=recorded_url.url,
                    warc_date=warc_date, data=recorded_url.request_data,
                    warc_type=recorded_url.custom_type,
                    content_type=recorded_url.content_type.encode("latin1"),
                    payload_digest=warcprox.digest_str(
                        recorded_url.payload_digest, self.base32),
                    content_length=recorded_url.size)
            return (principal_record,)

    def build_warc_record(self, url, warc_date=None, recorder=None, data=None,
        concurrent_to=None, warc_type=None, content_type=None, remote_ip=None,
        profile=None, refers_to=None, refers_to_target_uri=None,
        refers_to_date=None, payload_digest=None, truncated=None,
        content_length=None):

        if warc_date is None:
            warc_date = self.format_warc_date(datetime.datetime.utcnow())

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
        # truncated value may be 'length' or 'time'
        if truncated is not None:
            headers.append((b'WARC-Truncated', truncated))
        if content_length is not None:
            headers.append((
                warctools.WarcRecord.CONTENT_LENGTH,
                str(content_length).encode('latin1')))

        if recorder is not None:
            if payload_digest is not None:
                headers.append(
                        (warctools.WarcRecord.PAYLOAD_DIGEST, payload_digest))
            if content_length is None:
                headers.append((
                    warctools.WarcRecord.CONTENT_LENGTH,
                    str(len(recorder)).encode('latin1')))
            headers.append((warctools.WarcRecord.BLOCK_DIGEST,
                warcprox.digest_str(recorder.block_digest, self.base32)))
            recorder.tempfile.seek(0)
            record = warctools.WarcRecord(
                    headers=headers, content_file=recorder.tempfile)
        else:
            if content_length is None:
                headers.append((
                    warctools.WarcRecord.CONTENT_LENGTH,
                    str(len(data)).encode('latin1')))

            block_digest = None
            if not hasattr(data, 'read'):
                block_digest = warcprox.digest_str(
                        hashlib.new(self.digest_algorithm, data), self.base32)

            if not content_type.lower().startswith(b'application/http'):
                # no http headers, so block digest == payload digest
                if payload_digest and not block_digest:
                    block_digest = payload_digest
                elif block_digest and not payload_digest:
                    payload_digest = block_digest

            if block_digest:
                headers.append(
                        (warctools.WarcRecord.BLOCK_DIGEST, block_digest))
            if payload_digest:
                headers.append(
                        (warctools.WarcRecord.PAYLOAD_DIGEST, payload_digest))

            if hasattr(data, 'read'):
                record = warctools.WarcRecord(
                        headers=headers, content_file=data)
            else:
                content_tuple = content_type, data
                record = warctools.WarcRecord(
                        headers=headers, content=(content_type, data))

        return record

    def _local_address(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1)) # ip doesn't need to be reachable
        output = s.getsockname()[0]
        s.close()
        return output

    def build_warcinfo_record(self, filename):
        warc_record_date = self.format_warc_date(datetime.datetime.utcnow())
        record_id = warctools.WarcRecord.random_warc_uuid()

        headers = []
        headers.append((warctools.WarcRecord.ID, record_id))
        headers.append((warctools.WarcRecord.TYPE, warctools.WarcRecord.WARCINFO))
        headers.append((warctools.WarcRecord.FILENAME, filename.encode('latin1')))
        headers.append((warctools.WarcRecord.DATE, warc_record_date))

        warcinfo_fields = []
        warcinfo_fields.append(b'software: warcprox ' + warcprox.__version__.encode('latin1'))
        hostname = socket.gethostname()
        warcinfo_fields.append('hostname: {}'.format(hostname).encode('latin1'))
        warcinfo_fields.append(('ip: %s' % self._local_address()).encode('latin1'))
        warcinfo_fields.append(b'format: WARC File Format 1.0')
        # warcinfo_fields.append('robots: ignore')
        # warcinfo_fields.append('description: {0}'.format(self.description))
        # warcinfo_fields.append('isPartOf: {0}'.format(self.is_part_of))
        data = b'\r\n'.join(warcinfo_fields) + b'\r\n'

        record = warctools.WarcRecord(headers=headers, content=(b'application/warc-fields', data))

        return record

