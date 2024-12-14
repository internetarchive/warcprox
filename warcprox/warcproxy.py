'''
warcprox/warcproxy.py - recording proxy, extends mitmproxy to record traffic,
enqueue info on the recorded url queue

Copyright (C) 2013-2022 Internet Archive

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
import queue
import logging
import json
import socket
from hanzo import warctools
import warcprox
import urlcanon
import os
import tempfile
import hashlib
import doublethink
import re
import zlib
import base64

class WarcProxyHandler(warcprox.mitmproxy.MitmProxyHandler):
    '''
    XXX add more information.

    Among other things, this class enforces limits specified in the
    Warcprox-Meta request header. If a limit is deemed to have been reached, no
    request will be made to the remote destination server. This implementation
    detail has implications worth noting. For example, if a limit applies to
    "new" (not deduplicated) bytes, and the limit has already been reached, no
    request will be made, even if it would have resulted in duplicate content,
    which would not count toward the limit. To reiterate, this is because the
    limit enforcer does not know that the content would be deduplicated.
    '''
    # self.server is WarcProxy
    logger = logging.getLogger("warcprox.warcprox.WarcProxyHandler")

    def _enforce_blocks(self, warcprox_meta):
        """
        Sends a 403 response and raises warcprox.RequestBlockedByRule if the
        url is blocked by a rule in warcprox_meta.
        """
        url = urlcanon.semantic(self.url)
        if warcprox_meta and "blocks" in warcprox_meta:
            for rule in warcprox_meta["blocks"]:
                block_rule = urlcanon.MatchRule(**rule)
                if block_rule.applies(url):
                    body = ("request rejected by warcprox: blocked by "
                            "rule found in Warcprox-Meta header: %s\n"
                            % json.dumps(rule)).encode("utf-8")
                    self.send_response(403, "Forbidden")
                    self.send_header("Content-Type", "text/plain;charset=utf-8")
                    self.send_header("Connection", "close")
                    self.send_header("Content-Length", len(body))
                    response_meta = {"blocked-by-rule": rule}
                    self.send_header(
                            "Warcprox-Meta",
                            json.dumps(response_meta, separators=(",",":")))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(body)
                    self.connection.close()
                    raise warcprox.RequestBlockedByRule(
                            "%s 403 %s %s -- blocked by rule in Warcprox-Meta "
                            "request header %s" % (
                                self.client_address[0], self.command,
                                self.url, rule))

    def _enforce_limit(self, buckets, limit_key, limit_value, soft=False):
        if not self.server.stats_db:
            return

        # parse limit key
        bucket0, bucket1, bucket2 = limit_key.rsplit("/", 2)
        # normalize domain if part of bucket
        if ":" in bucket0:
            b, raw_domain = bucket0.split(":", 1)
            domain = urlcanon.normalize_host(raw_domain).decode("ascii")
            bucket0 = "{}:{}".format(b, domain)
            limit_key = "{}/{}/{}".format(bucket0, bucket1, bucket2)

        if not bucket0 in buckets:
            return

        value = self.server.stats_db.value(bucket0, bucket1, bucket2)
        if value and limit_value and limit_value > 0 and value >= limit_value:
            body = ("request rejected by warcprox: reached {} {}={}\n".format(
                        "soft limit" if soft else "limit", limit_key,
                        limit_value)).encode("utf-8")
            if soft:
                self.send_response(430, "Reached soft limit")
            else:
                self.send_response(420, "Reached limit")
            self.send_header("Content-Type", "text/plain;charset=utf-8")
            self.send_header("Connection", "close")
            self.send_header("Content-Length", len(body))
            response_meta = {
                "stats": {bucket0:self.server.stats_db.value(bucket0)}
            }
            if soft:
                response_meta["reached-soft-limit"] = {limit_key:limit_value}
            else:
                response_meta["reached-limit"] = {limit_key:limit_value}
            self.send_header(
                    "Warcprox-Meta", json.dumps(response_meta, separators=",:"))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            self.connection.close()
            raise warcprox.RequestBlockedByRule(
                    "{} {} {} {} -- reached {} {}={}".format(
                        self.client_address[0], 430 if soft else 420,
                        self.command, self.url,
                        "soft limit" if soft else "limit",
                        limit_key, limit_value))

    def _enforce_limits(self, warcprox_meta):
        """
        Sends a 420 (hard limit) or 430 (soft limit) response and raises
        warcprox.RequestBlockedByRule if a limit specified in warcprox_meta is
        reached.
        """
        buckets = warcprox.stats.unravel_buckets(self.url, warcprox_meta)
        if warcprox_meta and "limits" in warcprox_meta:
            for item in warcprox_meta["limits"].items():
                limit_key, limit_value = item
                self._enforce_limit(buckets, limit_key, limit_value, soft=False)
        if warcprox_meta and "soft-limits" in warcprox_meta:
            for item in warcprox_meta["soft-limits"].items():
                limit_key, limit_value = item
                self._enforce_limit(buckets, limit_key, limit_value, soft=True)

    def _security_check(self, warcprox_meta):
        '''
        Sends a 400 if `warcprox_meta` specifies a 'warc-prefix' and the
        'warc-prefix' contains a slash or backslash.
        '''
        if warcprox_meta and 'warc-prefix' in warcprox_meta and (
                '/' in warcprox_meta['warc-prefix']
                or '\\' in warcprox_meta['warc-prefix']):
            raise warcprox.BadRequest(
                "request rejected by warcprox: slash and backslash are not "
                "permitted in warc-prefix")

    def _enforce_limits_and_blocks(self):
        if 'Warcprox-Meta' in self.headers:
            warcprox_meta = json.loads(self.headers['Warcprox-Meta'])
            self._security_check(warcprox_meta)
            self._enforce_limits(warcprox_meta)
            if 'compressed_blocks' in warcprox_meta:
                # b64decode and decompress
                blocks_decompressed = zlib.decompress(base64.b64decode(warcprox_meta['compressed_blocks']))
                # decode() and json.loads
                warcprox_meta['blocks'] = json.loads(blocks_decompressed.decode())
                # delete compressed_blocks (just in case?)
                del warcprox_meta['compressed_blocks']
            self._enforce_blocks(warcprox_meta)

    def _connect_to_remote_server(self):
        '''
        Wraps `MitmProxyHandler._connect_to_remote_server`, first enforcing
        limits and block rules in the Warcprox-Meta request header, if any.
        Raises `warcprox.RequestBlockedByRule` if a rule has been enforced.
        Otherwise calls `MitmProxyHandler._connect_to_remote_server`, which
        initializes `self._remote_server_conn`.
        '''
        self._enforce_limits_and_blocks()
        return warcprox.mitmproxy.MitmProxyHandler._connect_to_remote_server(self)

    def _parse_warcprox_meta(self):
        '''
        :return: Warcprox-Meta request header value as a dictionary, or None
        '''
        raw_warcprox_meta = self.headers.get('Warcprox-Meta')
        self.logger.trace(
            'request for %s Warcprox-Meta header: %s', self.url,
            raw_warcprox_meta)
        if raw_warcprox_meta:
            return json.loads(raw_warcprox_meta)
        else:
            return None

    def _proxy_request(self):
        warcprox_meta = self._parse_warcprox_meta()
        remote_ip = self._remote_server_conn.sock.getpeername()[0]
        timestamp = doublethink.utcnow()
        extra_response_headers = {}
        if warcprox_meta and 'accept' in warcprox_meta and \
                'capture-metadata' in warcprox_meta['accept']:
            rmeta = {'capture-metadata': {'timestamp': timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')}}
            extra_response_headers['Warcprox-Meta'] = json.dumps(rmeta, separators=',:')

        req, prox_rec_res = warcprox.mitmproxy.MitmProxyHandler._proxy_request(
                self, extra_response_headers=extra_response_headers)

        content_type = None
        try:
            content_type = prox_rec_res.headers.get('content-type')
        except AttributeError: # py2
            raw = prox_rec_res.msg.getrawheader('content-type')
            if raw:
                content_type = raw.strip()

        recorded_url = RecordedUrl(
                url=self.url, request_data=req,
                response_recorder=prox_rec_res.recorder, remote_ip=remote_ip,
                warcprox_meta=warcprox_meta, status=prox_rec_res.status,
                size=prox_rec_res.recorder.len,
                client_ip=self.client_address[0],
                content_type=content_type, method=self.command,
                timestamp=timestamp, host=self.hostname,
                duration=doublethink.utcnow()-timestamp,
                referer=self.headers.get('referer'),
                payload_digest=prox_rec_res.payload_digest,
                truncated=prox_rec_res.truncated)
        self.server.recorded_url_q.put(recorded_url)

        return recorded_url

    def do_GET(self):
        if self.path == '/status' and self.command == 'GET':
            status_info = {
                'role': 'warcprox',
                'version': warcprox.__version__,
                'host': socket.gethostname(),
                'address': self.connection.getsockname()[0],
                'port': self.connection.getsockname()[1],
                'pid': os.getpid(),
            }
            status_info.update(self.server.status())
            payload = json.dumps(
                    status_info, cls=warcprox.Jsonner,
                    indent=2).encode('utf-8') + b'\n'
            self.send_response(200, 'OK')
            self.send_header('Content-type', 'application/json')
            self.send_header('Content-Length', len(payload))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.do_COMMAND()

    # deprecated
    def do_PUTMETA(self):
        '''
        Handles a special warcprox PUTMETA request (deprecated). A PUTMETA
        request is equivalent to a WARCPROX_WRITE_RECORD request with
        WARC-Type: metadata.
        '''
        self.do_WARCPROX_WRITE_RECORD(warc_type=warctools.WarcRecord.METADATA)

    def do_WARCPROX_WRITE_RECORD(self, warc_type=None):
        '''
        Handles a request with http method WARCPROX_WRITE_RECORD, a special
        type of request which tells warcprox to construct a warc record from
        the request more or less verbatim, and write it to a warc.

        To honor the request, this method creates a RecordedUrl queues it for
        the WarcWriterThread to process. The warc record headers Content-Type
        and WARC-Type are taken from the request headers, as is the payload.

        Example request:

        WARCPROX_WRITE_RECORD screenshot:https://example.com/ HTTP/1.1
        WARC-Type: metadata
        Content-Type: image/png
        Content-Length: 12345
        Connection: close

        <png image data>
        '''
        try:
            self.url = self.path
            self._enforce_limits_and_blocks()

            if ('Content-Length' in self.headers and 'Content-Type' in self.headers
                    and (warc_type or 'WARC-Type' in self.headers)):
                timestamp = doublethink.utcnow()

                request_data = tempfile.SpooledTemporaryFile(
                        max_size=self._tmp_file_max_memory_size)
                payload_digest = hashlib.new(self.server.digest_algorithm)

                # XXX we don't support chunked uploads for now
                length = int(self.headers['Content-Length'])
                buf = self.rfile.read(min(65536, length - request_data.tell()))
                while buf != b'':
                    request_data.write(buf)
                    payload_digest.update(buf)
                    buf = self.rfile.read(
                            min(65536, length - request_data.tell()))

                warcprox_meta = None
                raw_warcprox_meta = self.headers.get('Warcprox-Meta')
                if raw_warcprox_meta:
                    warcprox_meta = json.loads(raw_warcprox_meta)

                rec_custom = RecordedUrl(
                        url=self.url,
                        request_data=request_data,
                        response_recorder=None,
                        remote_ip=b'',
                        warcprox_meta=warcprox_meta,
                        content_type=self.headers['Content-Type'],
                        custom_type=warc_type or self.headers['WARC-Type'].encode('utf-8'),
                        status=204,
                        size=request_data.tell(),
                        client_ip=self.client_address[0],
                        method=self.command,
                        timestamp=timestamp,
                        duration=doublethink.utcnow()-timestamp,
                        payload_digest=payload_digest)
                request_data.seek(0)

                self.server.recorded_url_q.put(rec_custom)
                self.send_response(204, 'OK')
            else:
                self.send_error(400, message='Bad request', explain=(
                    'Bad request. WARC-Type, Content-Length, and Content-Type '
                    'request headers required for WARCPROX_WRITE_RECORD '
                    'request.'))

            self.end_headers()
        except warcprox.RequestBlockedByRule as e:
            # limit enforcers have already sent the appropriate response
            self.logger.info("%r: %r", self.requestline, e)
            return
        except:
            self.logger.error("uncaught exception in do_WARCPROX_WRITE_RECORD", exc_info=True)
            raise

    def send_error(self, code, message=None, explain=None, exception=None):
        super().send_error(code, message=message, explain=explain, exception=exception)

        # If error happens during CONNECT handling and before the inner request, self.url
        # is unset, and self.path is something like 'example.com:443'
        urlish = self.url or self.path

        warcprox_meta = self._parse_warcprox_meta()
        self._swallow_hop_by_hop_headers()
        request_data = self._build_request()

        failed_url = FailedUrl(
                url=urlish,
                request_data=request_data,
                warcprox_meta=warcprox_meta,
                status=code,
                client_ip=self.client_address[0],
                method=self.command,
                timestamp=doublethink.utcnow(),
                host=self.hostname,
                duration=None,
                referer=self.headers.get('referer'),
                do_not_archive=True,
                message=message,
                exception=exception)

        self.server.recorded_url_q.put(failed_url)

    def log_message(self, fmt, *args):
        # logging better handled elsewhere?
        pass

RE_MIMETYPE = re.compile(r'[;\s]')

class RequestedUrl:
    logger = logging.getLogger("warcprox.warcproxy.RequestedUrl")
    def __init__(self, url, request_data, response_recorder=None, remote_ip=None,
            warcprox_meta=None, content_type=None, custom_type=None,
            status=None, size=None, client_ip=None, method=None,
            timestamp=None, host=None, duration=None, referer=None,
            payload_digest=None, truncated=None, warc_records=None,
            do_not_archive=False):
        # XXX should test what happens with non-ascii url (when does
        # url-encoding happen?)
        if type(url) is not bytes:
            self.url = url.encode('ascii')
        else:
            self.url = url

        self.request_data = request_data
        self.response_recorder = response_recorder

        if warcprox_meta:
            if 'captures-bucket' in warcprox_meta:
                # backward compatibility
                warcprox_meta['dedup-buckets'] = {}
                warcprox_meta['dedup-buckets'][warcprox_meta['captures-bucket']] = 'rw'
                del warcprox_meta['captures-bucket']
            if 'dedup-bucket' in warcprox_meta:
                # more backwards compatibility
                warcprox_meta['dedup-buckets'] = {}
                warcprox_meta['dedup-buckets'][warcprox_meta['dedup-bucket']] = 'rw'
                del warcprox_meta['dedup-bucket']
            self.warcprox_meta = warcprox_meta
        else:
            self.warcprox_meta = {}

        self.content_type = content_type

        self.mimetype = content_type
        if self.mimetype:
            # chop off subtype, and ensure there's no whitespace
            self.mimetype = RE_MIMETYPE.split(self.mimetype, 2)[0]

        self.custom_type = custom_type
        self.status = status
        self.size = size
        self.client_ip = client_ip
        self.method = method
        self.timestamp = timestamp
        self.host = host
        self.duration = duration
        self.referer = referer
        self.payload_digest = payload_digest
        self.truncated = truncated
        self.warc_records = warc_records
        self.do_not_archive = do_not_archive

class FailedUrl(RequestedUrl):
    logger = logging.getLogger("warcprox.warcproxy.FailedUrl")

    def __init__(self, url, request_data, warcprox_meta=None, status=None,
            client_ip=None, method=None, timestamp=None, host=None, duration=None,
            referer=None, do_not_archive=True, message=None, exception=None):

        super().__init__(url, request_data, warcprox_meta=warcprox_meta,
                status=status, client_ip=client_ip, method=method,
                timestamp=timestamp, host=host, duration=duration,
                referer=referer, do_not_archive=do_not_archive)

        self.message = message
        self.exception = exception

class RecordedUrl(RequestedUrl):
    logger = logging.getLogger("warcprox.warcproxy.RecordedUrl")

    def __init__(self, url, request_data, response_recorder, remote_ip,
            warcprox_meta=None, content_type=None, custom_type=None,
            status=None, size=None, client_ip=None, method=None,
            timestamp=None, host=None, duration=None, referer=None,
            payload_digest=None, truncated=None, warc_records=None,
            do_not_archive=False):

        super().__init__(url, request_data, response_recorder=response_recorder,
        warcprox_meta=warcprox_meta, content_type=content_type,
        custom_type=custom_type, status=status, size=size, client_ip=client_ip,
        method=method, timestamp=timestamp, host=host, duration=duration,
        referer=referer, payload_digest=payload_digest, truncated=truncated,
        warc_records=warc_records, do_not_archive=do_not_archive)

        if type(remote_ip) is not bytes:
            self.remote_ip = remote_ip.encode('ascii')
        else:
            self.remote_ip = remote_ip

    def is_text(self):
        """Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Complete_list_of_MIME_types
        Alternative method: try to decode('ascii') first N bytes to make sure
        its text.
        """
        if self.mimetype:
            return self.mimetype[:5] == "text/" or self.mimetype in (
                "application/xml", "application/javascript", "application/json",
                "application/xhtml+xml", "application/typescript",
                "image/svg+xml")
        return False

# inherit from object so that multiple inheritance from this class works
# properly in python 2
# http://stackoverflow.com/questions/1713038/super-fails-with-error-typeerror-argument-1-must-be-type-not-classobj#18392639
class SingleThreadedWarcProxy(warcprox.mitmproxy.SingleThreadedMitmProxy):
    logger = logging.getLogger("warcprox.warcproxy.WarcProxy")

    def __init__(
            self, stats_db=None, status_callback=None,
            options=warcprox.Options()):
        self.start_time = doublethink.utcnow()

        warcprox.mitmproxy.SingleThreadedMitmProxy.__init__(
                self, WarcProxyHandler, options)

        self.status_callback = status_callback
        self.stats_db = stats_db
        self.recorded_url_q = queue.Queue(maxsize=options.queue_size or 1000)
        self.running_stats = warcprox.stats.RunningStats()

    def status(self):
        if hasattr(super(), 'status'):
            result = super().status()
        else:
            result = {}
        result.update({
            'load': 1.0 * self.recorded_url_q.qsize() / (
                self.recorded_url_q.maxsize or 100),
            'queued_urls': self.recorded_url_q.qsize(),
            'queue_max_size': self.recorded_url_q.maxsize,
            'urls_processed': self.running_stats.urls,
            'warc_bytes_written': self.running_stats.warc_bytes,
            'start_time': self.start_time,
        })
        elapsed, urls_per_sec, warc_bytes_per_sec = self.running_stats.current_rates(1)
        result['rates_1min'] = {
            'actual_elapsed': elapsed,
            'urls_per_sec': urls_per_sec,
            'warc_bytes_per_sec': warc_bytes_per_sec,
        }
        elapsed, urls_per_sec, warc_bytes_per_sec = self.running_stats.current_rates(5)
        result['rates_5min'] = {
            'actual_elapsed': elapsed,
            'urls_per_sec': urls_per_sec,
            'warc_bytes_per_sec': warc_bytes_per_sec,
        }
        elapsed, urls_per_sec, warc_bytes_per_sec = self.running_stats.current_rates(15)
        result['rates_15min'] = {
            'actual_elapsed': elapsed,
            'urls_per_sec': urls_per_sec,
            'warc_bytes_per_sec': warc_bytes_per_sec,
        }
        # gets postfetch chain status from the controller
        if self.status_callback:
            result.update(self.status_callback())
        return result

class WarcProxy(SingleThreadedWarcProxy, warcprox.mitmproxy.PooledMitmProxy):
    logger = logging.getLogger("warcprox.warcproxy.WarcProxy")

    def __init__(
            self, stats_db=None, status_callback=None,
            options=warcprox.Options()):
        warcprox.mitmproxy.PooledMitmProxy.__init__(self, options)
        SingleThreadedWarcProxy.__init__(
                self, stats_db, status_callback, options)

    def server_activate(self):
        http_server.HTTPServer.server_activate(self)
        self.logger.notice(
                'listening on %s:%s', self.server_address[0],
                self.server_address[1])
        # take note of actual port in case running with --port=0 so that other
        # parts of warcprox have easy access to it
        self.options.server_port = self.server_address[1]

    def server_close(self):
        self.logger.notice('shutting down')
        http_server.HTTPServer.server_close(self)
        warcprox.mitmproxy.PooledMitmProxy.server_close(self)
        self.remote_connection_pool.clear()

    def handle_error(self, request, client_address):
        self.logger.warning(
                "exception processing request %s from %s", request,
                client_address, exc_info=True)
