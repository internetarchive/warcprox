'''
warcprox/warcproxy.py - recording proxy, extends mitmproxy to record traffic,
enqueue info on the recorded url queue

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
try:
    import queue
except ImportError:
    import Queue as queue
import logging
import re
import traceback
import json
import socket
from hanzo import warctools
from certauth.certauth import CertificateAuthority
import warcprox
import datetime
import concurrent.futures
import resource
import ipaddress
import surt

class Url:
    def __init__(self, url):
        self.url = url
        self._surt = None
        self._host = None

    @property
    def surt(self):
        if not self._surt:
            hurl = surt.handyurl.parse(self.url)
            surt.GoogleURLCanonicalizer.canonicalize(hurl)
            hurl.query = None
            hurl.hash = None
            self._surt = hurl.getURLString(surt=True, trailing_comma=True)
        return self._surt

    @property
    def host(self):
        if not self._host:
            self._host = surt.handyurl.parse(self.url).host
        return self._host

    def matches_ip_or_domain(self, ip_or_domain):
        """Returns true if
           - ip_or_domain is an ip address and self.host is the same ip address
           - ip_or_domain is a domain and self.host is the same domain
           - ip_or_domain is a domain and self.host is a subdomain of it
        """
        if ip_or_domain == self.host:
            return True

        # if either ip_or_domain or self.host are ip addresses, and they're not
        # identical (previous check), not a match
        try:
            ipaddress.ip_address(ip_or_domain)
            return False
        except:
            pass
        try:
            ipaddress.ip_address(self.host)
            return False
        except:
            pass

        # if we get here, we're looking at two hostnames
        # XXX do we need to handle case of one punycoded idn, other not?
        domain_parts = ip_or_domain.split(".")
        host_parts = self.host.split(".")

        return host_parts[-len(domain_parts):] == domain_parts

class WarcProxyHandler(warcprox.mitmproxy.MitmProxyHandler):
    # self.server is WarcProxy
    logger = logging.getLogger("warcprox.warcprox.WarcProxyHandler")

    # XXX nearly identical to brozzler.site.Site._scope_rule_applies() but
    # there's no obvious common dependency where this code should go... TBD
    def _scope_rule_applies(self, rule):
        u = Url(self.url)

        if "host" in rule and not u.matches_ip_or_domain(rule["host"]):
            return False
        if "url_match" in rule:
            if rule["url_match"] == "STRING_MATCH":
                return u.url.find(rule["value"]) >= 0
            elif rule["url_match"] == "REGEX_MATCH":
                try:
                    return re.fullmatch(rule["value"], u.url)
                except Exception as e:
                    self.logger.warn(
                            "caught exception matching against regex %s: %s",
                            rule["value"], e)
                    return False
            elif rule["url_match"] == "SURT_MATCH":
                return u.surt.startswith(rule["value"])
            else:
                self.logger.warn("invalid rule.url_match=%s", rule.url_match)
                return False
        else:
            if "host" in rule:
                # we already know that it matches from earlier check
                return True
            else:
                self.logger.warn("unable to make sense of scope rule %s", rule)
                return False

    def _enforce_blocks(self, warcprox_meta):
        """
        Sends a 403 response and raises warcprox.RequestBlockedByRule if the
        url is blocked by a rule in warcprox_meta.
        """
        if warcprox_meta and "blocks" in warcprox_meta:
            for rule in warcprox_meta["blocks"]:
                if self._scope_rule_applies(rule):
                    body = ("request rejected by warcprox: blocked by "
                            "rule found in Warcprox-Meta header: %s"
                            % rule).encode("utf-8")
                    self.send_response(403, "Forbidden")
                    self.send_header("Content-Type", "text/plain;charset=utf-8")
                    self.send_header("Connection", "close")
                    self.send_header("Content-Length", len(body))
                    response_meta = {"blocked-by-rule":rule}
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

    def _enforce_limits(self, warcprox_meta):
        """
        Sends a 420 response and raises warcprox.RequestBlockedByRule if a
        limit specified in warcprox_meta is reached.
        """
        if warcprox_meta and "limits" in warcprox_meta:
            for item in warcprox_meta["limits"].items():
                key, limit = item
                bucket0, bucket1, bucket2 = key.rsplit(".", 2)
                value = self.server.stats_db.value(bucket0, bucket1, bucket2)
                self.logger.debug("warcprox_meta['limits']=%s stats['%s']=%s recorded_url_q.qsize()=%s",
                        warcprox_meta['limits'], key, value, self.server.recorded_url_q.qsize())
                if value and value >= limit:
                    body = "request rejected by warcprox: reached limit {}={}\n".format(key, limit).encode("utf-8")
                    self.send_response(420, "Reached limit")
                    self.send_header("Content-Type", "text/plain;charset=utf-8")
                    self.send_header("Connection", "close")
                    self.send_header("Content-Length", len(body))
                    response_meta = {"reached-limit":{key:limit}, "stats":{bucket0:self.server.stats_db.value(bucket0)}}
                    self.send_header("Warcprox-Meta", json.dumps(response_meta, separators=(",",":")))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(body)
                    self.connection.close()
                    raise warcprox.RequestBlockedByRule(
                            "%s 420 %s %s -- reached limit %s=%s" % (
                                self.client_address[0], self.command,
                                self.url, key, limit))

    def _connect_to_remote_server(self):
        '''
        Wraps MitmProxyHandler._connect_to_remote_server, first enforcing
        limits and block rules in the Warcprox-Meta request header, if any.
        Raises warcprox.RequestBlockedByRule if a rule has been enforced.
        Otherwise calls MitmProxyHandler._connect_to_remote_server, which
        initializes self._remote_server_sock.
        '''
        if 'Warcprox-Meta' in self.headers:
            warcprox_meta = json.loads(self.headers['Warcprox-Meta'])
            self._enforce_limits(warcprox_meta)
            self._enforce_blocks(warcprox_meta)
        return warcprox.mitmproxy.MitmProxyHandler._connect_to_remote_server(self)

    def _proxy_request(self):
        warcprox_meta = None
        raw_warcprox_meta = self.headers.get('Warcprox-Meta')
        self.logger.log(
                warcprox.TRACE, 'request for %s Warcprox-Meta header: %s',
                self.url, repr(raw_warcprox_meta))
        if raw_warcprox_meta:
            warcprox_meta = json.loads(raw_warcprox_meta)
            del self.headers['Warcprox-Meta']

        remote_ip = self._remote_server_sock.getpeername()[0]
        timestamp = datetime.datetime.utcnow()

        req, prox_rec_res = warcprox.mitmproxy.MitmProxyHandler._proxy_request(
                self)

        recorded_url = RecordedUrl(
                url=self.url, request_data=req,
                response_recorder=prox_rec_res.recorder, remote_ip=remote_ip,
                warcprox_meta=warcprox_meta, status=prox_rec_res.status,
                size=prox_rec_res.recorder.len,
                client_ip=self.client_address[0],
                content_type=prox_rec_res.getheader("Content-Type"),
                method=self.command, timestamp=timestamp, host=self.hostname,
                duration=datetime.datetime.utcnow()-timestamp)
        self.server.recorded_url_q.put(recorded_url)

        return recorded_url

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

            if ('Content-Length' in self.headers and 'Content-Type' in self.headers
                    and (warc_type or 'WARC-Type' in self.headers)):
                timestamp = datetime.datetime.utcnow()

                # stream this?
                request_data = self.rfile.read(int(self.headers['Content-Length']))

                warcprox_meta = None
                raw_warcprox_meta = self.headers.get('Warcprox-Meta')
                if raw_warcprox_meta:
                    warcprox_meta = json.loads(raw_warcprox_meta)

                rec_custom = RecordedUrl(url=self.url,
                                         request_data=request_data,
                                         response_recorder=None,
                                         remote_ip=b'',
                                         warcprox_meta=warcprox_meta,
                                         content_type=self.headers['Content-Type'],
                                         custom_type=warc_type or self.headers['WARC-Type'].encode('utf-8'),
                                         status=204, size=len(request_data),
                                         client_ip=self.client_address[0],
                                         method=self.command, timestamp=timestamp)

                self.server.recorded_url_q.put(rec_custom)
                self.send_response(204, 'OK')
            else:
                self.send_error(400, 'Bad request')

            self.end_headers()
        except:
            self.logger.error("uncaught exception in do_WARCPROX_WRITE_RECORD", exc_info=True)
            raise

    def log_message(self, fmt, *args):
        # logging better handled elsewhere?
        pass


class RecordedUrl:
    logger = logging.getLogger("warcprox.warcproxy.RecordedUrl")

    def __init__(self, url, request_data, response_recorder, remote_ip,
            warcprox_meta=None, content_type=None, custom_type=None,
            status=None, size=None, client_ip=None, method=None,
            timestamp=None, host=None, duration=None):
        # XXX should test what happens with non-ascii url (when does
        # url-encoding happen?)
        if type(url) is not bytes:
            self.url = url.encode('ascii')
        else:
            self.url = url

        if type(remote_ip) is not bytes:
            self.remote_ip = remote_ip.encode('ascii')
        else:
            self.remote_ip = remote_ip

        self.request_data = request_data
        self.response_recorder = response_recorder

        if warcprox_meta:
            self.warcprox_meta = warcprox_meta
        else:
            self.warcprox_meta = {}

        self.content_type = content_type

        self.mimetype = content_type
        if self.mimetype:
            n = self.mimetype.find(";")
            if n >= 0:
                self.mimetype = self.mimetype[:n]

        self.custom_type = custom_type
        self.status = status
        self.size = size
        self.client_ip = client_ip
        self.method = method
        self.timestamp = timestamp
        self.host = host
        self.duration = duration


class SingleThreadedWarcProxy(http_server.HTTPServer):
    logger = logging.getLogger("warcprox.warcproxy.WarcProxy")

    def __init__(self, ca=None, recorded_url_q=None, stats_db=None, options=warcprox.Options()):
        server_address = (options.address or 'localhost', options.port if options.port is not None else 8000)

        if options.onion_tor_socks_proxy:
            try:
                host, port = options.onion_tor_socks_proxy.split(':')
                WarcProxyHandler.onion_tor_socks_proxy_host = host
                WarcProxyHandler.onion_tor_socks_proxy_port = int(port)
            except ValueError:
                WarcProxyHandler.onion_tor_socks_proxy_host = options.onion_tor_socks_proxy
                WarcProxyHandler.onion_tor_socks_proxy_port = None

        http_server.HTTPServer.__init__(self, server_address, WarcProxyHandler, bind_and_activate=True)

        self.digest_algorithm = options.digest_algorithm or 'sha1'

        if ca is not None:
            self.ca = ca
        else:
            ca_name = 'Warcprox CA on {}'.format(socket.gethostname())[:64]
            self.ca = CertificateAuthority(ca_file='warcprox-ca.pem',
                                           certs_dir='./warcprox-ca',
                                           ca_name=ca_name)

        if recorded_url_q is not None:
            self.recorded_url_q = recorded_url_q
        else:
            self.recorded_url_q = queue.Queue(maxsize=options.queue_size or 1000)

        self.stats_db = stats_db

        self.options = options

    def server_activate(self):
        http_server.HTTPServer.server_activate(self)
        self.logger.info('WarcProxy listening on {0}:{1}'.format(self.server_address[0], self.server_address[1]))

    def server_close(self):
        self.logger.info('WarcProxy shutting down')
        http_server.HTTPServer.server_close(self)

    def handle_error(self, request, client_address):
        self.logger.warn("exception processing request %s from %s", request, client_address, exc_info=True)

class PooledMixIn(socketserver.ThreadingMixIn):
    def process_request(self, request, client_address):
        self.pool.submit(self.process_request_thread, request, client_address)

class WarcProxy(PooledMixIn, SingleThreadedWarcProxy):
    logger = logging.getLogger("warcprox.warcproxy.WarcProxy")

    def __init__(self, *args, **kwargs):
        SingleThreadedWarcProxy.__init__(self, *args, **kwargs)
        if self.options.max_threads:
            max_threads = self.options.max_threads
            self.logger.info("max_threads=%s set by command line option",
                             max_threads)
        else:
            # man getrlimit: "RLIMIT_NPROC The maximum number of processes (or,
            # more precisely on Linux, threads) that can be created for the
            # real user ID of the calling process."
            rlimit_nproc = resource.getrlimit(resource.RLIMIT_NPROC)[0]
            rlimit_nofile = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            max_threads = min(rlimit_nofile // 10, rlimit_nproc // 2)
            self.logger.info("max_threads=%s (rlimit_nproc=%s, rlimit_nofile=%s)",
                             max_threads, rlimit_nproc, rlimit_nofile)

        self.pool = concurrent.futures.ThreadPoolExecutor(max_threads)
