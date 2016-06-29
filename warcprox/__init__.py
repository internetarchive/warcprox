"""
warcprox/__init__.py - warcprox package main file, contains some utility code

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
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.
"""

from argparse import Namespace as _Namespace
from pkg_resources import get_distribution as _get_distribution
__version__ = _get_distribution('warcprox').version

def digest_str(hash_obj, base32):
    import base64
    return hash_obj.name.encode('utf-8') + b':' + (
            base64.b32encode(hash_obj.digest()) if base32
            else hash_obj.hexdigest().encode('ascii'))

class Options(_Namespace):
    def __getattr__(self, name):
        try:
            return super(Options, self).__getattr__(self, name)
        except AttributeError:
            return None

# XXX linux-specific
def gettid():
    try:
        import ctypes
        libc = ctypes.cdll.LoadLibrary('libc.so.6')
        SYS_gettid = 186
        tid = libc.syscall(SYS_gettid)
        return tid
    except:
        return "n/a"

class RequestBlockedByRule(Exception):
    """
    An exception raised when a request should be blocked to respect a
    Warcprox-Meta rule.
    """
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return "%s: %s" % (self.__class__.__name__, self.msg)

class Url:
    '''
    Utility class
    '''
    def __init__(self, url):
        self.url = url
        self._surt = None
        self._host = None

    @property
    def surt(self):
        if not self._surt:
            import surt
            hurl = surt.handyurl.parse(self.url)
            surt.GoogleURLCanonicalizer.canonicalize(hurl)
            hurl.query = None
            hurl.hash = None
            self._surt = hurl.getURLString(surt=True, trailing_comma=True)
        return self._surt

    @property
    def host(self):
        if not self._host:
            import surt
            self._host = surt.handyurl.parse(self.url).host
        return self._host

    def matches_ip_or_domain(self, ip_or_domain):
        return host_matches_ip_or_domain(self.host, ip_or_domain)

def normalize_host(host):
    # normalize host (punycode and lowercase)
    return host.encode('idna').decode('ascii').lower()

def host_matches_ip_or_domain(host, ip_or_domain):
    '''
    Returns true if
     - ip_or_domain is an ip address and host is the same ip address
     - ip_or_domain is a domain and host is the same domain
     - ip_or_domain is a domain and host is a subdomain of it
    '''
    _host = normalize_host(host)
    _ip_or_domain = normalize_host(ip_or_domain)

    if _ip_or_domain == _host:
        return True

    # if either _ip_or_domain or host are ip addresses, and they're not
    # identical (previous check), not a match
    try:
        ipaddress.ip_address(_ip_or_domain)
        return False
    except:
        pass
    try:
        ipaddress.ip_address(_host)
        return False
    except:
        pass

    # if we get here, we're looking at two hostnames
    domain_parts = _ip_or_domain.split(".")
    host_parts = _host.split(".")

    result = host_parts[-len(domain_parts):] == domain_parts
    return result


# logging level more fine-grained than logging.DEBUG==10
TRACE = 5

import warcprox.controller as controller
import warcprox.playback as playback
import warcprox.dedup as dedup
import warcprox.warcproxy as warcproxy
import warcprox.mitmproxy as mitmproxy
import warcprox.writer as writer
import warcprox.warc as warc
import warcprox.writerthread as writerthread
import warcprox.stats as stats
import warcprox.bigtable as bigtable
import warcprox.kafkafeed as kafkafeed
