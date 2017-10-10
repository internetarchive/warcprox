'''
doublethink/__init__.py - rethinkdb connection-manager-ish thing and service
registry thing

Copyright (C) 2015-2017 Internet Archive

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import rethinkdb
import datetime
try:
    import urllib.parse as urllib_parse
except:
    import urlparse as urllib_parse
import collections

from doublethink.orm import Document
from doublethink.rethinker import Rethinker
from doublethink.services import ServiceRegistry

__all__ = [
    'Document', 'Rethinker', 'ServiceRegistry', 'UTC', 'utcnow',
    'parse_rethinkdb_url', 'ParsedRethinkDbUrl']

try:
    UTC = datetime.timezone.utc
except:
    UTC = rethinkdb.make_timezone("00:00")

def utcnow():
    """Convenience function to get timezone-aware UTC datetime. RethinkDB
    requires timezone-aware datetime for its native time type, and
    unfortunately datetime.datetime.utcnow() is not timezone-aware. Also python
    2 doesn't come with a timezone implementation."""
    return datetime.datetime.now(UTC)

ParsedRethinkDbUrl = collections.namedtuple(
        'ParsedRethinkDbUrl', ['hosts', 'database', 'table'])

def parse_rethinkdb_url(s):
    '''
    Parses a url like this rethinkdb://server1:port,server2:port/database/table

    Returns:
        tuple `(['server1:port', 'server2:port'], database, table)`
        `table` and `database` may be None

    Raises:
        ValueError if url cannot be parsed as a rethinkdb url

    There is some precedent for this kind of url (though only with a single
    host):
    - https://gist.github.com/lucidfrontier45/e5881a8fca25e51ab21c3cf4b4179daa
    - https://github.com/laggyluke/node-parse-rethinkdb-url
    '''
    result = ParsedRethinkDbUrl(None, None, None)
    parsed = urllib_parse.urlparse(s)
    if parsed.scheme != 'rethinkdb':
        raise ValueError
    hosts = parsed.netloc.split(',')

    database = None
    table = None
    path_segments = parsed.path.split('/')[1:]
    if len(path_segments) >= 3:
        raise ValueError
    if len(path_segments) >= 1:
        database = path_segments[0]
        if len(path_segments) == 2:
            table = path_segments[1]

    if '' in hosts or database == '' or table == '':
        raise ValueError

    if any('@' in host for host in hosts):
        raise ValueError

    return ParsedRethinkDbUrl(hosts, database, table)

