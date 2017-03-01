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

from doublethink.orm import Document
from doublethink.rethinker import Rethinker
from doublethink.services import ServiceRegistry

__all__ = ['Document', 'Rethinker', 'ServiceRegistry', 'UTC', 'utcnow']

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

