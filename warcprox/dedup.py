# vim:set sw=4 et:

from __future__ import absolute_import

try:
    import dbm.gnu as dbm_gnu
except ImportError:
    try:
        import gdbm as dbm_gnu
    except ImportError:
        import anydbm as dbm_gnu

import logging
import os
import json
from hanzo import warctools

class DedupDb(object):
    logger = logging.getLogger("warcprox.dedup.DedupDb")

    def __init__(self, dbm_file='./warcprox-dedup.db'):
        if os.path.exists(dbm_file):
            self.logger.info('opening existing deduplication database {}'.format(dbm_file))
        else:
            self.logger.info('creating new deduplication database {}'.format(dbm_file))

        self.db = dbm_gnu.open(dbm_file, 'c')

    def close(self):
        self.db.close()

    def sync(self):
        try:
            self.db.sync()
        except:
            pass

    def save(self, key, response_record, offset):
        record_id = response_record.get_header(warctools.WarcRecord.ID).decode('latin1')
        url = response_record.get_header(warctools.WarcRecord.URL).decode('latin1')
        date = response_record.get_header(warctools.WarcRecord.DATE).decode('latin1')

        py_value = {'i':record_id, 'u':url, 'd':date}
        json_value = json.dumps(py_value, separators=(',',':'))

        self.db[key] = json_value.encode('utf-8')
        self.logger.debug('dedup db saved {}:{}'.format(key, json_value))

    def lookup(self, key):
        if key in self.db:
            json_result = self.db[key]
            result = json.loads(json_result.decode('utf-8'))
            result['i'] = result['i'].encode('latin1')
            result['u'] = result['u'].encode('latin1')
            result['d'] = result['d'].encode('latin1')
            return result
        else:
            return None


