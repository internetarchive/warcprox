from argparse import Namespace as _Namespace

def digest_str(hash_obj, base32):
    import base64
    return hash_obj.name.encode('utf-8') + b':' + (base64.b32encode(hash_obj.digest()) if base32 else hash_obj.hexdigest().encode('ascii'))

def _read_version_bytes():
    import os
    version_txt = os.path.sep.join(__file__.split(os.path.sep)[:-1] + ['version.txt'])
    with open(version_txt, 'rb') as fin:
        return fin.read().strip()

class Options(_Namespace):
    def __getattr__(self, name):
        try:
            return super(Options, self).__getattr__(self, name)
        except AttributeError:
            return None

class Rethinker:
    import logging
    logger = logging.getLogger("warcprox.Rethinker")

    def __init__(self, servers=["localhost"], db=None):
        self.servers = servers
        self.db = db

    # https://github.com/rethinkdb/rethinkdb-example-webpy-blog/blob/master/model.py
    # "Best practices: Managing connections: a connection per request"
    def _random_server_connection(self):
        import rethinkdb as r
        import random
        while True:
            server = random.choice(self.servers)
            try:
                try:
                    host, port = server.split(":")
                    return r.connect(host=host, port=port)
                except ValueError:
                    return r.connect(host=server)
            except Exception as e:
                self.logger.error("will keep trying to get a connection after failure connecting to %s", server, exc_info=True)
                import time
                time.sleep(0.5)

    def run(self, query):
        import rethinkdb as r
        while True:
            with self._random_server_connection() as conn:
                try:
                    return query.run(conn, db=self.db)
                except (r.ReqlAvailabilityError, r.ReqlTimeoutError) as e:
                    self.logger.error("will retry rethinkdb query/operation %s which failed like so:", query, exc_info=True)

version_bytes = _read_version_bytes().strip()
version_str = version_bytes.decode('utf-8')

def gettid():
    try:
        import ctypes
        libc = ctypes.cdll.LoadLibrary('libc.so.6')
        SYS_gettid = 186
        tid = libc.syscall(SYS_gettid)
        return tid
    except:
        logging.warn("gettid failed?")

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
