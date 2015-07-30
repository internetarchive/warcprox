# vim:set sw=4 et:

import warcprox.controller as controller
import warcprox.playback as playback
import warcprox.dedup as dedup
import warcprox.warcproxy as warcproxy
import warcprox.mitmproxy as mitmproxy
import warcprox.writer as writer
import warcprox.warc as warc
import warcprox.writerthread as writerthread

def digest_str(hash_obj, base32):
    import base64
    return hash_obj.name.encode('utf-8') + b':' + (base64.b32encode(hash_obj.digest()) if base32 else hash_obj.hexdigest().encode('ascii'))

def _read_version_bytes():
    import os
    version_txt = os.path.sep.join(__file__.split(os.path.sep)[:-1] + ['version.txt'])
    with open(version_txt, 'rb') as fin:
        return fin.read().strip()

version_bytes = _read_version_bytes().strip()
version_str = version_bytes.decode('utf-8')
