"""
This module is an extension to warcprox
to provide a SingleWarcPerUrlWriterThread which writes a new single warc
per url request instead of appending to one open warc
"""

from warcprox import WarcWriterThread, _build_arg_parser
from warcprox import CertificateAuthority, WarcProxy, WarcproxController

import logging
import sys
import os
import hashlib
import re

try:
    import queue
except ImportError:
    import Queue
    queue = Queue

try:
    import http.cookies
    cookie = http.cookies
except ImportError:
    import Cookie
    cookie = Cookie


class SingleWarcPerUrlWriterThread(WarcWriterThread):

    # regex to match invalid chars in dir
    STRIP_DIR_RX = re.compile('[\W]+')

    def init_writer(self):
        pass

    def get_record_writer(self, recorded_url):
        target_dir = None

        if recorded_url.custom_header_params:
            params = cookie.SimpleCookie()
            params.load(recorded_url.custom_header_params)
            try:
                target_dir = params["target"].value
            except KeyError:
                pass

        if target_dir:
            # strip non-alphanum and _ from target dir, for security
            target_dir = self.STRIP_DIR_RX.sub('', target_dir)
            target_dir = os.path.join(self.directory, target_dir)

            if not os.path.exists(target_dir):
                self.logger.info("warc destination directory {} doesn't exist, creating it".format(target_dir))
                os.mkdir(target_dir)
        else:
            #TODO: is this required? maybe it an error if omitted?
            target_dir = self.directory


        filename = '{}-{}.warc{}'.format(self.timestamp17(),
                                       os.getpid(),
                                       '.gz' if self.gzip else '')

        fullpath = os.path.join(target_dir, filename)

        writer = open(fullpath, 'wb')
        return fullpath, writer

    def finish_record(self, path, writer, recorded_url):
        writer.flush()
        writer.close()

    def close_writer(self):
        pass


def main(argv=sys.argv):
    arg_parser = _build_arg_parser()
    args = arg_parser.parse_args(args=argv[1:])

    if args.verbose:
        loglevel = logging.DEBUG
    elif args.quiet:
        loglevel = logging.WARNING
    else:
        loglevel = logging.INFO

    logging.basicConfig(stream=sys.stdout, level=loglevel,
            format='%(asctime)s %(process)d %(levelname)s %(threadName)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')

    try:
        hashlib.new(args.digest_algorithm)
    except Exception as e:
        logging.fatal(e)
        exit(1)

    recorded_url_q = queue.Queue()

    ca = CertificateAuthority(args.cacert, args.certs_dir)

    proxy = WarcProxy(server_address=(args.address, int(args.port)),
            ca=ca, recorded_url_q=recorded_url_q,
            digest_algorithm=args.digest_algorithm)

    warc_writer = SingleWarcPerUrlWriterThread(recorded_url_q=recorded_url_q,
            directory=args.directory, gzip=args.gzip, prefix=args.prefix,
            port=int(args.port), rollover_size=int(args.size),
            rollover_idle_time=None,
            base32=args.base32, dedup_db=None,
            digest_algorithm=args.digest_algorithm,
            playback_index_db=None)

    warcprox = WarcproxController(proxy, warc_writer, None)
    warcprox.run_until_shutdown()

if __name__ == "__main__":
    main()
