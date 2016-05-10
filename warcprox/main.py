#!/usr/bin/env python
'''
warcprox/main.py - entrypoint for warcprox executable, parses command line
arguments, initializes components, starts controller, handles signals

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
    import queue
except ImportError:
    import Queue as queue

import logging
import sys
import hashlib
import argparse
import os
import socket
import pprint
import traceback
import signal
import threading
import certauth.certauth
import warcprox
import re
import rethinkstuff

def _build_arg_parser(prog=os.path.basename(sys.argv[0])):
    arg_parser = argparse.ArgumentParser(prog=prog,
            description='warcprox - WARC writing MITM HTTP/S proxy',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('-p', '--port', dest='port', default='8000',
            type=int, help='port to listen on')
    arg_parser.add_argument('-b', '--address', dest='address',
            default='localhost', help='address to listen on')
    arg_parser.add_argument('-c', '--cacert', dest='cacert',
            default='./{0}-warcprox-ca.pem'.format(socket.gethostname()),
            help='CA certificate file; if file does not exist, it will be created')
    arg_parser.add_argument('--certs-dir', dest='certs_dir',
            default='./{0}-warcprox-ca'.format(socket.gethostname()),
            help='where to store and load generated certificates')
    arg_parser.add_argument('-d', '--dir', dest='directory',
            default='./warcs', help='where to write warcs')
    arg_parser.add_argument('-z', '--gzip', dest='gzip', action='store_true',
            help='write gzip-compressed warc records')
    arg_parser.add_argument('-n', '--prefix', dest='prefix',
            default='WARCPROX', help='WARC filename prefix')
    arg_parser.add_argument('-s', '--size', dest='size',
            default=1000*1000*1000, type=int,
            help='WARC file rollover size threshold in bytes')
    arg_parser.add_argument('--rollover-idle-time',
            dest='rollover_idle_time', default=None, type=int,
            help="WARC file rollover idle time threshold in seconds (so that Friday's last open WARC doesn't sit there all weekend waiting for more data)")
    try:
        hash_algos = hashlib.algorithms_guaranteed
    except AttributeError:
        hash_algos = hashlib.algorithms
    arg_parser.add_argument('-g', '--digest-algorithm', dest='digest_algorithm',
            default='sha1', help='digest algorithm, one of {}'.format(', '.join(hash_algos)))
    arg_parser.add_argument('--base32', dest='base32', action='store_true',
            default=False, help='write digests in Base32 instead of hex')
    arg_parser.add_argument('--stats-db-file', dest='stats_db_file',
            default='./warcprox-stats.db', help='persistent statistics database file; empty string or /dev/null disables statistics tracking')
    arg_parser.add_argument('-P', '--playback-port', dest='playback_port',
            type=int, default=None, help='port to listen on for instant playback')
    arg_parser.add_argument('--playback-index-db-file', dest='playback_index_db_file',
            default='./warcprox-playback-index.db',
            help='playback index database file (only used if --playback-port is specified)')
    group = arg_parser.add_mutually_exclusive_group()
    group.add_argument('-j', '--dedup-db-file', dest='dedup_db_file',
            default='./warcprox-dedup.db', help='persistent deduplication database file; empty string or /dev/null disables deduplication')
    group.add_argument('--rethinkdb-servers', dest='rethinkdb_servers',
            help='rethinkdb servers, used for dedup and stats if specified; e.g. db0.foo.org,db0.foo.org:38015,db1.foo.org')
    arg_parser.add_argument('--rethinkdb-db', dest='rethinkdb_db', default='warcprox',
            help='rethinkdb database name (ignored unless --rethinkdb-servers is specified)')
    arg_parser.add_argument('--rethinkdb-big-table',
            dest='rethinkdb_big_table', action='store_true', default=False,
            help='use a big rethinkdb table called "captures", instead of a small table called "dedup"; table is suitable for use as index for playback (ignored unless --rethinkdb-servers is specified)')
    arg_parser.add_argument('--kafka-broker-list', dest='kafka_broker_list',
            default=None, help='kafka broker list for capture feed')
    arg_parser.add_argument('--kafka-capture-feed-topic', dest='kafka_capture_feed_topic',
            default=None, help='kafka capture feed topic')
    arg_parser.add_argument('--queue-size', dest='queue_size', default=500,
            help=argparse.SUPPRESS)
    arg_parser.add_argument('--max-threads', dest='max_threads',
            help=argparse.SUPPRESS)
    arg_parser.add_argument('--profile', action='store_true', default=False,
            help=argparse.SUPPRESS)
    arg_parser.add_argument('--onion-tor-socks-proxy', dest='onion_tor_socks_proxy',
            default=None, help='host:port of tor socks proxy, used only to connect to .onion sites')
    arg_parser.add_argument('--version', action='version',
            version="warcprox {}".format(warcprox.__version__))
    arg_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true')
    arg_parser.add_argument('--trace', dest='trace', action='store_true')
    arg_parser.add_argument('-q', '--quiet', dest='quiet', action='store_true')

    return arg_parser

def dump_state(signum=None, frame=None):
    '''
    Signal handler, logs stack traces of active threads.
    '''
    pp = pprint.PrettyPrinter(indent=4)
    state_strs = []

    for th in threading.enumerate():
        try:
            state_strs.append(str(th))
        except AssertionError:
            state_strs.append("<n/a:AssertionError>")
        stack = traceback.format_stack(sys._current_frames()[th.ident])
        state_strs.append("".join(stack))

    logging.warn("dumping state (caught signal {})\n{}".format(signum, "\n".join(state_strs)))

def init_controller(args):
    '''
    Creates a warcprox.controller.WarcproxController configured according to
    the supplied arguments (normally the result of parse_args(sys.argv)).
    '''
    options = warcprox.Options(**vars(args))

    try:
        hashlib.new(args.digest_algorithm)
    except Exception as e:
        logging.fatal(e)
        exit(1)

    listeners = []
    if args.rethinkdb_servers:
        r = rethinkstuff.Rethinker(args.rethinkdb_servers.split(","), args.rethinkdb_db)
        if args.rethinkdb_big_table:
            captures_db = warcprox.bigtable.RethinkCaptures(r, options=options)
            dedup_db = warcprox.bigtable.RethinkCapturesDedup(captures_db, options=options)
            listeners.append(captures_db)
        else:
            dedup_db = warcprox.dedup.RethinkDedupDb(r, options=options)
            listeners.append(dedup_db)
    elif args.dedup_db_file in (None, '', '/dev/null'):
        logging.info('deduplication disabled')
        dedup_db = None
    else:
        dedup_db = warcprox.dedup.DedupDb(args.dedup_db_file, options=options)
        listeners.append(dedup_db)

    if args.rethinkdb_servers:
        stats_db = warcprox.stats.RethinkStatsDb(r, options=options)
        listeners.append(stats_db)
    elif args.stats_db_file in (None, '', '/dev/null'):
        logging.info('statistics tracking disabled')
        stats_db = None
    else:
        stats_db = warcprox.stats.StatsDb(args.stats_db_file, options=options)
        listeners.append(stats_db)

    if args.kafka_broker_list and args.kafka_capture_feed_topic:
        kafka_capture_feed = warcprox.kafkafeed.CaptureFeed(args.kafka_broker_list, args.kafka_capture_feed_topic)
        listeners.append(kafka_capture_feed)

    recorded_url_q = queue.Queue(maxsize=args.queue_size)

    ca_name = 'Warcprox CA on {}'.format(socket.gethostname())[:64]
    ca = certauth.certauth.CertificateAuthority(args.cacert, args.certs_dir,
                                                ca_name=ca_name)

    proxy = warcprox.warcproxy.WarcProxy(ca=ca, recorded_url_q=recorded_url_q,
            stats_db=stats_db, options=options)

    if args.playback_port is not None:
        playback_index_db = warcprox.playback.PlaybackIndexDb(args.playback_index_db_file, options=options)
        playback_proxy = warcprox.playback.PlaybackProxy(
                server_address=(args.address, args.playback_port), ca=ca,
                playback_index_db=playback_index_db, warcs_dir=args.directory,
                options=options)
        listeners.append(playback_index_db)
    else:
        playback_index_db = None
        playback_proxy = None

    writer_pool = warcprox.writer.WarcWriterPool(options=options)
    warc_writer_thread = warcprox.writerthread.WarcWriterThread(
            recorded_url_q=recorded_url_q, writer_pool=writer_pool,
            dedup_db=dedup_db, listeners=listeners, options=options)

    if args.rethinkdb_servers:
        svcreg = rethinkstuff.ServiceRegistry(r)
    else:
        svcreg = None

    controller = warcprox.controller.WarcproxController(proxy,
        warc_writer_thread, playback_proxy, service_registry=svcreg,
        options=options)

    signal.signal(signal.SIGTERM, lambda a,b: controller.stop.set())
    signal.signal(signal.SIGINT, lambda a,b: controller.stop.set())
    signal.signal(signal.SIGQUIT, dump_state)

    return controller

def real_main(args):
    controller = init_controller(args)
    controller.run_until_shutdown()

def parse_args(argv=sys.argv):
    '''
    Parses command line arguments with argparse.
    '''
    arg_parser = _build_arg_parser(prog=os.path.basename(argv[0]))
    args = arg_parser.parse_args(args=argv[1:])
    return args

def main(argv=sys.argv):
    '''
    Main method, entry point of warcprox command.
    '''
    args = parse_args(argv)

    if args.trace:
        loglevel = warcprox.TRACE
    elif args.verbose:
        loglevel = logging.DEBUG
    elif args.quiet:
        loglevel = logging.WARNING
    else:
        loglevel = logging.INFO

    logging.basicConfig(stream=sys.stdout, level=loglevel,
            format='%(asctime)s %(process)d %(levelname)s %(threadName)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')

    real_main(args)

if __name__ == '__main__':
    main()

