#!/usr/bin/env python
'''
doublethink/cli.py - doublethink Command Line Tools

Copyright (C) 2017 Internet Archive

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

import os, sys
import argparse
import doublethink
import logging

def purge_stale_services(argv=None):
    """Command-line utility to periodically purge stale entries from the "services" table.

    It is designed to be used in conjunction with cron.
    """
    argv = argv or sys.argv
    arg_parser = argparse.ArgumentParser(
            prog=os.path.basename(argv[0]), description=(
                'doublethink-purge-stale-services: utility to periodically '
                'purge stale entries from the "services" table.'))

    arg_parser.add_argument(
            "-d", "--rethinkdb-db", required=True, dest="database",
            help="A RethinkDB database containing a 'services' table")

    arg_parser.add_argument("-s", "--rethinkdb-servers",
        metavar="SERVERS", dest="servers", default='localhost',
        help="rethinkdb servers, e.g. db0.foo.org,db0.foo.org:38015,db1.foo.org")

    arg_parser.add_argument(
        '-v', '--verbose', dest='log_level', action='store_const',
        default=logging.INFO, const=logging.DEBUG, help=(
                'verbose logging'))
    args = arg_parser.parse_args(argv[1:])
    logging.basicConfig(
            stream=sys.stdout, level=args.log_level, format=(
                '%(asctime)s %(process)d %(levelname)s %(threadName)s '
                '%(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s'))

    args.servers = [srv.strip() for srv in args.servers.split(",")]

    rethinker = doublethink.Rethinker(servers=args.servers, db=args.database)
    registry = doublethink.services.ServiceRegistry(rethinker)
    registry.purge_stale_services()
    return 0
