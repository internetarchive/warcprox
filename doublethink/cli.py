#!/usr/bin/env python
'''
doublethink/orm.py - rethinkdb ORM Command Line Interface

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

def purge_stale_services(argv=None):
    """Command-line utility to periodically purge stale entries from the "services" table.

    It is designed to be used in conjunction with cron.
    """
    argv = argv or sys.argv
    arg_parser = argparse.ArgumentParser(
            prog=os.path.basename(argv[0]),
            description='purge-stale-services: utility to periodically purge stale entries from the "services" table.')

    arg_parser.add_argument("db", help="A RethinkDB database containing a 'services' table")

    arg_parser.add_argument("-s", "--rethinkdb-servers",
        metavar="SERVERS", dest="servers", required=True,
        help="a comma-separated list of hostnames of rethinkdb servers. Required.")
    args = arg_parser.parse_args(argv[1:])

    args.servers = [srv.strip() for srv in args.servers.split(",")]

    rethinker = doublethink.Rethinker(servers=args.servers, db=args)
    registry = doublethink.services.ServiceRegistry(rethinker)
    registry.purge_stale_services()