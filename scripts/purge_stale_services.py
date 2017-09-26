#!/usr/bin/env python
import sys
from optparse import OptionParser
from doublethink import Rethinker
from doublethink.services import ServiceRegistry

usage = """usage: %prog [options] db
where 'db' is the the name of a RethinkDB database that contains a "services" table.

This script can be used to periodically purge stale entries from the "services" table.

It is designed to be used in conjunction with cron.

Example:
%prog -s rethink-host0,rethink-host1,rethink-host2 doublethink_database"""
parser = OptionParser(usage=usage)
parser.add_option("-s", "--rethinkdb-servers",
    metavar="SERVERS", dest="servers",
    help="a comma-separated list of hostnames of rethinkdb servers. Required. [default: none]")
parser.add_option("-g", "--grace-period",
    metavar="SECONDS", dest="grace_period", type="int",
    help="leave records that have been stale for up to SECONDS seconds. [default: 0]")
(options, args) = parser.parse_args()

if len(args) < 1:
    sys.exit('"db" is a required argument and should be the name of a RethinkDB database that contains a "services" table. See "--help" for a list of options')

if not options.servers:
    sys.exit('--rethinkdb-servers (-s) is a required argument. It should be a comma-separated list of rethinkdb servers. See --help for more information')

options.servers = [srv.strip() for srv in options.servers.split(",")]

rethinker = Rethinker(servers=options.servers, db=args[0])
registry = ServiceRegistry(rethinker)
registry.purge_stale_services(grace_period=options.grace_period)