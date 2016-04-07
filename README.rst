warcprox - WARC writing MITM HTTP/S proxy
-----------------------------------------
.. image:: https://travis-ci.org/internetarchive/warcprox.png?branch=master
        :target: https://travis-ci.org/internetarchive/warcprox

Based on the excellent and simple pymiproxy by Nadeem Douba.
https://github.com/allfro/pymiproxy

Install
~~~~~~~

Warcprox runs on python 3.4.

To install latest release run:


::

    # apt-get install libffi-dev libssl-dev python3-gdbm
    pip install warcprox

You can also install the latest bleeding edge code:

::

    pip install git+https://github.com/internetarchive/warcprox.git


Trusting the CA cert
~~~~~~~~~~~~~~~~~~~~

For best results while browsing through warcprox, you need to add the CA
cert as a trusted cert in your browser. If you don't do that, you will
get the warning when you visit each new site. But worse, any embedded
https content on a different server will simply fail to load, because
the browser will reject the certificate without telling you.

Usage
~~~~~

::

    usage: warcprox [-h] [-p PORT] [-b ADDRESS] [-c CACERT]
                    [--certs-dir CERTS_DIR] [-d DIRECTORY] [-z] [-n PREFIX]
                    [-s SIZE] [--rollover-idle-time ROLLOVER_IDLE_TIME]
                    [-g DIGEST_ALGORITHM] [--base32]
                    [--stats-db-file STATS_DB_FILE] [-P PLAYBACK_PORT]
                    [--playback-index-db-file PLAYBACK_INDEX_DB_FILE]
                    [-j DEDUP_DB_FILE | --rethinkdb-servers RETHINKDB_SERVERS]
                    [--rethinkdb-db RETHINKDB_DB] [--rethinkdb-big-table]
                    [--kafka-broker-list KAFKA_BROKER_LIST]
                    [--kafka-capture-feed-topic KAFKA_CAPTURE_FEED_TOPIC]
                    [--onion-tor-socks-proxy ONION_TOR_SOCKS_PROXY]
                    [--version] [-v] [-q]

    warcprox - WARC writing MITM HTTP/S proxy

    optional arguments:
      -h, --help            show this help message and exit
      -p PORT, --port PORT  port to listen on (default: 8000)
      -b ADDRESS, --address ADDRESS
                            address to listen on (default: localhost)
      -c CACERT, --cacert CACERT
                            CA certificate file; if file does not exist, it
                            will be created (default: ./MacBook-Pro.local-
                            warcprox-ca.pem)
      --certs-dir CERTS_DIR
                            where to store and load generated certificates
                            (default: ./MacBook-Pro.local-warcprox-ca)
      -d DIRECTORY, --dir DIRECTORY
                            where to write warcs (default: ./warcs)
      -z, --gzip            write gzip-compressed warc records (default:
                            False)
      -n PREFIX, --prefix PREFIX
                            WARC filename prefix (default: WARCPROX)
      -s SIZE, --size SIZE  WARC file rollover size threshold in bytes
                            (default: 1000000000)
      --rollover-idle-time ROLLOVER_IDLE_TIME
                            WARC file rollover idle time threshold in seconds
                            (so that Friday's last open WARC doesn't sit there
                            all weekend waiting for more data) (default: None)
      -g DIGEST_ALGORITHM, --digest-algorithm DIGEST_ALGORITHM
                            digest algorithm, one of sha1, sha256, md5,
                            sha224, sha512, sha384 (default: sha1)
      --base32              write digests in Base32 instead of hex (default:
                            False)
      --stats-db-file STATS_DB_FILE
                            persistent statistics database file; empty string
                            or /dev/null disables statistics tracking
                            (default: ./warcprox-stats.db)
      -P PLAYBACK_PORT, --playback-port PLAYBACK_PORT
                            port to listen on for instant playback (default:
                            None)
      --playback-index-db-file PLAYBACK_INDEX_DB_FILE
                            playback index database file (only used if
                            --playback-port is specified) (default:
                            ./warcprox-playback-index.db)
      -j DEDUP_DB_FILE, --dedup-db-file DEDUP_DB_FILE
                            persistent deduplication database file; empty
                            string or /dev/null disables deduplication
                            (default: ./warcprox-dedup.db)
      --rethinkdb-servers RETHINKDB_SERVERS
                            rethinkdb servers, used for dedup and stats if
                            specified; e.g.
                            db0.foo.org,db0.foo.org:38015,db1.foo.org
                            (default: None)
      --rethinkdb-db RETHINKDB_DB
                            rethinkdb database name (ignored unless
                            --rethinkdb-servers is specified) (default:
                            warcprox)
      --rethinkdb-big-table
                            use a big rethinkdb table called "captures",
                            instead of a small table called "dedup"; table is
                            suitable for use as index for playback (ignored
                            unless --rethinkdb-servers is specified) (default:
                            False)
      --kafka-broker-list KAFKA_BROKER_LIST
                            kafka broker list for capture feed (default: None)
      --kafka-capture-feed-topic KAFKA_CAPTURE_FEED_TOPIC
                            kafka capture feed topic (default: None)
      --onion-tor-socks-proxy ONION_TOR_SOCKS_PROXY
                            host:port of tor socks proxy, used only to connect
                            to .onion sites (default: None)
      --version             show program's version number and exit
      -v, --verbose
      -q, --quiet


License
~~~~~~~

Warcprox is a derivative work of pymiproxy, which is GPL. Thus warcprox is also
GPL.

Copyright (C) 2012 Cygnos Corporation
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
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

