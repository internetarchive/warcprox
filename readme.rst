warcprox - WARC writing MITM HTTP/S proxy
*****************************************
.. image:: https://travis-ci.org/internetarchive/warcprox.svg?branch=master
    :target: https://travis-ci.org/internetarchive/warcprox

Based on the excellent and simple pymiproxy by Nadeem Douba.
https://github.com/allfro/pymiproxy

Install
=======

Warcprox runs on python 3.4+.

To install latest release run:

::

    # apt-get install libffi-dev libssl-dev
    pip install warcprox

You can also install the latest bleeding edge code:

::

    pip install git+https://github.com/internetarchive/warcprox.git


Trusting the CA cert
====================

For best results while browsing through warcprox, you need to add the CA
cert as a trusted cert in your browser. If you don't do that, you will
get the warning when you visit each new site. But worse, any embedded
https content on a different server will simply fail to load, because
the browser will reject the certificate without telling you.

API
===

For interacting with a running instance of warcprox.

* `/status` url
* `WARCPROX_WRITE_RECORD` http method
* `Warcprox-Meta` http request header

See `<api.rst>`_.

Plugins
=======

Warcprox supports a limited notion of plugins by way of the `--plugin` command
line argument. Plugin classes are loaded from the regular python module search
path. They will be instantiated with one argument, a `warcprox.Options`, which
holds the values of all the command line arguments. Legacy plugins with
constructors that take no arguments are also supported. Plugins should either
have a method `notify(self, recorded_url, records)` or should subclass
`warcprox.BasePostfetchProcessor`. More than one plugin can be configured by
specifying `--plugin` multiples times.

`A minimal example <https://github.com/internetarchive/warcprox/blob/318405e795ac0ab8760988a1a482cf0a17697148/warcprox/__init__.py#L165>`__

Usage
=====

::

    usage: warcprox [-h] [-p PORT] [-b ADDRESS] [-c CACERT]
                    [--certs-dir CERTS_DIR] [-d DIRECTORY]
                    [--warc-filename WARC_FILENAME] [-z] [-n PREFIX]
                    [-s ROLLOVER_SIZE]
                    [--rollover-idle-time ROLLOVER_IDLE_TIME]
                    [-g DIGEST_ALGORITHM] [--base32]
                    [--method-filter HTTP_METHOD]
                    [--stats-db-file STATS_DB_FILE | --rethinkdb-stats-url RETHINKDB_STATS_URL]
                    [-P PLAYBACK_PORT]
                    [-j DEDUP_DB_FILE | --rethinkdb-dedup-url RETHINKDB_DEDUP_URL | --rethinkdb-big-table-url RETHINKDB_BIG_TABLE_URL | --rethinkdb-trough-db-url RETHINKDB_TROUGH_DB_URL | --cdxserver-dedup CDXSERVER_DEDUP]
                    [--rethinkdb-services-url RETHINKDB_SERVICES_URL]
                    [--onion-tor-socks-proxy ONION_TOR_SOCKS_PROXY]
                    [--crawl-log-dir CRAWL_LOG_DIR] [--plugin PLUGIN_CLASS]
                    [--version] [-v] [--trace] [-q]

    warcprox - WARC writing MITM HTTP/S proxy

    optional arguments:
      -h, --help            show this help message and exit
      -p PORT, --port PORT  port to listen on (default: 8000)
      -b ADDRESS, --address ADDRESS
                            address to listen on (default: localhost)
      -c CACERT, --cacert CACERT
                            CA certificate file; if file does not exist, it
                            will be created (default:
                            ./ayutla.monkeybrains.net-warcprox-ca.pem)
      --certs-dir CERTS_DIR
                            where to store and load generated certificates
                            (default: ./ayutla.monkeybrains.net-warcprox-ca)
      -d DIRECTORY, --dir DIRECTORY
                            where to write warcs (default: ./warcs)
      --warc-filename WARC_FILENAME
                            define custom WARC filename with variables
                            {prefix}, {timestamp14}, {timestamp17},
                            {serialno}, {randomtoken}, {hostname},
                            {shorthostname} (default:
                            {prefix}-{timestamp17}-{serialno}-{randomtoken})
      -z, --gzip            write gzip-compressed warc records
      -n PREFIX, --prefix PREFIX
                            default WARC filename prefix (default: WARCPROX)
      -s ROLLOVER_SIZE, --size ROLLOVER_SIZE
                            WARC file rollover size threshold in bytes
                            (default: 1000000000)
      --rollover-idle-time ROLLOVER_IDLE_TIME
                            WARC file rollover idle time threshold in seconds
                            (so that Friday's last open WARC doesn't sit there
                            all weekend waiting for more data) (default: None)
      -g DIGEST_ALGORITHM, --digest-algorithm DIGEST_ALGORITHM
                            digest algorithm, one of sha384, sha224, md5,
                            sha256, sha512, sha1 (default: sha1)
      --base32              write digests in Base32 instead of hex
      --method-filter HTTP_METHOD
                            only record requests with the given http method(s)
                            (can be used more than once) (default: None)
      --stats-db-file STATS_DB_FILE
                            persistent statistics database file; empty string
                            or /dev/null disables statistics tracking
                            (default: ./warcprox.sqlite)
      --rethinkdb-stats-url RETHINKDB_STATS_URL
                            rethinkdb stats table url, e.g. rethinkdb://db0.fo
                            o.org,db1.foo.org:38015/my_warcprox_db/my_stats_ta
                            ble (default: None)
      -P PLAYBACK_PORT, --playback-port PLAYBACK_PORT
                            port to listen on for instant playback (default:
                            None)
      -j DEDUP_DB_FILE, --dedup-db-file DEDUP_DB_FILE
                            persistent deduplication database file; empty
                            string or /dev/null disables deduplication
                            (default: ./warcprox.sqlite)
      --rethinkdb-dedup-url RETHINKDB_DEDUP_URL
                            rethinkdb dedup url, e.g. rethinkdb://db0.foo.org,
                            db1.foo.org:38015/my_warcprox_db/my_dedup_table
                            (default: None)
      --rethinkdb-big-table-url RETHINKDB_BIG_TABLE_URL
                            rethinkdb big table url (table will be populated
                            with various capture information and is suitable
                            for use as index for playback), e.g. rethinkdb://d
                            b0.foo.org,db1.foo.org:38015/my_warcprox_db/captur
                            es (default: None)
      --rethinkdb-trough-db-url RETHINKDB_TROUGH_DB_URL
                            🐷 url pointing to trough configuration rethinkdb
                            database, e.g. rethinkdb://db0.foo.org,db1.foo.org
                            :38015/trough_configuration (default: None)
      --cdxserver-dedup CDXSERVER_DEDUP
                            use a CDX Server URL for deduplication; e.g.
                            https://web.archive.org/cdx/search (default: None)
      --rethinkdb-services-url RETHINKDB_SERVICES_URL
                            rethinkdb service registry table url; if provided,
                            warcprox will create and heartbeat entry for
                            itself (default: None)
      --onion-tor-socks-proxy ONION_TOR_SOCKS_PROXY
                            host:port of tor socks proxy, used only to connect
                            to .onion sites (default: None)
      --crawl-log-dir CRAWL_LOG_DIR
                            if specified, write crawl log files in the
                            specified directory; one crawl log is written per
                            warc filename prefix; crawl log format mimics
                            heritrix (default: None)
      --plugin PLUGIN_CLASS
                            Qualified name of plugin class, e.g.
                            "mypkg.mymod.MyClass". May be used multiple times
                            to register multiple plugins. See README.rst for
                            more information. (default: None)
      --version             show program's version number and exit
      -v, --verbose
      --trace
      -q, --quiet

License
=======

Warcprox is a derivative work of pymiproxy, which is GPL. Thus warcprox is also
GPL.

* Copyright (C) 2012 Cygnos Corporation
* Copyright (C) 2013-2018 Internet Archive

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

