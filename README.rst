warcprox - WARC writing MITM HTTP/S proxy
-----------------------------------------
.. image:: https://travis-ci.org/internetarchive/warcprox.png?branch=master   
        :target: https://travis-ci.org/internetarchive/warcprox

Based on the excellent and simple pymiproxy by Nadeem Douba.
https://github.com/allfro/pymiproxy

License: because pymiproxy is GPL and warcprox is a derivative work of
pymiproxy, warcprox is also GPL.


Install
~~~~~~~

Warcprox runs on python 3.4.

To install latest release run:

::

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
                    [-g DIGEST_ALGORITHM] [--base32] [-j DEDUP_DB_FILE]
                    [-P PLAYBACK_PORT]
                    [--playback-index-db-file PLAYBACK_INDEX_DB_FILE] [--version]
                    [-v] [-q]

    warcprox - WARC writing MITM HTTP/S proxy

    optional arguments:
      -h, --help            show this help message and exit
      -p PORT, --port PORT  port to listen on (default: 8000)
      -b ADDRESS, --address ADDRESS
                            address to listen on (default: localhost)
      -c CACERT, --cacert CACERT
                            CA certificate file; if file does not exist, it will
                            be created (default: ./desktop-nlevitt-warcprox-
                            ca.pem)
      --certs-dir CERTS_DIR
                            where to store and load generated certificates
                            (default: ./desktop-nlevitt-warcprox-ca)
      -d DIRECTORY, --dir DIRECTORY
                            where to write warcs (default: ./warcs)
      -z, --gzip            write gzip-compressed warc records (default: False)
      -n PREFIX, --prefix PREFIX
                            WARC filename prefix (default: WARCPROX)
      -s SIZE, --size SIZE  WARC file rollover size threshold in bytes (default:
                            1000000000)
      --rollover-idle-time ROLLOVER_IDLE_TIME
                            WARC file rollover idle time threshold in seconds (so
                            that Friday's last open WARC doesn't sit there all
                            weekend waiting for more data) (default: None)
      -g DIGEST_ALGORITHM, --digest-algorithm DIGEST_ALGORITHM
                            digest algorithm, one of sha384, sha512, md5, sha224,
                            sha256, sha1 (default: sha1)
      --base32              write digests in Base32 instead of hex (default:
                            False)
      -j DEDUP_DB_FILE, --dedup-db-file DEDUP_DB_FILE
                            persistent deduplication database file; empty string
                            or /dev/null disables deduplication (default:
                            ./warcprox-dedup.db)
      -P PLAYBACK_PORT, --playback-port PLAYBACK_PORT
                            port to listen on for instant playback (default: None)
      --playback-index-db-file PLAYBACK_INDEX_DB_FILE
                            playback index database file (only used if --playback-
                            port is specified) (default: ./warcprox-playback-
                            index.db)
      --version             show program's version number and exit
      -v, --verbose
      -q, --quiet

To do
~~~~~

* (partly done) integration tests, unit tests
* (done) url-agnostic deduplication
* unchunk and/or ungzip before storing payload, or alter request to
  discourage server from chunking/gzipping
* check certs from proxied website, like browser does, and present
  browser-like warning if appropriate
* keep statistics, produce reports
* write cdx while crawling?
* performance testing
* (done) base32 sha1 like heritrix?
* configurable timeouts and stuff
* evaluate ipv6 support
* (done) more explicit handling of connection closed exception
  during transfer
* dns cache?? the system already does a fine job I'm thinking
* keepalive with remote servers?
* (done) python3
* special handling for 304 not-modified (write nothing or write revisit
  record... and/or modify request so server never responds with 304)
* (done) instant playback on a second proxy port
* special url for downloading ca cert e.g. http(s)://warcprox./ca.pem
* special url for other stuff, some status info or something?
* browser plugin for warcprox mode

  -  accept warcprox CA cert only when in warcprox mode
  -  separate temporary cookie store, like incognito
  -  "careful! your activity is being archived" banner
  -  easy switch between archiving and instant playback proxy port

To not do
^^^^^^^^^

The features below could also be part of warcprox. But maybe they don't
belong here, since this is a proxy, not a crawler/robot. It can be used
by a human with a browser, or by something automated, i.e. a robot. My
feeling is that it's more appropriate to implement these in the robot.

*  politeness, i.e. throttle requests per server
*  fetch and obey robots.txt
*  alter user-agent, maybe insert something like "warcprox mitm
   archiving proxy; +http://archive.org/details/archive.org\_bot"

