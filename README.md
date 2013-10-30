##warcprox - WARC writing MITM HTTP/S proxy

Based on the excellent and simple pymiproxy by Nadeem Douba.
https://github.com/allfro/pymiproxy

License: because pymiproxy is GPL and warcprox is a derivative work of
pymiproxy, warcprox is also GPL.

###Trusting the CA cert

For best results while browsing through warcprox, you need to add the CA cert
as a trusted cert in your browser. If you don't do that, you will get the
warning when you visit each new site. But worse, any embedded https content on
a different server will simply fail to load, because the browser will reject
the certificate without telling you. 

###Dependencies

Currently depends on tweaks branch of my fork of warctools.
https://github.com/nlevitt/warctools/tree/tweaks
Hopefully the changes in that branch, or something equivalent, will be
incorporated into warctools mainline.

###Usage

    usage: warcprox.py [-h] [-p PORT] [-b ADDRESS] [-c CACERT]
                       [--certs-dir CERTS_DIR] [-d DIRECTORY] [-z] [-n PREFIX]
                       [-s SIZE] [--rollover-idle-time ROLLOVER_IDLE_TIME]
                       [--base32] [-v] [-q]
    
    warcprox - WARC writing MITM HTTP/S proxy
    
    optional arguments:
      -h, --help            show this help message and exit
      -p PORT, --port PORT  port to listen on (default: 8080)
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
      --base32              write SHA1 digests in Base32 instead of hex (default:
                            False)
      -v, --verbose
      -q, --quiet

###To do

- integration tests, unit tests
- url-agnostic deduplication
- unchunk and/or ungzip before storing payload, or alter request to discourage server from chunking/gzipping
- check certs from proxied website, like browser does, and present browser-like warning if appropriate
- keep statistics, produce reports
- write cdx while crawling?
- performance testing
- ~~base32 sha1 like heritrix?~~
- configurable timeouts and stuff
- evaluate ipv6 support
- more explicit handling of connection closed exception during transfer? other error cases?
- dns cache?? the system already does a fine job I'm thinking
- keepalive with remote servers?
- python3
- special handling for 304 not-modified (either write revisit record, or modify
  request so server never responds with 304)

#### To not do

The features below could also be part of warcprox. But maybe they don't belong
here, since this is a proxy, not a crawler/robot. It can be used by a human
with a browser, or by something automated, i.e. a robot. My feeling is that
it's more appropriate to implement these in the robot.

- politeness, i.e. throttle requests per server
- fetch and obey robots.txt
- alter user-agent, maybe insert something like "warcprox mitm archiving proxy; +http://archive.org/details/archive.org_bot"

