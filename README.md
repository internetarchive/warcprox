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
                       [-s SIZE] [-v] [-q]
    
    warcprox - WARC writing MITM HTTP/S proxy
    
    optional arguments:
      -h, --help            show this help message and exit
      -p PORT, --port PORT  port to listen on (default: 8080)
      -b ADDRESS, --address ADDRESS
                            address to listen on (default: localhost)
      -c CACERT, --cacert CACERT
                            CA certificate file; if file does not exist, it will
                            be created (default: ./warcprox-ca.pem)
      --certs-dir CERTS_DIR
                            where to store and load generated certificates
                            (default: ./warcprox-ca)
      -d DIRECTORY, --dir DIRECTORY
                            where to write warcs (default: ./warcs)
      -z, --gzip            write gzip-compressed warc records (default: False)
      -n PREFIX, --prefix PREFIX
                            WARC filename prefix (default: WARCPROX)
      -s SIZE, --size SIZE  WARC file rollover size threshold in bytes (default:
                            1000000000)
      -v, --verbose
      -q, --quiet

###To do

- politeness, i.e. throttle requests per server
- fetch and obey robots.txt
- url-agnostic deduplication
- alter user-agent, maybe insert something like "warcprox mitm archiving proxy; +http://archive.org/details/archive.org_bot"
- unchunk and/or ungzip before storing payload, or alter request to discourage server from chunking/gzipping
- check suppressed certs from proxied website, like browser does, and present browser-like warning if appropriate
- write cdx while crawling?
- keep statistics, produce reports
- performance testing
- etc...
