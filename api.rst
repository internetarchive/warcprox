warcprox API
************

Means of Interacting with warcprox over http, aside from simply proxying urls.

`/status` url
=============

If warcprox is running at localhost:8000, http://localhost:8000/status returns
a json blob with a bunch of status info. For example:

::

    $ curl -sS http://localhost:8000/status
    {
      "rates_5min": {
        "warc_bytes_per_sec": 0.0,
        "urls_per_sec": 0.0,
        "actual_elapsed": 277.2983281612396
      },
      "version": "2.4b2.dev174",
      "load": 0.0,
      "seconds_behind": 0.0,
      "threads": 100,
      "warc_bytes_written": 0,
      "port": 8000,
      "postfetch_chain": [
        {
          "queued_urls": 0,
          "processor": "SkipFacebookCaptchas"
        },
        {
          "queued_urls": 0,
          "processor": "BatchTroughLoader"
        },
        {
          "queued_urls": 0,
          "processor": "WarcWriterProcessor"
        },
        {
          "queued_urls": 0,
          "processor": "BatchTroughStorer"
        },
        {
          "queued_urls": 0,
          "processor": "RethinkStatsProcessor"
        },
        {
          "queued_urls": 0,
          "processor": "CrawlLogger"
        },
        {
          "queued_urls": 0,
          "processor": "TroughFeed"
        },
        {
          "queued_urls": 0,
          "processor": "RunningStats"
        }
      ],
      "queue_max_size": 500,
      "role": "warcprox",
      "queued_urls": 0,
      "active_requests": 1,
      "host": "wbgrp-svc405.us.archive.org",
      "rates_15min": {
        "warc_bytes_per_sec": 0.0,
        "urls_per_sec": 0.0,
        "actual_elapsed": 876.9885368347168
      },
      "unaccepted_requests": 0,
      "urls_processed": 0,
      "pid": 18841,
      "address": "127.0.0.1",
      "rates_1min": {
        "warc_bytes_per_sec": 0.0,
        "urls_per_sec": 0.0,
        "actual_elapsed": 54.92501664161682
      },
      "start_time": 1526690353.4060142
    }

`WARCPROX_WRITE_RECORD` http method
===================================

::

    $ echo -ne 'WARCPROX_WRITE_RECORD special://url/some?thing HTTP/1.1\r\nWARC-Type: resource\r\ncontent-type: text/plain;charset=utf-8\r\ncontent-length: 29\r\n\r\ni am a warc record payload!\r\n' | ncat 127.0.0.1 8000
    HTTP/1.0 204 OK
    Server: BaseHTTP/0.6 Python/3.6.3
    Date: Mon, 21 May 2018 23:33:31 GMT

::

    WARC/1.0
    WARC-Type: resource
    WARC-Record-ID: <urn:uuid:d0e10852-b18c-4037-a99e-f41915fec5b5>
    WARC-Date: 2018-05-21T23:33:31Z
    WARC-Target-URI: special://url/some?thing
    WARC-Block-Digest: sha1:a282cfe127ab8d51b315ff3d31de18614979d0df
    WARC-Payload-Digest: sha1:a282cfe127ab8d51b315ff3d31de18614979d0df
    Content-Type: text/plain;charset=utf-8
    Content-Length: 29

    i am a warc record payload!


`Warcprox-Meta` http request header
===================================

