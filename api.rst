warcprox API
************

Means of interacting with warcprox over http, aside from simply proxying urls.

.. contents::

``/status`` url
===============

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

``WARCPROX_WRITE_RECORD`` http method
=====================================

To make warcprox write an arbitrary warc record you can send it a special
request with http method ``WARCPROX_WRITE_RECORD``. The http request must
include the headers ``WARC-Type``, ``Content-Type``, and ``Content-Length``.
Warcprox will use these to populate the warc record. For example::

    $ ncat --crlf 127.0.0.1 8000 <<EOF
    > WARCPROX_WRITE_RECORD special://url/some?thing HTTP/1.1
    > WARC-Type: resource
    > Content-type: text/plain;charset=utf-8
    > Content-length: 29
    > 
    > i am a warc record payload!
    > EOF
    HTTP/1.0 204 OK
    Server: BaseHTTP/0.6 Python/3.6.3
    Date: Tue, 22 May 2018 19:21:02 GMT

On success warcprox responds with http status 204. For the request above
warcprox will write a warc record that looks like this::

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

``Warcprox-Meta`` http request header
=====================================

``Warcprox-Meta`` is a special http request header that can be used to pass
configuration information and metadata with each proxy request to warcprox. The
value is a json blob. There are several fields understood by warcprox, and
arbitrary additional fields can be included. If warcprox doesn't recognize a
field it simply ignores it. Warcprox plugins could make use of custom fields,
for example.

Warcprox strips the ``warcprox-meta`` header out before sending the request to
remote server, and also does not write it in the warc request record.

::

    Warcprox-Meta: {}

Warcprox-Meta fields
-------------------

``warc-prefix`` (string)
~~~~~~~~~~~~~~~~~~~~~~~~
Specifies a warc filename prefix. Warcprox will write the warc record for this
capture, if any, to a warc named accordingly.

Example::

    Warcprox-Meta: {"warc-prefix": "special-warc"}

``stats`` (dictionary)
~~~~~~~~~~~~~~~~~~~~~~
* buckets

Example::

    Warcprox-Meta: {"stats":{"buckets":["my-stats-bucket","all-the-stats"]}}

``dedup-bucket`` (string)
~~~~~~~~~~~~~~~~~~~~~~~~~
Specifies the deduplication bucket. For more information about deduplication
see `<readme.rst#deduplication>`_.

Example::

    Warcprox-Meta: {"dedup-bucket":"my-dedup-bucket"}

``blocks``
~~~~~~~~~~

``limits``
~~~~~~~~~~

``soft-limits``
~~~~~~~~~~~~~~~

``metadata`` (dictionary)
~~~~~~~~~~~~~~~~~~~~~~~~~

``accept``
~~~~~~~~~~

Brozzler knows about ``warcprox-meta``. For information on configuring
``warcprox-meta`` in brozzler, see https://github.com/internetarchive/brozzler/blob/master/job-conf.rst#warcprox-meta

``Warcprox-Meta`` http response header
======================================

In some cases warcprox will add a ``Warcprox-Meta`` header in the http response
that it sends to the client. Like the request header, the value is a json blob.
It is only included if something in the ``warcprox-meta`` request header calls
for it. Those cases are described above in the "``Warcprox-Meta`` http request header" section.

### - blocked-by-rule
### - reached-limit
### - reached-soft-limit
### - stats
### - capture-metadata
###
### Response codes 420, 430
