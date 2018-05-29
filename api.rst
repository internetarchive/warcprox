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

Brozzler knows about ``warcprox-meta``. For information on configuring
it in brozzler, see
https://github.com/internetarchive/brozzler/blob/master/job-conf.rst#warcprox-meta.
``Warcprox-Meta`` is often a very important part of brozzler job configuration.
It is the way url and data limits on jobs, seeds, and hosts are implemented,
among other things.

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
``stats`` is a dictionary with only one field understood by warcprox,
``buckets``. The value of ``buckets`` is a list of strings and/or
dictionaries. A string signifies the name of the bucket; a dictionary is
expected to have at least an item with key ``bucket`` whose value is the name
of the bucket. The other currently recognized key is ``tally-domains``, which
if supplied should be a list of domains. This instructs warcprox to
additionally tally substats of the given bucket by domain. Host stats are
stored in the stats table under the key
``{parent-bucket}:{domain(normalized)}``, e.g. ``"bucket2:foo.bar.com"`` for the
example below.

Examples::

    Warcprox-Meta: {"stats":{"buckets":["my-stats-bucket","all-the-stats"]}}
    Warcprox-Meta: {"stats":{"buckets":["bucket1",{"bucket":"bucket2","tally-domains":["foo.bar.com","192.168.10.20"}]}}

See `<readme.rst#statistics>`_ for more information on statistics kept by
warcprox.

``dedup-bucket`` (string)
~~~~~~~~~~~~~~~~~~~~~~~~~
Specifies the deduplication bucket. For more information about deduplication
see `<readme.rst#deduplication>`_.

Example::

    Warcprox-Meta: {"dedup-bucket":"my-dedup-bucket"}

``blocks`` (list)
~~~~~~~~~~~~~~~~~
List of url match rules. Url match rules are somewhat described at
https://github.com/internetarchive/brozzler/blob/master/job-conf.rst#scoping
and https://github.com/iipc/urlcanon/blob/e2ab3524e/python/urlcanon/rules.py#L70.
(TODO: write a better doc and link to it)

Example::

    Warcprox-Meta: {"blocks": [{"ssurt": "com,example,//http:/"}, {"domain": "malware.us", "substring": "wp-login.php?action=logout"}]}

If any of the rules match the url being requested, warcprox aborts normal
processing and responds with a http 403. The http response includes
a ``Warcprox-Meta`` **response** header with one field, ``blocked-by-rule``,
which reproduces the value of the match rule that resulted in the block. The
presence of the ``warcprox-meta`` response header can be used by the client to
distinguish this type of a response from a 403 from the remote url being
requested.

An example::

    $ curl -iksS --proxy localhost:8000 --header 'Warcprox-Meta: {"blocks": [{"ssurt": "com,example,//http:/"}, {"domain": "malware.us", "substring": "wp-login.php?action=logout"}]}' http://example.com/foo
    HTTP/1.0 403 Forbidden
    Server: BaseHTTP/0.6 Python/3.6.3
    Date: Fri, 25 May 2018 22:46:42 GMT
    Content-Type: text/plain;charset=utf-8
    Connection: close
    Content-Length: 111
    Warcprox-Meta: {"blocked-by-rule":{"ssurt":"com,example,//http:/"}}

    request rejected by warcprox: blocked by rule found in Warcprox-Meta header: {"ssurt": "com,example,//http:/"}

You might be wondering why ``blocks`` is necessary. Why would the warcprox
client make a request that it should already know will be blocked by the proxy?
The answer is that the request may be initiated somewhere where it's difficult
to evaluate the block rules. In particular, this circumstance prevails when the
browser controlled by brozzler is requesting images, javascript, css, and so
on, embedded in a page.

``limits`` (dictionary)
~~~~~~~~~~~~~~~~~~~~~~~
Specifies quantitative limits for warcprox to enforce. The structure of the
dictionary is ``{stats_key: numerical_limit, ...}`` where stats key has the
format ``"bucket/sub-bucket/statistic"``. See `readme.rst#statistics`_ for
further explanation of what "bucket", "sub-bucket", and "statistic" mean here.

Example::

    {"stats": {"buckets": ["test_limits_bucket"]}, "limits": {"test_limits_bucket/total/urls": 10}}

::

    $ curl -iksS --proxy localhost:8000 --header 'Warcprox-Meta: {"stats": {"buckets": ["test_limits_bucket"]}, "limits": {"test_limits_bucket/total/urls": 10}}' http://example.com/foo
    HTTP/1.0 420 Reached limit
    Server: BaseHTTP/0.6 Python/3.6.3
    Date: Fri, 25 May 2018 23:08:32 GMT
    Content-Type: text/plain;charset=utf-8
    Connection: close
    Content-Length: 77
    Warcprox-Meta: {"stats":{"test_limits_bucket":{"bucket":"test_limits_bucket","total":{"urls":10,"wire_bytes":15840},"new":{"urls":0,"wire_bytes":0},"revisit":{"urls":10,"wire_bytes":15840}}},"reached-limit":{"test_limits_bucket/total/urls":10}}

    request rejected by warcprox: reached limit test_limits_bucket/total/urls=10

``soft-limits`` (dictionary)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
From warcprox's perspective ``soft-limits`` work almost exactly the same way
as ``limits``. The only difference is that when a soft limit is hit, warcprox
response with an http 430 "Reached soft limit" instead of http 420.

Warcprox clients might treat a 430 very differently from a 420. From brozzler's
perspective, for instance, ``soft-limits`` are very different from ``limits``.
When brozzler receives a 420 from warcprox because a ``limit`` has been
reached, this means that crawling for that seed is finished, and brozzler sets
about finalizing the crawl of that seed. On the other hand, brozzler blissfully
ignores 430 responses, because soft limits only apply to a particular bucket
(like a domain), and don't have any effect on crawling of urls that don't fall
in that bucket.

Example::

    Warcprox-Meta: {"stats": {"buckets": [{"bucket": "test_domain_doc_limit_bucket", "tally-domains": ["foo.localhost"]}]}, "soft-limits": {"test_domain_doc_limit_bucket:foo.localhost/total/urls": 10}}

::

    $ curl -iksS --proxy localhost:8000 --header 'Warcprox-Meta: {"stats": {"buckets": ["test_limits_bucket"]}, "soft-limits": {"test_limits_bucket/total/urls": 10}}' http://example.com/foo
    HTTP/1.0 430 Reached soft limit
    Server: BaseHTTP/0.6 Python/3.6.3
    Date: Fri, 25 May 2018 23:12:06 GMT
    Content-Type: text/plain;charset=utf-8
    Connection: close
    Content-Length: 82
    Warcprox-Meta: {"stats":{"test_limits_bucket":{"bucket":"test_limits_bucket","total":{"urls":10,"wire_bytes":15840},"new":{"urls":0,"wire_bytes":0},"revisit":{"urls":10,"wire_bytes":15840}}},"reached-soft-limit":{"test_limits_bucket/total/urls":10}}

    request rejected by warcprox: reached soft limit test_limits_bucket/total/urls=10

``metadata`` (dictionary)
~~~~~~~~~~~~~~~~~~~~~~~~~

Example::

    Warcprox-Meta: {"metadata": {"seed": "http://example.com/seed", "description": "here's some information about this crawl job. blah blah"}

``accept`` (list)
~~~~~~~~~~~~~~~~~

Example::

    request_meta = {"accept": ["capture-metadata"]}

``Warcprox-Meta`` http response header
======================================

In some cases warcprox will add a ``Warcprox-Meta`` header in the http response
that it sends to the client. Like the request header, the value is a json blob.
It is only included if something in the ``warcprox-meta`` request header calls
for it. Those cases are described above in the
`#warcprox-meta-http-request-header`_ section.

### - blocked-by-rule
### - reached-limit
### - reached-soft-limit
### - stats
### - capture-metadata
###
### Response codes 420, 430
