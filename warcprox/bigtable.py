# vim:set sw=4 et:

from __future__ import absolute_import

import logging
from hanzo import warctools
import rethinkdb
r = rethinkdb
import random
import warcprox
import base64
import surt
import os

class RethinkCaptures:
    logger = logging.getLogger("warcprox.bigtables.RethinkCaptures")

    def __init__(self, servers=["localhost"], db="warcprox", table="captures", shards=3, replicas=3, options=warcprox.Options()):
        self.r = warcprox.Rethinker(servers, db)
        self.table = table
        self.shards = shards
        self.replicas = replicas
        self.options = options
        self._ensure_db_table()

    def _ensure_db_table(self):
        dbs = self.r.run(r.db_list())
        if not self.r.db in dbs:
            self.logger.info("creating rethinkdb database %s", repr(self.r.db))
            self.r.run(r.db_create(self.r.db))
        tables = self.r.run(r.table_list())
        if not self.table in tables:
            self.logger.info("creating rethinkdb table %s in database %s", repr(self.table), repr(self.r.db))
            self.r.run(r.table_create(self.table, shards=self.shards, replicas=self.replicas))
            self.r.run(r.table(self.table).index_create("abbr_canon_surt_timesamp", [r.row["abbr_canon_surt"], r.row["timestamp"]]))
            self.r.run(r.table(self.table).index_create("sha1_warc_type", [r.row["sha1base32"], r.row["warc_type"], r.row["bucket"]]))

    def find_response_by_digest(self, algo, raw_digest, bucket="__unspecified__"):
        if algo != "sha1":
            raise Exception("digest type is {} but big capture table is indexed by sha1".format(algo))
        sha1base32 = base64.b32encode(raw_digest).decode("utf-8")
        cursor = self.r.run(r.table(self.table).get_all([sha1base32, "response", bucket], index="sha1_warc_type"))
        results = list(cursor)
        if len(results) > 1:
            raise Exception("expected 0 or 1 but found %s results for sha1base32=%s", len(results), sha1base32)
        elif len(results) == 1:
            result = results[0]
        else:
            result = None
        self.logger.debug("returning %s for sha1base32=%s bucket=%s", result, sha1base32, bucket)
        return result

    def notify(self, recorded_url, records):
        if not recorded_url.response_recorder:
            return

        if recorded_url.response_recorder.payload_digest.name != "sha1":
            self.logger.warn("digest type is %s but big capture table is indexed by sha1", recorded_url.response_recorder.payload_digest.name)

        if recorded_url.warcprox_meta and "captures-bucket" in recorded_url.warcprox_meta:
            bucket = recorded_url.warcprox_meta["captures-bucket"]
        else:
            bucket = "__unspecified__"

        canon_surt = surt.surt(recorded_url.url.decode("utf-8"), trailing_comma=True, host_massage=False)

        mimetype = recorded_url.content_type
        if mimetype:
            n = mimetype.find(";")
            if n >= 0:
                mimetype = mimetype[:n]

        entry = {
            # id only specified for rethinkdb partitioning
            "id": "{} {}".format(canon_surt[:20], records[0].id.decode("utf-8")[10:-1]),
            "abbr_canon_surt": canon_surt[:150],
            # "timestamp": re.sub(r"[^0-9]", "", records[0].date.decode("utf-8")),
            "timestamp": records[0].date.decode("utf-8"),
            "url": recorded_url.url.decode("utf-8"),
            "offset": records[0].offset,
            "filename": os.path.basename(records[0].warc_filename),
            "warc_type": records[0].type.decode("utf-8"),
            "warc_id": records[0].id.decode("utf-8"),
            "sha1base32": base64.b32encode(recorded_url.response_recorder.payload_digest.digest()).decode("utf-8"),
            "content_type": mimetype,
            "response_code": recorded_url.status,
            "http_method": recorded_url.method,
            "bucket": bucket,
            "length": records[0].length,
        }

        result = self.r.run(r.table(self.table).insert(entry))
        if result["inserted"] == 1 and sorted(result.values()) != [0,0,0,0,0,1]:
            raise Exception("unexpected result %s saving %s", result, entry)
        self.logger.debug("big capture table db saved %s", entry)

class RethinkCapturesDedup:
    logger = logging.getLogger("warcprox.dedup.RethinkCapturesDedup")

    def __init__(self, captures_db, options=warcprox.Options()):
        self.captures_db = captures_db
        self.options = options

    def lookup(self, digest_key, bucket="__unspecified__"):
        k = digest_key.decode("utf-8") if isinstance(digest_key, bytes) else digest_key
        algo, value_str = k.split(":")
        if self.options.base32:
            raw_digest = base64.b32decode(value_str, casefold=True)
        else:
            raw_digest = base64.b16decode(value_str, casefold=True)
        entry = self.captures_db.find_response_by_digest(algo, raw_digest, bucket)
        if entry:
            dedup_info = {"url":entry["url"].encode("utf-8"), "date":entry["timestamp"].encode("utf-8"), "id":entry["warc_id"].encode("utf-8")}
            return dedup_info
        else:
            return None

    def close(self):
        pass
