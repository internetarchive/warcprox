# vim:set sw=4 et:

from __future__ import absolute_import

import logging
from hanzo import warctools
import random
import warcprox
import base64
import surt
import os
import hashlib

class RethinkCaptures:
    logger = logging.getLogger("warcprox.bigtables.RethinkCaptures")

    def __init__(self, r, table="captures", shards=None, replicas=None, options=warcprox.Options()):
        self.r = r
        self.table = table
        self.shards = shards or len(r.servers)
        self.replicas = replicas or min(3, len(r.servers))
        self.options = options
        self._ensure_db_table()

    def _ensure_db_table(self):
        dbs = self.r.db_list().run()
        if not self.r.dbname in dbs:
            self.logger.info("creating rethinkdb database %s", repr(self.r.dbname))
            self.r.db_create(self.r.dbname).run()
        tables = self.r.table_list().run()
        if not self.table in tables:
            self.logger.info("creating rethinkdb table %s in database %s", repr(self.table), repr(self.r.dbname))
            self.r.table_create(self.table, shards=self.shards, replicas=self.replicas).run()
            self.r.table(self.table).index_create("abbr_canon_surt_timesamp", [self.r.row["abbr_canon_surt"], self.r.row["timestamp"]]).run()
            self.r.table(self.table).index_create("sha1_warc_type", [self.r.row["sha1base32"], self.r.row["warc_type"], self.r.row["bucket"]]).run()

    def find_response_by_digest(self, algo, raw_digest, bucket="__unspecified__"):
        if algo != "sha1":
            raise Exception("digest type is {} but big capture table is indexed by sha1".format(algo))
        sha1base32 = base64.b32encode(raw_digest).decode("utf-8")
        results_iter = self.r.table(self.table).get_all([sha1base32, "response", bucket], index="sha1_warc_type").run()
        results = list(results_iter)
        if len(results) > 1:
            raise Exception("expected 0 or 1 but found %s results for sha1base32=%s", len(results), sha1base32)
        elif len(results) == 1:
            result = results[0]
        else:
            result = None
        self.logger.debug("returning %s for sha1base32=%s bucket=%s", result, sha1base32, bucket)
        return result

    def notify(self, recorded_url, records):
        if recorded_url.response_recorder:
            if recorded_url.response_recorder.payload_digest.name == "sha1":
                sha1base32 = base64.b32encode(recorded_url.response_recorder.payload_digest.digest()).decode("utf-8")
            else:
                self.logger.warn("digest type is %s but big capture table is indexed by sha1", recorded_url.response_recorder.payload_digest.name)
        else:
            digest = hashlib.new("sha1", records[0].content[1])
            sha1base32 = base64.b32encode(digest.digest()).decode("utf-8")

        if recorded_url.warcprox_meta and "captures-bucket" in recorded_url.warcprox_meta:
            bucket = recorded_url.warcprox_meta["captures-bucket"]
        else:
            bucket = "__unspecified__"

        canon_surt = surt.surt(recorded_url.url.decode("utf-8"),
            trailing_comma=True, host_massage=False, with_scheme=True)

        entry = {
            # id only specified for rethinkdb partitioning
            "id": "{} {}".format(canon_surt[:20], records[0].id.decode("utf-8")[10:-1]),
            "abbr_canon_surt": canon_surt[:150],
            "canon_surt": canon_surt,
            # "timestamp": re.sub(r"[^0-9]", "", records[0].date.decode("utf-8")),
            "timestamp": records[0].date.decode("utf-8"),
            "url": recorded_url.url.decode("utf-8"),
            "offset": records[0].offset,
            "filename": os.path.basename(records[0].warc_filename),
            "warc_type": records[0].type.decode("utf-8"),
            "warc_id": records[0].id.decode("utf-8"),
            "sha1base32": sha1base32,
            "content_type": recorded_url.mimetype,
            "response_code": recorded_url.status,
            "http_method": recorded_url.method,
            "bucket": bucket,
            "length": records[0].length,
        }

        result = self.r.table(self.table).insert(entry).run()
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
