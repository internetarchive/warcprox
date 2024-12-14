"""
warcprox/bigtable.py - module for "big" RethinkDB table for deduplication;
the table is "big" in the sense that it is designed to be usable as an index
for playback software outside of warcprox, and contains information not
needed merely for deduplication

Copyright (C) 2015-2016 Internet Archive

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
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.
"""
import logging
import warcprox
import base64
import urlcanon
import os
import hashlib
import threading
import datetime
import doublethink
from rethinkdb import RethinkDB; r = RethinkDB()
from warcprox.dedup import DedupableMixin

class RethinkCaptures:
    """Inserts in batches every 0.5 seconds"""
    logger = logging.getLogger("warcprox.bigtable.RethinkCaptures")

    def __init__(self, options=warcprox.Options()):
        parsed = doublethink.parse_rethinkdb_url(
                options.rethinkdb_big_table_url)
        self.rr = doublethink.Rethinker(
                servers=parsed.hosts, db=parsed.database)
        self.table = parsed.table
        self.options = options
        self._ensure_db_table()

        self._stop = threading.Event()
        self._batch_lock = threading.RLock()
        with self._batch_lock:
            self._batch = []
        self._timer = None

    def start(self):
        """Starts batch insert repeating timer"""
        self._insert_batch()

    def _insert_batch(self):
        try:
            with self._batch_lock:
                if len(self._batch) > 0:
                    result = self.rr.table(self.table).insert(
                            self._batch, conflict="replace").run()
                    if (result["inserted"] + result["replaced"]
                            + result["unchanged"] != len(self._batch)):
                        raise Exception(
                                "unexpected result saving batch of %s: %s "
                                "entries" % (len(self._batch), result))
                    if result["replaced"] > 0 or result["unchanged"] > 0:
                        self.logger.warning(
                                "inserted=%s replaced=%s unchanged=%s in big "
                                "captures table (normally replaced=0 and "
                                "unchanged=0)", result["inserted"],
                                result["replaced"], result["unchanged"])
                    else:
                        self.logger.debug(
                                "inserted %s entries to big captures table",
                                len(self._batch))
                    self._batch = []
        except BaseException as e:
            self.logger.error(
                    "caught exception trying to save %s entries, they will "
                    "be included in the next batch", len(self._batch),
                    exc_info=True)
        finally:
            if not self._stop.is_set():
                t = threading.Timer(0.5, self._insert_batch)
                t.name = "RethinkCaptures-batch-insert-timer-%s" % datetime.datetime.utcnow().isoformat()
                t.start()
                # ensure self._timer joinable (already started) whenever
                # close() happens to be called
                self._timer = t
            else:
                self.logger.info("finished")

    def _ensure_db_table(self):
        dbs = self.rr.db_list().run()
        if not self.rr.dbname in dbs:
            self.logger.info("creating rethinkdb database %r", self.rr.dbname)
            self.rr.db_create(self.rr.dbname).run()
        tables = self.rr.table_list().run()
        if not self.table in tables:
            self.logger.info(
                    "creating rethinkdb table %r in database %r",
                    self.table, self.rr.dbname)
            self.rr.table_create(
                    self.table, shards=len(self.rr.servers),
                    replicas=min(3, len(self.rr.servers))).run()
            self.rr.table(self.table).index_create(
                    "abbr_canon_surt_timestamp",
                    [r.row["abbr_canon_surt"], r.row["timestamp"]]).run()
            self.rr.table(self.table).index_create("sha1_warc_type", [
                r.row["sha1base32"], r.row["warc_type"], r.row["bucket"]]).run()
            self.rr.table(self.table).index_wait().run()

    def find_response_by_digest(self, algo, raw_digest, bucket="__unspecified__"):
        if algo != "sha1":
            raise Exception(
                    "digest type is %r but big captures table is indexed by "
                    "sha1" % algo)
        sha1base32 = base64.b32encode(raw_digest).decode("utf-8")
        results_iter = self.rr.table(self.table).get_all(
                [sha1base32, "response", bucket],
                index="sha1_warc_type").filter(
                        r.row["dedup_ok"], default=True).run()
        results = list(results_iter)
        if len(results) > 0:
            if len(results) > 1:
                self.logger.debug(
                        "expected 0 or 1 but found %r results for "
                        "sha1base32=%r bucket=%r (will use first result)",
                        len(results), sha1base32, bucket)
            result = results[0]
        else:
            result = None
        self.logger.debug("returning %r for sha1base32=%r bucket=%r",
                          result, sha1base32, bucket)
        return result

    def _assemble_entry(self, recorded_url, records):
        if recorded_url.payload_digest:
            if recorded_url.payload_digest.name == "sha1":
                sha1base32 = base64.b32encode(
                        recorded_url.payload_digest.digest()
                        ).decode("utf-8")
            else:
                self.logger.warning(
                        "digest type is %r but big captures table is indexed "
                        "by sha1",
                        recorded_url.payload_digest.name)
        else:
            digest = hashlib.new("sha1", records[0].content[1])
            sha1base32 = base64.b32encode(digest.digest()).decode("utf-8")

        if (recorded_url.warcprox_meta
                and "dedup-buckets" in recorded_url.warcprox_meta):
            for bucket, bucket_mode in recorded_url.warcprox_meta["dedup-buckets"].items():
                if not bucket_mode == 'ro':
                    # maybe this is the right thing to do here? or should we return an entry for each? or ?
                    break
        else:
            bucket = "__unspecified__"

        canon_surt = urlcanon.semantic(recorded_url.url).surt().decode('ascii')

        entry = {
            # id only specified for rethinkdb partitioning
            "id": "{} {}".format(
                canon_surt[:20], records[0].id.decode("utf-8")[10:-1]),
            "abbr_canon_surt": canon_surt[:150],
            "canon_surt": canon_surt,
            "timestamp": recorded_url.timestamp.replace(
                tzinfo=doublethink.UTC),
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
            "record_length": records[0].length, # compressed (or not) length of
                                                # warc record including record
                                                # headers
            "wire_bytes": recorded_url.size, # count of bytes transferred over
                                             # the wire, including http headers
                                             # if any
        }

        if recorded_url.warcprox_meta:
            if "dedup-ok" in recorded_url.warcprox_meta:
                entry["dedup_ok"] = recorded_url.warcprox_meta["dedup-ok"]
            if "captures-table-extra-fields" in recorded_url.warcprox_meta:
                extras = recorded_url.warcprox_meta[
                        "captures-table-extra-fields"]
                for extra_field in extras:
                    entry[extra_field] = extras[extra_field]

        return entry

    def notify(self, recorded_url, records):
        if records:
            entry = self._assemble_entry(recorded_url, records)
            with self._batch_lock:
                self._batch.append(entry)

    def close(self):
        self.stop()

    def stop(self):
        self.logger.info("closing rethinkdb captures table")
        self._stop.set()
        if self._timer:
            self._timer.join()

class RethinkCapturesDedup(warcprox.dedup.DedupDb, DedupableMixin):
    logger = logging.getLogger("warcprox.dedup.RethinkCapturesDedup")

    def __init__(self, options=warcprox.Options()):
        DedupableMixin.__init__(self, options)
        self.captures_db = RethinkCaptures(options=options)
        self.options = options

    def lookup(self, digest_key, bucket="__unspecified__", url=None):
        k = digest_key.decode("utf-8") if isinstance(digest_key, bytes) else digest_key
        algo, value_str = k.split(":")
        if self.options.base32:
            raw_digest = base64.b32decode(value_str, casefold=True)
        else:
            raw_digest = base64.b16decode(value_str, casefold=True)
        entry = self.captures_db.find_response_by_digest(algo, raw_digest, bucket)
        if entry:
            dedup_info = {
                "url": entry["url"].encode("utf-8"),
                "date": entry["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ").encode("utf-8"),
            }
            if "warc_id" in entry:
                dedup_info["id"] = entry["warc_id"].encode("utf-8")
            return dedup_info
        else:
            return None

    def start(self):
        self.captures_db.start()

    def stop(self):
        self.captures_db.stop()

    def close(self):
        self.captures_db.close()

    def notify(self, recorded_url, records):
        self.captures_db.notify(recorded_url, records)
