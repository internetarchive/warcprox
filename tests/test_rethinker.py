import rethinkstuff
import logging
import sys
import types
import gc

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
        format="%(asctime)s %(process)d %(levelname)s %(threadName)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s")

class RethinkerForTesting(rethinkstuff.Rethinker):
    def __init__(self, *args, **kwargs):
        super(RethinkerForTesting, self).__init__(*args, **kwargs)

    def _random_server_connection(self):
        self.last_conn = super(RethinkerForTesting, self)._random_server_connection()
        # logging.info("self.last_conn=%s", self.last_conn)
        return self.last_conn

def test_rethinker():
    r = RethinkerForTesting()
    result = r.db_create("my_db").run()
    assert not r.last_conn.is_open()
    assert result["dbs_created"] == 1

    r = RethinkerForTesting(db="my_db")
    assert r.table_list().run() == []
    result = r.table_create("my_table").run()
    assert not r.last_conn.is_open()
    assert result["tables_created"] == 1

    assert r.table("my_table").index_create("foo").run() == {"created": 1}
    assert not r.last_conn.is_open()

    result = r.table("my_table").insert(({"foo":i,"bar":"repeat"*i} for i in range(2000))).run()
    assert not r.last_conn.is_open()
    assert len(result["generated_keys"]) == 2000
    assert result["inserted"] == 2000

    result = r.table("my_table").run()
    assert r.last_conn.is_open() # should still be open this time
    assert isinstance(result, types.GeneratorType)
    n = 0
    for x in result:
        n += 1
        pass
    # connection should be closed after finished iterating over results
    assert not r.last_conn.is_open()
    assert n == 2000

    result = r.table("my_table").run()
    assert r.last_conn.is_open() # should still be open this time
    assert isinstance(result, types.GeneratorType)
    next(result)
    result = None
    gc.collect()
    # connection should be closed after result is garbage-collected
    assert not r.last_conn.is_open()

    result = r.table("my_table").run()
    assert r.last_conn.is_open() # should still be open this time
    assert isinstance(result, types.GeneratorType)
    result = None
    gc.collect()
    # connection should be closed after result is garbage-collected
    assert not r.last_conn.is_open()

