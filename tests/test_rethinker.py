import rethinkstuff
import logging
import sys
import types
import gc
import pytest
import rethinkdb
import time

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
        format="%(asctime)s %(process)d %(levelname)s %(threadName)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s")

class RethinkerForTesting(rethinkstuff.Rethinker):
    def __init__(self, *args, **kwargs):
        super(RethinkerForTesting, self).__init__(*args, **kwargs)

    def _random_server_connection(self):
        self.last_conn = super(RethinkerForTesting, self)._random_server_connection()
        # logging.info("self.last_conn=%s", self.last_conn)
        return self.last_conn

@pytest.fixture(scope="module")
def r():
    r = RethinkerForTesting()
    result = r.db_create("my_db").run()
    assert not r.last_conn.is_open()
    assert result["dbs_created"] == 1
    return RethinkerForTesting(db="my_db")

@pytest.fixture(scope="module")
def my_table(r):
    assert r.table_list().run() == []
    result = r.table_create("my_table").run()
    assert not r.last_conn.is_open()
    assert result["tables_created"] == 1

def test_rethinker(r, my_table):
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

def test_too_many_errors(r):
    with pytest.raises(rethinkdb.errors.ReqlOpFailedError):
        r.table_create("too_many_replicas", replicas=99).run()
    with pytest.raises(rethinkdb.errors.ReqlOpFailedError):
        r.table_create("too_many_shards", shards=99).run()

def test_slice(r, my_table):
    """Tests RethinkerWrapper.__getitem__()"""
    result = r.table("my_table")[5:10].run()
    assert r.last_conn.is_open() # should still be open this time
    assert isinstance(result, types.GeneratorType)
    n = 0
    for x in result:
        n += 1
        pass
    # connection should be closed after finished iterating over results
    assert not r.last_conn.is_open()
    assert n == 5

def test_svcreg(r):
    # import pdb; pdb.set_trace()
    svcreg = rethinkstuff.ServiceRegistry(r)
    assert svcreg.available_service("yes-such-role") == None
    svc0 = {
        "role": "yes-such-role",
        "load": 100.0,
        "heartbeat_interval": 0.2,
    }
    svc1 = {
        "role": "yes-such-role",
        "load": 200.0,
        "heartbeat_interval": 0.2,
    }
    svc0["id"] = svcreg.heartbeat(svc0)
    svc1["id"] = svcreg.heartbeat(svc1)
    assert svc0["id"] is not None
    assert svc1["id"] is not None
    assert svc0["id"] != svc1["id"]
    time.sleep(0.1)
    assert svcreg.available_service("no-such-role") == None
    assert svcreg.available_service("yes-such-role")["id"] == svc0["id"]

    svc1["load"] = 50.0
    svcreg.heartbeat(svc1)
    time.sleep(0.1)
    assert svcreg.available_service("no-such-role") == None
    assert svcreg.available_service("yes-such-role")["id"] == svc1["id"]

    svc1["load"] = 200.0
    svcreg.heartbeat(svc1)
    time.sleep(0.1)
    assert svcreg.available_service("no-such-role") == None
    assert svcreg.available_service("yes-such-role")["id"] == svc0["id"]
    svcreg.heartbeat(svc1)
    time.sleep(0.1)

    svcreg.heartbeat(svc1)
    time.sleep(0.4)
    assert svcreg.available_service("no-such-role") == None
    assert svcreg.available_service("yes-such-role")["id"] == svc1["id"]

    svcreg.unregister(svc1["id"])
    time.sleep(0.1)
    assert svcreg.available_service("no-such-role") == None
    assert svcreg.available_service("yes-such-role") == None

