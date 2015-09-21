import rethinkstuff
import logging
import sys
import types

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
        format="%(asctime)s %(process)d %(levelname)s %(threadName)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s")

def test_rethinker():
    r = rethinkstuff.Rethinker()
    result = r.db_create("my_db").run()
    assert result["dbs_created"] == 1

    r = rethinkstuff.Rethinker(db="my_db")
    assert r.table_list().run() == []
    result = r.table_create("my_table").run()
    assert result["tables_created"] == 1

    assert r.table("my_table").index_create("foo").run() == {"created": 1}

    result = r.table("my_table").insert(({"foo":i,"bar":"repeat"*i} for i in range(2000))).run()
    assert len(result["generated_keys"]) == 2000
    assert result["inserted"] == 2000

    result = r.table("my_table").run()
    assert isinstance(result, types.GeneratorType)

