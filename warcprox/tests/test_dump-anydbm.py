#!/usr/bin/env python

import pytest
import os
import tempfile
import subprocess # to access the script from shell

# will try as python 3 then default to python 2 modules
try:
    import dbm
    from dbm import ndbm
    from dbm import gnu as gdbm
    from dbm import dumb

    whichdb = dbm.whichdb

    ndbm_type = "dbm.ndbm"
    gdbm_type = "dbm.gnu"
    dumb_type = "dbm.dumb"

except:
    import dbm as ndbm
    import gdbm
    import dumbdbm as dumb

    from whichdb import whichdb

    ndbm_type = "dbm"
    gdbm_type = "gdbm"
    dumb_type = "dumbdbm"

#global settings
key1 = 'very first key'
key2 = 'second key'
val1 = 'very first value'
val2 = 'second value'
dump_anydbm = "dump-anydbm"


@pytest.fixture(scope="function")
def make_gdbm_test_db(request):
    print("creating test gdbm file")
    temp_file = tempfile.NamedTemporaryFile()
    test_db = gdbm.open(temp_file.name, "n")
    test_db[key1] = val1
    test_db[key2] = val2
    test_db.close()

    def delete_test_dumbdbm():
        print("deleting test gdbm file")
        temp_file.close()

    request.addfinalizer(delete_test_dumbdbm)
    return temp_file.name


@pytest.fixture(scope="function")
def make_ndbm_test_db(request):
    print("creating test ndbm file")
    temp_file = tempfile.NamedTemporaryFile()
    test_db = ndbm.open(temp_file.name, "n")
    test_db[key1] = val1
    test_db[key2] = val2
    test_db.close()

    def delete_test_ndbm():
        print("deleting test ndbm file")
        temp_file.close()
        os.remove(temp_file.name + ".db")

    request.addfinalizer(delete_test_ndbm)
    return temp_file.name


@pytest.fixture(scope="function")
def make_dumbdbm_test_db(request):
    print("creating test dumbdbm file")
    temp_file = tempfile.NamedTemporaryFile()
    test_db = dumb.open(temp_file.name, "n")
    test_db[key1] = val1
    test_db[key2] = val2
    test_db.close()

    def delete_test_dumbdbm():
        print("deleting test dumbdbm file")
        temp_file.close()
        os.remove(temp_file.name + ".dir")
        os.remove(temp_file.name + ".bak")
        os.remove(temp_file.name + ".dat")

    request.addfinalizer(delete_test_dumbdbm)
    return temp_file.name


def test_dumpanydbm_identify_gdbm(make_gdbm_test_db):
    print("running test_dumpanydbm_identify_gdbm")
    output = subprocess.check_output([dump_anydbm, make_gdbm_test_db])
    print(b"script printout: \n" + output)

    assert (output == make_gdbm_test_db.encode(encoding='UTF-8') + b' is a ' + gdbm_type.encode(encoding='UTF-8') + b' db\nvery first key:very first value\nsecond key:second value\n' or
            output == make_gdbm_test_db.encode(encoding='UTF-8') + b' is a ' + gdbm_type.encode(encoding='UTF-8') + b' db\nsecond key:second value\nvery first key:very first value\n')


def test_dumpanydbm_identify_ndbm(make_ndbm_test_db):
    print("running test_dumpanydbm_identify_ndbm")
    output = subprocess.check_output([dump_anydbm, make_ndbm_test_db])
    print(b"script printout: \n" + output)

    assert (output == make_ndbm_test_db.encode(encoding='UTF-8') + b' is a ' + ndbm_type.encode(encoding='UTF-8') + b' db\nvery first key:very first value\nsecond key:second value\n' or
            output == make_ndbm_test_db.encode(encoding='UTF-8') + b' is a ' + ndbm_type.encode(encoding='UTF-8') + b' db\nsecond key:second value\nvery first key:very first value\n')


def test_dumpanydbm_identify_dumbdbm(make_dumbdbm_test_db):
    print("running test_dumpanydbm_identify_dumbdbm")
    output = subprocess.check_output([dump_anydbm, make_dumbdbm_test_db])
    print(b"script printout: \n" + output)

    assert (output == make_dumbdbm_test_db.encode(encoding='UTF-8') + b' is a ' + dumb_type.encode(encoding='UTF-8') + b' db\nvery first key:very first value\nsecond key:second value\n' or
            output == make_dumbdbm_test_db.encode(encoding='UTF-8') + b' is a ' + dumb_type.encode(encoding='UTF-8') + b' db\nsecond key:second value\nvery first key:very first value\n')
