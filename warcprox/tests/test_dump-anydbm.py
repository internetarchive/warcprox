#!/usr/bin/env python

import pytest
import os
import tempfile
import subprocess # to access the script from shell
import sys

# will try as python 3 then default to python 2 modules
try:
    import dbm
    from dbm import ndbm
    from dbm import gnu as gdbm
    from dbm import dumb

    whichdb = dbm.whichdb

    ndbm_type = b"dbm.ndbm"
    gdbm_type = b"dbm.gnu"
    dumb_type = b"dbm.dumb"

except:
    import dbm as ndbm
    import gdbm
    import dumbdbm as dumb

    from whichdb import whichdb

    ndbm_type = b"dbm"
    gdbm_type = b"gdbm"
    dumb_type = b"dumbdbm"

#global settings
key1 = 'very first key'
key2 = 'second key'
val1 = 'very first value'
val2 = 'second value'

py = sys.executable
dump_anydbm_loc = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "bin/dump-anydbm")

@pytest.fixture(scope="function")
def gdbm_test_db(request):
    print("creating test gdbm file")
    temp_file = tempfile.NamedTemporaryFile()
    test_db = gdbm.open(temp_file.name, "n")
    test_db[key1] = val1
    test_db[key2] = val2
    test_db.close()

    def delete_gdbm_test_db():
        print("deleting test gdbm file")
        temp_file.close()

    request.addfinalizer(delete_gdbm_test_db)
    return temp_file.name


@pytest.fixture(scope="function")
def ndbm_test_db(request):
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
def dumbdbm_test_db(request):
    print("creating test dumbdbm file")
    temp_file = tempfile.NamedTemporaryFile()
    test_db = dumb.open(temp_file.name, "n")
    test_db[key1] = val1
    test_db[key2] = val2
    test_db.close()

    def delete_dumbdbm_test_db():
        print("deleting test dumbdbm file")
        temp_file.close()
        os.remove(temp_file.name + ".dir")
        os.remove(temp_file.name + ".bak")
        os.remove(temp_file.name + ".dat")

    request.addfinalizer(delete_dumbdbm_test_db)
    return temp_file.name


def test_dumpanydbm_identify_gdbm(gdbm_test_db):
    print("running test_dumpanydbm_identify_gdbm")
    output = subprocess.check_output([py, dump_anydbm_loc, gdbm_test_db])
    print(b"script printout: ")
    print(output)
    print(b"check_one: ")
    print(gdbm_test_db.encode(encoding='UTF-8') + b' is a ' + gdbm_type + b' db\nvery first key:very first value\nsecond key:second value\n')

    assert (output == gdbm_test_db.encode(encoding='UTF-8') + b' is a ' + gdbm_type + b' db\nvery first key:very first value\nsecond key:second value\n' or
            output == gdbm_test_db.encode(encoding='UTF-8') + b' is a ' + gdbm_type + b' db\nsecond key:second value\nvery first key:very first value\n')


def test_dumpanydbm_identify_ndbm(ndbm_test_db):
    print("running test_dumpanydbm_identify_ndbm")
    output = subprocess.check_output([py, dump_anydbm_loc, ndbm_test_db])
    print(b"script printout: ")
    print(output)
    print(b"check_one: ")
    print(ndbm_test_db.encode(encoding='UTF-8') + b' is a ' + ndbm_type + b' db\nvery first key:very first value\nsecond key:second value\n')

    assert (output == ndbm_test_db.encode(encoding='UTF-8') + b' is a ' + ndbm_type + b' db\nvery first key:very first value\nsecond key:second value\n' or
            output == ndbm_test_db.encode(encoding='UTF-8') + b' is a ' + ndbm_type + b' db\nsecond key:second value\nvery first key:very first value\n')


def test_dumpanydbm_identify_dumbdbm(dumbdbm_test_db):
    print("running test_dumpanydbm_identify_dumbdbm")

    output = subprocess.check_output([py, dump_anydbm_loc, dumbdbm_test_db])
    print(b"script printout: ")
    print(output)
    print(b"check_one: ")
    print(dumbdbm_test_db.encode(encoding='UTF-8') + b' is a ' + dumb_type + b' db\nvery first key:very first value\nsecond key:second value\n')

    assert (output == dumbdbm_test_db.encode(encoding='UTF-8') + b' is a ' + dumb_type + b' db\nvery first key:very first value\nsecond key:second value\n' or
            output == dumbdbm_test_db.encode(encoding='UTF-8') + b' is a ' + dumb_type + b' db\nsecond key:second value\nvery first key:very first value\n')
