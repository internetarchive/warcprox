#!/usr/bin/env python

#from warcprox.bin import dump-anydbm
import pytest

# will try as python 3 then default to python 2 modules
try: 
	import dbm
	ndbm = dbm.ndbm
	gdbm = dbm.gdbm
	dumb = dbm.dumb
	whichdb = dbm.whichdb
except:
	import dbm as ndbm
	import gdbm
	import dumbdbm as dumb
	from whichdb import whichdb

@pytest.fixture
def make_gdbm_test_db():
	db_name ="test_gdbm"
	print "creating", db_name
	test_db = gdbm.open(db_name, "n")
	test_db['very first key'] = 'very first value'
	test_db['second key'] = 'second value'
	test_db.close()
	return db_name

def test_assert_gdbm_db_is_created_and_correctly_identified(make_gdbm_test_db):
	print "runing assert_gdbm_db_is_created_and_correctly_identified with gdbm test file"
	assert whichdb(make_gdbm_test_db) == "dbm.gdbm" or "gdbm"