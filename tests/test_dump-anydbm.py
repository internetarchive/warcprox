#!/usr/bin/env python

#from warcprox.bin import dump-anydbm
import pytest
import os

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

@pytest.fixture(scope = "function")
def make_gdbm_test_db(request):
	db_name ="test_gdbm"
	print "creating", db_name
	test_db = gdbm.open(db_name, "n")
	test_db['very first key'] = 'very first value'
	test_db['second key'] = 'second value'
	test_db.close()
	def delete_test_dumbdbm():
		print "deleting", db_name
		os.remove(db_name)
		
	request.addfinalizer(delete_test_dumbdbm)
	return db_name

@pytest.fixture(scope = "function")
def make_dumbdbm_test_db(request):
	db_name ="test_dumbdbm"
	print "creating", db_name
	test_db = dumb.open(db_name, "n")
	test_db['very first key'] = 'very first value'
	test_db['second key'] = 'second value'
	test_db.close()
	def delete_test_dumbdbm():
		print "deleting", db_name
		os.remove(db_name+".dir")
		os.remove(db_name+".bak")
		os.remove(db_name+".dat")

	request.addfinalizer(delete_test_dumbdbm)
	return db_name+".dir"

def test_assert_gdbm_db_is_created_and_correctly_identified(make_gdbm_test_db):
	print "runing assert_gdbm_db_is_created_and_correctly_identified with gdbm test file"
	assert whichdb(make_gdbm_test_db) == "dbm.gdbm" or "gdbm"

def test_assert_reading_gdbm_correctly(make_gdbm_test_db):
	print "running assert_reading_gdbm_correctly with gdbm test db"
	db = gdbm.open(make_gdbm_test_db, "r")
	assert len(db.keys()) == 2
	assert db.has_key('very first key')
	assert db['very first key'] == 'very first value'

def test_assert_dumbdbm_db_is_created_and_correctly_identified(make_dumbdbm_test_db):
	print "runing assert_dumbdbm_db_is_created_and_correctly_identified with gdbm test file"
	assert whichdb(make_dumbdbm_test_db) == "dbm.dumb" or "dumbdbm"