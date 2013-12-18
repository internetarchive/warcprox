#!/usr/bin/env python

#from warcprox.bin import dump-anydbm
import pytest
import os
import subprocess # to access the script from shell

# will try as python 3 then default to python 2 modules
try: 
	import dbm
	ndbm = dbm.ndbm
	gdbm = dbm.gdbm
	dumb = dbm.dumb

	whichdb = dbm.whichdb

	ndbm_type = "dbm.ndbm"
	gdbm_type = "dbm.gdbm"
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
	test_db[key1] = val1
	test_db[key2] = val2
	test_db.close()
	def delete_test_dumbdbm():
		print "deleting", db_name
		os.remove(db_name+".dir")
		os.remove(db_name+".bak")
		os.remove(db_name+".dat")

	request.addfinalizer(delete_test_dumbdbm)
	return db_name

# def test_fixture(make_ndbm_test_db):
# 	print "runing test_fixture with"
# 	assert whichdb(make_ndbm_test_db) == "dbm"

def test_assert_gdbm_db_is_created_and_correctly_identified(make_gdbm_test_db):
	print "runing assert_gdbm_db_is_created_and_correctly_identified with gdbm test file"
	assert whichdb(make_gdbm_test_db) == gdbm_type

def test_assert_reading_gdbm_correctly(make_gdbm_test_db):
	print "running assert_reading_gdbm_correctly with gdbm test db"
	db = gdbm.open(make_gdbm_test_db, "r")
	assert len(db.keys()) == 2
	assert db.has_key(key1)
	assert db[key1] == val1

def test_assert_dumbdbm_db_is_created_and_correctly_identified(make_dumbdbm_test_db):
	print "runing assert_dumbdbm_db_is_created_and_correctly_identified with gdbm test file"
	assert whichdb(make_dumbdbm_test_db) == dumb_type

def test_assert_reading_dumbdbm_correctly(make_dumbdbm_test_db):
	print "running assert_reading_dumbdbm_correctly with dumbdbm test db"
	db = dumb.open(make_dumbdbm_test_db, "r")
	assert len(db.keys()) == 2
	assert db.has_key(key1)
	assert db[key1] == val1

def test_dumpanydbm_identify_gbdm(make_gdbm_test_db):
	print "running test_dumpanydbm_identify_gbdm"
	output = subprocess.check_output(["dump-anydbm", make_gdbm_test_db])
	output = output.strip().split("\n")
	assert len(output) == 3 # 2 keys plus whichdb line

	# split on space, then grab 4th word, which is db type
	which = output[0].split(' ')[3]
	print which
	assert which == gdbm_type

	#split remaining lines on ':' that separates key & value
	db_dump_first_pair = output[1].split(':')
	assert db_dump_first_pair[0] == key1
	assert db_dump_first_pair[1] == val1

	db_dump_second_pair = output[2].split(':')
	assert db_dump_second_pair[0] == key2
	assert db_dump_second_pair[1] == val2






