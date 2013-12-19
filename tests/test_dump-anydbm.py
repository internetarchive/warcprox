#!/usr/bin/env python

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
	test_db[key1] = val1
	test_db[key2] = val2
	test_db.close()
	def delete_test_dumbdbm():
		print "deleting", db_name
		os.remove(db_name)

	request.addfinalizer(delete_test_dumbdbm)
	return db_name

@pytest.fixture(scope = "function")
def make_ndbm_test_db(request):
	db_name = "test_ndbm"
	print "creating", db_name
	test_db = ndbm.open(db_name, "n")
	test_db[key1] = val1
	test_db[key2] = val2
	test_db.close()
	def delete_test_ndbm():
		print "deleting", db_name
		os.remove(db_name+".db")

	request.addfinalizer(delete_test_ndbm)
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

def test_dumpanydbm_identify_gdbm(make_gdbm_test_db):
	print "running test_dumpanydbm_identify_gdbm"
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

def test_dumpanydbm_identify_ndbm(make_ndbm_test_db):
	print "running test_dumpanydbm_identify_ndbm"
	output = subprocess.check_output(["dump-anydbm", make_ndbm_test_db])
	output = output.strip().split("\n")

	assert len(output) == 3 # 2 keys plus whichdb line

	# split on space, then grab 4th word, which is db type
	which = output[0].split(' ')[3]
	print which
	assert which == ndbm_type

	#split remaining lines on ':' that separates key & value
	db_dump_first_pair = output[1].split(':')
	assert db_dump_first_pair[0] == key1
	assert db_dump_first_pair[1] == val1

	db_dump_second_pair = output[2].split(':')
	assert db_dump_second_pair[0] == key2
	assert db_dump_second_pair[1] == val2

def test_dumpanydbm_identify_dumbdbm(make_dumbdbm_test_db):
	print "running test_dumpanydbm_identify_dumbdbm"
	output = subprocess.check_output(["dump-anydbm", make_dumbdbm_test_db])
	output = output.strip().split("\n")
	assert len(output) == 3 # 2 keys plus whichdb line

	# split on space, then grab 4th word, which is db type
	which = output[0].split(' ')[3]
	print which
	assert which == dumb_type

	#split remaining lines on ':' that separates key & value
	db_dump_first_pair = output[1].split(':')
	assert db_dump_first_pair[0] == key1
	assert db_dump_first_pair[1] == val1

	db_dump_second_pair = output[2].split(':')
	assert db_dump_second_pair[0] == key2
	assert db_dump_second_pair[1] == val2


