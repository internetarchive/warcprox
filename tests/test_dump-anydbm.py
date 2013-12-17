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



