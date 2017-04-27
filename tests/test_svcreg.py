'''
tests_rethinker.py - unit tests for doublethink

Copyright (C) 2015-2017 Internet Archive

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import doublethink
import logging
import sys
import types
import gc
import pytest
import rethinkdb as r
import time
import socket
import os
import datetime

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
        format="%(asctime)s %(process)d %(levelname)s %(threadName)s %(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s")

class RethinkerForTesting(doublethink.Rethinker):
    def __init__(self, *args, **kwargs):
        super(RethinkerForTesting, self).__init__(*args, **kwargs)

    def _random_server_connection(self):
        self.last_conn = super(RethinkerForTesting, self)._random_server_connection()
        # logging.info("self.last_conn=%s", self.last_conn)
        return self.last_conn

@pytest.fixture(scope="module")
def rr():
    rr = RethinkerForTesting()
    try:
        rr.db_drop("doublethink_test_db").run()
    except r.errors.ReqlOpFailedError:
        pass
    result = rr.db_create("doublethink_test_db").run()
    assert not rr.last_conn.is_open()
    assert result["dbs_created"] == 1
    return RethinkerForTesting(db="doublethink_test_db")

def test_leader_election(rr):
    svcreg = doublethink.ServiceRegistry(rr)
    assert svcreg.leader('example-role') == None
    # this raises an exception: no heartbeat_interval.
    with pytest.raises(Exception) as excinfo:
        svcreg.leader('example-role', default={})
    svc01 = {
        "role": "example-role",
        "load": 0.0,
        "heartbeat_interval": 0.4,
        "node": "test01.example.com"
    }
    svc02 = {
        "role": "example-role",
        "load": 0.0,
        "heartbeat_interval": 0.4,
        "node": "test02.example.com"
    }
    # register svc01. output should be svc01.
    output = svcreg.leader('example-role', default=svc01)
    assert output['node'] == svc01['node']
    # try to register svc02. Output should still be svc01.
    output = svcreg.leader('example-role', default=svc02)
    assert output['node'] == svc01['node']
    svcreg.unregister('example-role')

def test_service_registry(rr):
    svcreg = doublethink.ServiceRegistry(rr)
    # missing required fields
    with pytest.raises(Exception) as excinfo:
        svcreg.heartbeat({})
    with pytest.raises(Exception) as excinfo:
        svcreg.heartbeat({"role":"foo","load":1})
    with pytest.raises(Exception) as excinfo:
        svcreg.heartbeat({"role":"foo","heartbeat_interval":1.0})
    with pytest.raises(Exception) as excinfo:
        svcreg.heartbeat({"heartbeat_interval":1.0,"load":1})

    # invalid heartbeat interval (we accept anything for load and role)
    with pytest.raises(Exception) as excinfo:
        svcreg.heartbeat({"heartbeat_interval":-1,"role":"foo","load":1})
    with pytest.raises(Exception) as excinfo:
        svcreg.heartbeat({"heartbeat_interval":"strang","role":"foo","load":1})
    with pytest.raises(Exception) as excinfo:
        svcreg.heartbeat({"heartbeat_interval":[],"role":"foo","load":1})
    with pytest.raises(Exception) as excinfo:
        svcreg.heartbeat({"heartbeat_interval":[1],"role":"foo","load":1})
    with pytest.raises(Exception) as excinfo:
        svcreg.heartbeat({"heartbeat_interval":{},"role":"foo","load":1})
    with pytest.raises(Exception) as excinfo:
        svcreg.heartbeat({"heartbeat_interval":{1:2},"role":"foo","load":1})

    assert svcreg.available_service("yes-such-role") == None
    assert svcreg.available_services("yes-such-role") == []
    assert svcreg.available_services() == []
    svc0 = {
        "role": "yes-such-role",
        "load": 100.0,
        "heartbeat_interval": 0.4,
    }
    svc1 = {
        "role": "yes-such-role",
        "load": 200.0,
        "heartbeat_interval": 0.4,
    }
    svc0 = svcreg.heartbeat(svc0)
    svc1 = svcreg.heartbeat(svc1)
    assert "id" in svc0
    assert "id" in svc1
    assert svc0["id"] != svc1["id"]

    assert svc0["host"] == socket.gethostname()
    assert svc1["host"] == socket.gethostname()

    assert "pid" in svc0
    assert "pid" in svc1
    assert svc0["pid"] == os.getpid()
    assert svc1["pid"] == os.getpid()
    assert "first_heartbeat" in svc0
    assert "first_heartbeat" in svc1
    assert "last_heartbeat" in svc0
    assert "last_heartbeat" in svc1

    time.sleep(0.2)
    assert svcreg.available_service("no-such-role") == None
    assert svcreg.available_services("no-such-role") == []
    # svc0 has less load
    assert svcreg.available_service("yes-such-role")["id"] == svc0["id"]
    assert len(svcreg.available_services("yes-such-role")) == 2
    assert len(svcreg.available_services()) == 2

    svc1["load"] = 50.0
    svc1 = svcreg.heartbeat(svc1)
    time.sleep(0.2)
    assert svcreg.available_service("no-such-role") == None
    # now svc1 has less load
    assert svcreg.available_service("yes-such-role")["id"] == svc1["id"]
    assert len(svcreg.available_services("yes-such-role")) == 2
    assert len(svcreg.available_services()) == 2

    svc1["load"] = 200.0
    svc1 = svcreg.heartbeat(svc1)
    time.sleep(0.2)
    assert svcreg.available_service("no-such-role") == None
    # now svc0 has less load again
    assert svcreg.available_service("yes-such-role")["id"] == svc0["id"]
    assert len(svcreg.available_services("yes-such-role")) == 2
    assert len(svcreg.available_services()) == 2

    svc1 = svcreg.heartbeat(svc1)
    time.sleep(0.2)
    svc1 = svcreg.heartbeat(svc1)
    time.sleep(0.7)
    assert svcreg.available_service("no-such-role") == None
    # now it's been too long since the last heartbeat from svc0
    assert svcreg.available_service("yes-such-role")["id"] == svc1["id"]
    assert len(svcreg.available_services("yes-such-role")) == 1
    assert len(svcreg.available_services()) == 1

    svcreg.unregister(svc1["id"])
    time.sleep(0.2)
    assert svcreg.available_service("no-such-role") == None
    assert svcreg.available_service("yes-such-role") == None
    assert svcreg.available_services("yes-such-role") == []
    assert svcreg.available_services() == []

    svc0 = {
        "role": "yes-such-role",
        "load": 100.0,
        "heartbeat_interval": 0.4,
    }
    svc1 = {
        "role": "yes-such-role",
        "load": 200.0,
        "heartbeat_interval": 0.4,
    }
    svc0 = svcreg.heartbeat(svc0)
    svc1 = svcreg.heartbeat(svc1)
    assert len(svcreg.available_services("yes-such-role")) == 2
    assert len(svcreg.available_services()) == 2
    svcreg.unregister(svc0["id"])
    svcreg.unregister(svc1["id"])

    svc0 = {
        "role": "yes-such-role",
        "load": 100.0,
        "heartbeat_interval": 0.4,
    }
    svc1 = {
        "role": "yes-such-role",
        "load": 200.0,
        "heartbeat_interval": 0.4,
    }
    svc2 = {
        "role": "another-such-role",
        "load": 200.0,
        "heartbeat_interval": 0.4,
    }
    svc3 = {
        "role": "yet-another-such-role",
        "load": 200.0,
        "heartbeat_interval": 0.4,
    }
    svc0 = svcreg.heartbeat(svc0)
    svc1 = svcreg.heartbeat(svc1)
    svc2 = svcreg.heartbeat(svc2)
    svc3 = svcreg.heartbeat(svc3)
    assert len(svcreg.available_services("yes-such-role")) == 2
    assert len(svcreg.available_services()) == 4

def test_svcreg_heartbeat_server_down(rr):
    class MockRethinker:
        def table(self, *args, **kwargs):
            raise Exception('catch me if you can')

    class SortOfFakeServiceRegistry(doublethink.ServiceRegistry):
        def __init__(self, rethinker):
            self.rr = rethinker
            # self._ensure_table() # not doing this here

    # no such rethinkdb server
    rr = MockRethinker()
    svcreg = SortOfFakeServiceRegistry(rr)
    svc0 = {
        "role": "role-foo",
        "load": 100.0,
        "heartbeat_interval": 0.4,
    }
    # no exception thrown
    svc0 = svcreg.heartbeat(svc0)

    # check that status_info was *not* updated
    assert not 'id' in svc0
    assert not 'last_heartbeat' in svc0
    assert not 'first_heartbeat' in svc0
    assert not 'host' in svc0
    assert not 'pid' in svc0

