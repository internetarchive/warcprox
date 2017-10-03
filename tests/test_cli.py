'''
test_cli.py - unit tests for doublethink CLI

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
import doublethink.cli
import logging
import sys
import pytest
import rethinkdb as r
import pkg_resources

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

def test_cli(capsys, rr):
    entrypoint = pkg_resources.get_entry_map(
            'doublethink')['console_scripts']['doublethink-purge-stale-services']
    callable = entrypoint.resolve()
    with pytest.raises(SystemExit) as exit:
        callable(['doublethink-purge-stale-services'])
    print(dir(exit))
    assert exit.value.code != 0
    out, err = capsys.readouterr()
    with pytest.raises(SystemExit) as exit:
        # this wrap with sys.exit matches what occurs in the generated command
        sys.exit(callable(['doublethink-purge-stale-services', '-d', 'test']))
    assert exit.value.code == 0
    out, err = capsys.readouterr()
