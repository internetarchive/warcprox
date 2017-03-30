#!/bin/bash
#
# tests/run-tests.sh - Runs tests in a docker container. Also runs a temporary
# instance of rethinkdb inside the container. The tests run with rethinkdb
# features enabled, against that instance of rethinkdb, and also run without
# rethinkdb features enabled.  With python 2.7 and 3.4.
#
# tests/conftest.py - command line options for warcprox tests
#
# Copyright (C) 2015-2017 Internet Archive
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.
#
# 😬
#

set -e

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker build -t internetarchive/warcprox-tests $script_dir

for python in python2.7 python3
do
    docker run --rm --volume="$script_dir/..:/warcprox" internetarchive/warcprox-tests /sbin/my_init -- \
        bash -x -c "cd /tmp && git clone /warcprox && cd /tmp/warcprox \
            && (cd /warcprox && git diff HEAD) | patch -p1 \
            && virtualenv -p $python /tmp/venv \
            && source /tmp/venv/bin/activate \
            && pip --log-file /tmp/pip.log install . pytest requests \
            && py.test -vv tests \
            && py.test -vv --rethinkdb-servers=localhost tests \
            && py.test -vv --rethinkdb-servers=localhost --rethinkdb-big-table tests"
done

