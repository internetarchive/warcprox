#!/bin/bash
#
# tests/run-tests.sh - Runs tests in a docker container. Also runs a temporary
# instance of rethinkdb inside the container. The tests run with rethinkdb
# features enabled, against that instance of rethinkdb, and also run without
# rethinkdb features enabled.  With python 2.7 and 3.4.
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

docker run --rm --volume="$script_dir/..:/warcprox" internetarchive/warcprox-tests \
    bash -x -c "cd /tmp && git clone /warcprox && cd /tmp/warcprox \
        && (cd /warcprox && git diff HEAD) | patch -p1 \
        && virtualenv -p python3 /tmp/venv \
        && source /tmp/venv/bin/activate \
        && pip --log-file /tmp/pip.log install . pytest mock requests warcio trough \
        && py.test -v tests; \
	svscan /etc/service & \
	sleep 10; \
        py.test -v --rethinkdb-dedup-url=rethinkdb://localhost/test1/dedup tests \
        && py.test -v --rethinkdb-big-table-url=rethinkdb://localhost/test2/captures tests \
	&& /usr/local/hadoop/hadoop-services.sh \
        && py.test -v --rethinkdb-trough-db-url=rethinkdb://localhost/trough_configuration tests \
        "

