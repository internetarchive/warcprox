#!/bin/bash
#
# Runs tests in a docker container. Also runs a temporary instance of rethinkdb
# inside the container. The tests run with rethinkdb features enabled, against
# that instance of rethinkdb, and also run without rethinkdb features enabled.
# With python 2.7 and 3.4.
#
# 😬
#

set -e

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker build -t internetarchive/warcprox-tests $script_dir

for python in python2.7 python3.4
do
    docker run --rm --volume="$script_dir/..:/warcprox" internetarchive/warcprox-tests /sbin/my_init -- \
        bash -x -c "cd /tmp && git clone /warcprox && cd /tmp/warcprox \
            && (cd /warcprox && git diff) | patch -p1 \
            && virtualenv -p $python /tmp/venv \
            && source /tmp/venv/bin/activate \
            && pip --log-file /tmp/pip.log install . pytest requests \
            && py.test -s tests \
            && py.test -s --rethinkdb-servers=localhost tests \
            && py.test -s --rethinkdb-servers=localhost --rethinkdb-big-table tests"
done

