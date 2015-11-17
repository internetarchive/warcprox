#!/bin/bash

set -e

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker build -t internetarchive/rethinkdb $script_dir

for python in python2.7 python3.4
do
    docker run --rm -it --volume="$script_dir/..:/rethinkstuff" internetarchive/rethinkdb /sbin/my_init -- \
        bash -x -c "cd /tmp && git clone /rethinkstuff \
                && cd /tmp/rethinkstuff \
                && (cd /rethinkstuff && git diff) | patch -p1 \
                && virtualenv -p $python /tmp/venv \
                && source /tmp/venv/bin/activate \
                && tail -20 tests/test_reth* \
                && pip install pytest . \
                && py.test -v -s tests"
done
