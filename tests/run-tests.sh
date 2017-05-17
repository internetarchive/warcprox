#!/bin/bash

set -e

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker build -t internetarchive/rethinkdb $script_dir

for python in python2.7 python3
do
    docker run --rm -it --volume="$script_dir/..:/doublethink" internetarchive/rethinkdb /sbin/my_init -- \
        bash -x -c "cd /tmp && git clone /doublethink \
                && cd /tmp/doublethink \
                && (cd /doublethink && git diff) | patch -p1 \
                && virtualenv -p $python /tmp/venv \
                && source /tmp/venv/bin/activate \
                && pip install pytest . \
                && py.test -v tests"
done
