#!/bin/bash

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

docker build -t internetarchive/warcprox-tests $script_dir || exit 1

uid=$(id -u)
user=$(id -un)

set -e

for python in python2.7 python3.4
do
	docker run --rm -i -t --volume="$script_dir/..:/warcprox" internetarchive/warcprox-tests /sbin/my_init -- \
		bash -x -c " adduser --gecos=$user --disabled-password --quiet --uid=$uid $user \
			&& sudo PYTHONDONTWRITEBYTECODE=1 -u $user bash -x -c 'cd /warcprox \
				&& virtualenv -p $python /tmp/venv \
				&& source /tmp/venv/bin/activate \
				&& pip --log-file /tmp/pip.log install . pytest requests \
				&& py.test -s tests \
				&& py.test -s --rethinkdb-servers=localhost tests \
				&& py.test -s --rethinkdb-servers=localhost --rethinkdb-big-table tests'"
done

