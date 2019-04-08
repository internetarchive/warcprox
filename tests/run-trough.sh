#!/bin/bash
#
# this is used by .travis.yml
#

set -x

pip install git+https://github.com/nlevitt/snakebite.git@py3
pip install git+https://github.com/internetarchive/trough.git

mkdir /etc/trough

# hello docker user-defined bridge networking
echo '
HDFS_HOST: hadoop
RETHINKDB_HOSTS:
- rethinkdb
' > /etc/trough/settings.yml

sync.py >>/tmp/trough-sync-local.out 2>&1 &

sleep 5
python -c "
import doublethink
from trough.settings import settings
rr = doublethink.Rethinker(settings['RETHINKDB_HOSTS'])
rr.db('trough_configuration').wait().run()"

sync.py --server >>/tmp/trough-sync-server.out 2>&1 &
uwsgi --http :6222 --master --processes=2 --harakiri=240 --max-requests=50000 --vacuum --die-on-term --wsgi-file /usr/local/bin/writer.py >>/tmp/trough-write.out 2>&1 &
uwsgi --http :6112 --master --processes=2 --harakiri=20 --max-requests=50000 --vacuum --die-on-term --mount /=trough.wsgi.segment_manager:local >>/tmp/trough-segment-manager-local.out 2>&1 &
uwsgi --http :6111 --master --processes=2 --harakiri=20 --max-requests=50000 --vacuum --die-on-term --mount /=trough.wsgi.segment_manager:server >>/tmp/trough-segment-manager-server.out 2>&1 &
uwsgi --http :6444 --master --processes=2 --harakiri=3200 --socket-timeout=3200 --max-requests=50000 --vacuum --die-on-term --wsgi-file /usr/local/bin/reader.py >>/tmp/trough-read.out 2>&1 &

wait

