#
# Dockerfile for warcprox tests
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

FROM phusion/baseimage
MAINTAINER Noah Levitt <nlevitt@archive.org>

# see https://github.com/stuartpb/rethinkdb-dockerfiles/blob/master/trusty/2.1.3/Dockerfile
# and https://github.com/chali/hadoop-cdh-pseudo-docker/blob/master/Dockerfile

ENV LANG=C.UTF-8

RUN apt-get update && apt-get --auto-remove -y dist-upgrade

# Add the RethinkDB repository and public key
RUN curl -s https://download.rethinkdb.com/apt/pubkey.gpg | apt-key add - \
    && echo "deb http://download.rethinkdb.com/apt xenial main" > /etc/apt/sources.list.d/rethinkdb.list \
    && apt-get update && apt-get -y install rethinkdb

RUN mkdir -vp /etc/service/rethinkdb \
    && echo "#!/bin/bash\nexec rethinkdb --bind 0.0.0.0 --directory /tmp/rethink-data --runuser rethinkdb --rungroup rethinkdb\n" > /etc/service/rethinkdb/run \
    && chmod a+x /etc/service/rethinkdb/run

RUN apt-get -y install git
RUN apt-get -y install libpython2.7-dev libpython3-dev libffi-dev libssl-dev \
               python-setuptools python3-setuptools
RUN apt-get -y install gcc

RUN echo '57ff41e99cb01b6a1c2b0999161589b726f0ec8b  /tmp/pip-9.0.1.tar.gz' > /tmp/sha1sums.txt
RUN curl -sSL -o /tmp/pip-9.0.1.tar.gz https://pypi.python.org/packages/11/b6/abcb525026a4be042b486df43905d6893fb04f05aac21c32c638e939e447/pip-9.0.1.tar.gz
RUN sha1sum -c /tmp/sha1sums.txt
RUN tar -C /tmp -xf /tmp/pip-9.0.1.tar.gz
RUN cd /tmp/pip-9.0.1 && python3 setup.py install

RUN pip install virtualenv

RUN apt-get -y install tor
RUN mkdir -vp /etc/service/tor \
    && echo "#!/bin/sh\nexec tor\n" > /etc/service/tor/run \
    && chmod a+x /etc/service/tor/run

# hadoop hdfs for trough
RUN curl -s https://archive.cloudera.com/cdh5/ubuntu/xenial/amd64/cdh/archive.key | apt-key add - \
    && . /etc/lsb-release \
    && echo "deb [arch=amd64] http://archive.cloudera.com/cdh5/ubuntu/$DISTRIB_CODENAME/amd64/cdh $DISTRIB_CODENAME-cdh5 contrib" >> /etc/apt/sources.list.d/cloudera.list

RUN apt-get update
RUN apt-get install -y openjdk-8-jdk hadoop-conf-pseudo

RUN su hdfs -c 'hdfs namenode -format'

RUN mv -v /etc/hadoop/conf/core-site.xml /etc/hadoop/conf/core-site.xml.orig \
    && cat /etc/hadoop/conf/core-site.xml.orig | sed 's,localhost:8020,0.0.0.0:8020,' > /etc/hadoop/conf/core-site.xml

RUN mv -v /etc/hadoop/conf/hdfs-site.xml /etc/hadoop/conf/hdfs-site.xml.orig \
    && cat /etc/hadoop/conf/hdfs-site.xml.orig | sed 's,^</configuration>$,  <property>\n    <name>dfs.permissions.enabled</name>\n    <value>false</value>\n  </property>\n</configuration>,' > /etc/hadoop/conf/hdfs-site.xml

RUN echo '#!/bin/bash\nservice hadoop-hdfs-namenode start\nservice hadoop-hdfs-datanode start' > /etc/my_init.d/50_start_hdfs.sh \
    && chmod a+x /etc/my_init.d/50_start_hdfs.sh

RUN apt-get install -y libsqlite3-dev

# trough itself
RUN virtualenv -p python3 /opt/trough-ve3 \
    && . /opt/trough-ve3/bin/activate \
    && pip install git+https://github.com/nlevitt/snakebite.git@py3 \
    && pip install git+https://github.com/internetarchive/trough.git

RUN mkdir -vp /etc/service/trough-sync-local \
    && echo "#!/bin/bash\nsource /opt/trough-ve3/bin/activate\nexec sync.py >>/tmp/trough-sync-local.out 2>&1" > /etc/service/trough-sync-local/run \
    && chmod a+x /etc/service/trough-sync-local/run

RUN mkdir -vp /etc/service/trough-sync-server \
    && echo '#!/bin/bash\nsource /opt/trough-ve3/bin/activate\nsleep 5\npython -c $"import doublethink ; from trough.settings import settings ; rr = doublethink.Rethinker(settings[\"RETHINKDB_HOSTS\"]) ; rr.db(\"trough_configuration\").wait().run()"\nexec sync.py --server >>/tmp/trough-sync-server.out 2>&1' > /etc/service/trough-sync-server/run \
    && chmod a+x /etc/service/trough-sync-server/run

RUN mkdir -vp /etc/service/trough-read \
    && echo '#!/bin/bash\nvenv=/opt/trough-ve3\nsource $venv/bin/activate\nsleep 5\npython -c $"import doublethink ; from trough.settings import settings ; rr = doublethink.Rethinker(settings[\"RETHINKDB_HOSTS\"]) ; rr.db(\"trough_configuration\").wait().run()"\nexec uwsgi --venv=$venv --http :6444 --master --processes=2 --harakiri=3200 --socket-timeout=3200 --max-requests=50000 --vacuum --die-on-term --wsgi-file $venv/bin/reader.py >>/tmp/trough-read.out 2>&1' > /etc/service/trough-read/run \
    && chmod a+x /etc/service/trough-read/run

RUN mkdir -vp /etc/service/trough-write \
    && echo '#!/bin/bash\nvenv=/opt/trough-ve3\nsource $venv/bin/activate\nsleep 5\npython -c $"import doublethink ; from trough.settings import settings ; rr = doublethink.Rethinker(settings[\"RETHINKDB_HOSTS\"]) ; rr.db(\"trough_configuration\").wait().run()"\nexec uwsgi --venv=$venv --http :6222 --master --processes=2 --harakiri=240 --max-requests=50000 --vacuum --die-on-term --wsgi-file $venv/bin/writer.py >>/tmp/trough-write.out 2>&1' > /etc/service/trough-write/run \
    && chmod a+x /etc/service/trough-write/run

RUN mkdir -vp /etc/service/trough-segment-manager-local \
    && echo '#!/bin/bash\nvenv=/opt/trough-ve3\nsource $venv/bin/activate\nsleep 5\npython -c $"import doublethink ; from trough.settings import settings ; rr = doublethink.Rethinker(settings[\"RETHINKDB_HOSTS\"]) ; rr.db(\"trough_configuration\").wait().run()"\nexec uwsgi --venv=$venv --http :6112 --master --processes=2 --harakiri=7200 --http-timeout=7200 --max-requests=50000 --vacuum --die-on-term --mount /=trough.wsgi.segment_manager:local >>/tmp/trough-segment-manager-local.out 2>&1' > /etc/service/trough-segment-manager-local/run \
    && chmod a+x /etc/service/trough-segment-manager-local/run

RUN mkdir -vp /etc/service/trough-segment-manager-server \
    && echo '#!/bin/bash\nvenv=/opt/trough-ve3\nsource $venv/bin/activate\nsleep 5\npython -c $"import doublethink ; from trough.settings import settings ; rr = doublethink.Rethinker(settings[\"RETHINKDB_HOSTS\"]) ; rr.db(\"trough_configuration\").wait().run()"\nexec uwsgi --venv=$venv --http :6111 --master --processes=2 --harakiri=7200 --http-timeout=7200 --max-requests=50000 --vacuum --die-on-term --mount /=trough.wsgi.segment_manager:server >>/tmp/trough-segment-manager-server.out 2>&1' > /etc/service/trough-segment-manager-server/run \
    && chmod a+x /etc/service/trough-segment-manager-server/run

