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

FROM ubuntu:focal-20220404
MAINTAINER Noah Levitt <nlevitt@archive.org>

# see https://github.com/stuartpb/rethinkdb-dockerfiles/blob/master/trusty/2.1.3/Dockerfile
# and https://github.com/chali/hadoop-cdh-pseudo-docker/blob/master/Dockerfile

ENV LANG=C.UTF-8

RUN apt-get update && apt-get --auto-remove -y dist-upgrade
RUN apt-get install -y ca-certificates curl gnupg wget

# Add the RethinkDB repository and public key
RUN curl -Ss https://download.rethinkdb.com/repository/raw/pubkey.gpg | apt-key add - 
RUN echo "deb https://download.rethinkdb.com/repository/ubuntu-focal focal main" > /etc/apt/sources.list.d/rethinkdb.list \
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

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
RUN apt-get install -y openjdk-8-jdk openssh-server 

# set java home
ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64

# setup ssh with no passphrase
RUN ssh-keygen -t rsa -f $HOME/.ssh/id_rsa -P "" \
    && cat $HOME/.ssh/id_rsa.pub >> $HOME/.ssh/authorized_keys

RUN wget -O /hadoop-2.7.3.tar.gz -q https://archive.apache.org/dist/hadoop/common/hadoop-2.7.3/hadoop-2.7.3.tar.gz \
        && tar xfz hadoop-2.7.3.tar.gz \
        && mv /hadoop-2.7.3 /usr/local/hadoop \
        && rm /hadoop-2.7.3.tar.gz
	
# hadoop environment variables
ENV HADOOP_HOME=/usr/local/hadoop
ENV PATH=$PATH:$HADOOP_HOME/bin:$HADOOP_HOME/sbin

# hadoop-store
RUN mkdir -p $HADOOP_HOME/hdfs/namenode \
        && mkdir -p $HADOOP_HOME/hdfs/datanode

# Temporary files: http://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch03s18.html
COPY config/ /tmp/
RUN mv /tmp/ssh_config $HOME/.ssh/config \
    && mv /tmp/hadoop-env.sh $HADOOP_HOME/etc/hadoop/hadoop-env.sh \
    && mv /tmp/core-site.xml $HADOOP_HOME/etc/hadoop/core-site.xml \
    && mv /tmp/hdfs-site.xml $HADOOP_HOME/etc/hadoop/hdfs-site.xml \
    && mv /tmp/mapred-site.xml $HADOOP_HOME/etc/hadoop/mapred-site.xml.template \
    && cp $HADOOP_HOME/etc/hadoop/mapred-site.xml.template $HADOOP_HOME/etc/hadoop/mapred-site.xml \
    && mv /tmp/yarn-site.xml $HADOOP_HOME/etc/hadoop/yarn-site.xml

# Add startup script
ADD config/hadoop-services.sh $HADOOP_HOME/hadoop-services.sh

# set permissions
RUN chmod 744 -R $HADOOP_HOME

# format namenode
RUN $HADOOP_HOME/bin/hdfs namenode -format

# run hadoop services
#ENTRYPOINT $HADOOP_HOME/hadoop-services.sh; bash

RUN apt-get install -y libsqlite3-dev build-essential

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

RUN apt-get install -y daemontools daemontools-run
