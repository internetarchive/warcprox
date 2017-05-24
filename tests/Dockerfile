#
# Dockerfile for warcprox tests
#
# Copyright (C) 2015-2016 Internet Archive
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

ENV LANG=C.UTF-8

RUN apt-get update && apt-get --auto-remove -y dist-upgrade

# Add the RethinkDB repository and public key
# "RethinkDB Packaging <packaging@rethinkdb.com>" http://download.rethinkdb.com/apt/pubkey.gpg
RUN apt-key adv --keyserver pgp.mit.edu --recv-keys 1614552E5765227AEC39EFCFA7E00EF33A8F2399 \
    && echo "deb http://download.rethinkdb.com/apt xenial main" > /etc/apt/sources.list.d/rethinkdb.list \
    && apt-get update && apt-get -y install rethinkdb

RUN mkdir -vp /etc/service/rethinkdb \
    && echo "#!/bin/sh\nrethinkdb --bind 0.0.0.0 --directory /tmp/rethink-data --runuser rethinkdb --rungroup rethinkdb\n" > /etc/service/rethinkdb/run \
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
    && echo "#!/bin/sh\ntor\n" > /etc/service/tor/run \
    && chmod a+x /etc/service/tor/run

