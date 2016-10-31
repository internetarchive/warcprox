FROM phusion/baseimage
MAINTAINER Noah Levitt <nlevitt@archive.org>

# see https://github.com/stuartpb/rethinkdb-dockerfiles/blob/master/trusty/2.1.3/Dockerfile

ENV LANG=C.UTF-8

RUN apt-get update && apt-get --auto-remove -y dist-upgrade

# Add the RethinkDB repository and public key
# "RethinkDB Packaging <packaging@rethinkdb.com>" http://download.rethinkdb.com/apt/pubkey.gpg
RUN apt-key adv --keyserver pgp.mit.edu --recv-keys 1614552E5765227AEC39EFCFA7E00EF33A8F2399 \
    && . /etc/lsb-release \
    && echo "deb http://download.rethinkdb.com/apt $DISTRIB_CODENAME main" \
       > /etc/apt/sources.list.d/rethinkdb.list \
    && apt-get update && apt-get -y install rethinkdb

RUN mkdir -vp /etc/service/rethinkdb \
    && echo "#!/bin/sh\nrethinkdb --bind 0.0.0.0 --directory /tmp/rethink-data --runuser rethinkdb --rungroup rethinkdb\n" > /etc/service/rethinkdb/run \
    && chmod a+x /etc/service/rethinkdb/run

RUN apt-get -y install python-virtualenv git
RUN apt-get -y install python-gdbm python3-gdbm libpython2.7-dev libpython3-dev libffi-dev libssl-dev
