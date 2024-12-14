'''
tests/test_writer.py - warcprox warc writing tests

Copyright (C) 2017-2019 Internet Archive

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
USA.
'''

import os
import fcntl
from multiprocessing import Process, Queue
from datetime import datetime, timedelta
import pytest
import re
from warcprox.mitmproxy import ProxyingRecorder
from warcprox.warcproxy import RecordedUrl
from warcprox.writer import WarcWriter
from warcprox import Options
import time
import warcprox
import io
import tempfile
import logging
import hashlib
import queue
import sys

logging.basicConfig(
        stream=sys.stdout, level=logging.TRACE,
        format='%(asctime)s %(process)d %(levelname)s %(threadName)s '
        '%(name)s.%(funcName)s(%(filename)s:%(lineno)d) %(message)s')

def lock_file(q, filename):
    """Try to lock file and return 1 if successful, else return 0.
    It is necessary to run this method in a different process to test locking.
    """
    try:
        fi = open(filename, 'ab')
        fcntl.lockf(fi, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fi.close()
        q.put('OBTAINED LOCK')
    except OSError:
        q.put('FAILED TO OBTAIN LOCK')

def test_warc_writer_locking(tmpdir):
    """Test if WarcWriter is locking WARC files.
    When we don't have the .open suffix, WarcWriter locks the file and the
    external process trying to ``lock_file`` fails (result=0).
    """
    recorder = ProxyingRecorder(None, None, 'sha1', url='http://example.com')
    recorded_url = RecordedUrl(
            url='http://example.com', content_type='text/plain', status=200,
            client_ip='127.0.0.2', request_data=b'abc',
            response_recorder=recorder, remote_ip='127.0.0.3',
            timestamp=datetime.utcnow(), payload_digest=hashlib.sha1())

    dirname = os.path.dirname(str(tmpdir.mkdir('test-warc-writer')))
    wwriter = WarcWriter(Options(
        directory=dirname, no_warc_open_suffix=True))
    wwriter.write_records(recorded_url)
    warcs = [fn for fn in os.listdir(dirname) if fn.endswith('.warc')]
    assert warcs
    target_warc = os.path.join(dirname, warcs[0])
    # launch another process and try to lock WARC file
    q = Queue()
    p = Process(target=lock_file, args=(q, target_warc))
    p.start()
    p.join()
    assert q.get() == 'FAILED TO OBTAIN LOCK'
    wwriter.close()

    # locking must succeed after writer has closed the WARC file.
    p = Process(target=lock_file, args=(q, target_warc))
    p.start()
    p.join()
    assert q.get() == 'OBTAINED LOCK'

def wait(callback, timeout):
    start = time.time()
    while time.time() - start < timeout:
        if callback():
            return
        time.sleep(0.5)
    raise Exception('timed out waiting for %s to return truthy' % callback)

def test_special_dont_write_prefix():
    with tempfile.TemporaryDirectory() as tmpdir:
        logging.debug('cd %s', tmpdir)
        os.chdir(tmpdir)

        wwt = warcprox.writerthread.WarcWriterProcessor(Options(prefix='-'))
        wwt.inq = queue.Queue(maxsize=1)
        wwt.outq = queue.Queue(maxsize=1)
        try:
            wwt.start()
            # not to be written due to default prefix
            recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
            recorder.read()
            wwt.inq.put(RecordedUrl(
                url='http://example.com/no', content_type='text/plain',
                status=200, client_ip='127.0.0.2', request_data=b'abc',
                response_recorder=recorder, remote_ip='127.0.0.3',
                timestamp=datetime.utcnow(),
                payload_digest=recorder.block_digest))
            # to be written due to warcprox-meta prefix
            recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
            recorder.read()
            wwt.inq.put(RecordedUrl(
                url='http://example.com/yes', content_type='text/plain',
                status=200, client_ip='127.0.0.2', request_data=b'abc',
                response_recorder=recorder, remote_ip='127.0.0.3',
                timestamp=datetime.utcnow(),
                payload_digest=recorder.block_digest,
                warcprox_meta={'warc-prefix': 'normal-warc-prefix'}))
            recorded_url = wwt.outq.get(timeout=10)
            assert not recorded_url.warc_records
            recorded_url = wwt.outq.get(timeout=10)
            assert recorded_url.warc_records
            assert wwt.outq.empty()
        finally:
            wwt.stop.set()
            wwt.join()

        wwt = warcprox.writerthread.WarcWriterProcessor(
                Options(blackout_period=60, prefix='foo'))
        wwt.inq = queue.Queue(maxsize=1)
        wwt.outq = queue.Queue(maxsize=1)
        try:
            wwt.start()
            # to be written due to default prefix
            recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
            recorder.read()
            wwt.inq.put(RecordedUrl(
                url='http://example.com/yes', content_type='text/plain',
                status=200, client_ip='127.0.0.2', request_data=b'abc',
                response_recorder=recorder, remote_ip='127.0.0.3',
                timestamp=datetime.utcnow(),
                payload_digest=recorder.block_digest))
            # not to be written due to warcprox-meta prefix
            recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
            recorder.read()
            wwt.inq.put(RecordedUrl(
                url='http://example.com/no', content_type='text/plain',
                status=200, client_ip='127.0.0.2', request_data=b'abc',
                response_recorder=recorder, remote_ip='127.0.0.3',
                timestamp=datetime.utcnow(),
                payload_digest=recorder.block_digest,
                warcprox_meta={'warc-prefix': '-'}))
            recorded_url = wwt.outq.get(timeout=10)
            assert recorded_url.warc_records
            recorded_url = wwt.outq.get(timeout=10)
            assert not recorded_url.warc_records
            assert wwt.outq.empty()

            # test blackout_period option. Write first revisit record because
            # its outside the blackout_period (60). Do not write the second
            # because its inside the blackout_period.
            recorder = ProxyingRecorder(io.BytesIO(b'test1'), None)
            recorder.read()
            old = datetime.utcnow() - timedelta(0, 3600)
            ru = RecordedUrl(
                url='http://example.com/dup',
                content_type='text/plain',
                status=200, client_ip='127.0.0.2', request_data=b'abc',
                response_recorder=recorder, remote_ip='127.0.0.3',
                timestamp=datetime.utcnow(),
                payload_digest=recorder.block_digest)
            ru.dedup_info = dict(id=b'1', url=b'http://example.com/dup',
                                 date=old.strftime('%Y-%m-%dT%H:%M:%SZ').encode('utf-8'))
            wwt.inq.put(ru)
            recorded_url = wwt.outq.get(timeout=10)
            recorder = ProxyingRecorder(io.BytesIO(b'test2'), None)
            recorder.read()
            recent = datetime.utcnow() - timedelta(0, 5)
            ru = RecordedUrl(
                url='http://example.com/dup', content_type='text/plain',
                status=200, client_ip='127.0.0.2', request_data=b'abc',
                response_recorder=recorder, remote_ip='127.0.0.3',
                timestamp=datetime.utcnow(),
                payload_digest=recorder.block_digest)
            ru.dedup_info = dict(id=b'2', url=b'http://example.com/dup',
                                 date=recent.strftime('%Y-%m-%dT%H:%M:%SZ').encode('utf-8'))
            wwt.inq.put(ru)
            assert recorded_url.warc_records
            recorded_url = wwt.outq.get(timeout=10)
            assert not recorded_url.warc_records
            assert wwt.outq.empty()

        finally:
            wwt.stop.set()
            wwt.join()

def test_do_not_archive():
    with tempfile.TemporaryDirectory() as tmpdir:
        logging.debug('cd %s', tmpdir)
        os.chdir(tmpdir)

        wwt = warcprox.writerthread.WarcWriterProcessor()
        wwt.inq = queue.Queue(maxsize=1)
        wwt.outq = queue.Queue(maxsize=1)
        try:
            wwt.start()
            # to be written -- default do_not_archive False
            recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
            recorder.read()
            wwt.inq.put(RecordedUrl(
                url='http://example.com/yes', content_type='text/plain',
                status=200, client_ip='127.0.0.2', request_data=b'abc',
                response_recorder=recorder, remote_ip='127.0.0.3',
                timestamp=datetime.utcnow(),
                payload_digest=recorder.block_digest))
            # not to be written -- do_not_archive set True
            recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
            recorder.read()
            wwt.inq.put(RecordedUrl(
                url='http://example.com/no', content_type='text/plain',
                status=200, client_ip='127.0.0.2', request_data=b'abc',
                response_recorder=recorder, remote_ip='127.0.0.3',
                timestamp=datetime.utcnow(),
                payload_digest=recorder.block_digest,
                warcprox_meta={'warc-prefix': '-'},
                do_not_archive=True))
            recorded_url = wwt.outq.get(timeout=10)
            assert recorded_url.warc_records
            recorded_url = wwt.outq.get(timeout=10)
            assert not recorded_url.warc_records
            assert wwt.outq.empty()
        finally:
            wwt.stop.set()
            wwt.join()

def test_warc_writer_filename(tmpdir):
    """Test if WarcWriter is writing WARC files with custom filenames.
    """
    recorder = ProxyingRecorder(None, None, 'sha1', url='http://example.com')
    recorded_url = RecordedUrl(
            url='http://example.com', content_type='text/plain', status=200,
            client_ip='127.0.0.2', request_data=b'abc',
            response_recorder=recorder, remote_ip='127.0.0.3',
            timestamp=datetime.utcnow(), payload_digest=hashlib.sha1())

    dirname = os.path.dirname(str(tmpdir.mkdir('test-warc-writer')))
    wwriter = WarcWriter(Options(directory=dirname, prefix='foo',
        warc_filename='{timestamp17}_{prefix}_{timestamp14}_{serialno}'))
    wwriter.write_records(recorded_url)
    warcs = [fn for fn in os.listdir(dirname)]
    assert warcs
    assert re.search(
            r'\d{17}_foo_\d{14}_00000.warc.open', wwriter.path)

def test_close_for_prefix(tmpdir):
    wwp = warcprox.writerthread.WarcWriterProcessor(
            Options(directory=str(tmpdir)))
    wwp.inq = queue.Queue(maxsize=1)
    wwp.outq = queue.Queue(maxsize=1)

    try:
        wwp.start()

        # write a record to the default prefix
        recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
        recorder.read()
        wwp.inq.put(RecordedUrl(
            url='http://example.com/1', content_type='text/plain',
            status=200, client_ip='127.0.0.2', request_data=b'abc',
            response_recorder=recorder, remote_ip='127.0.0.3',
            timestamp=datetime.utcnow(),
            payload_digest=recorder.block_digest))
        time.sleep(0.5)
        rurl = wwp.outq.get() # wait for it to finish

        assert rurl.url == b'http://example.com/1'
        assert len(tmpdir.listdir()) == 1
        assert tmpdir.listdir()[0].basename.startswith('warcprox-')
        assert tmpdir.listdir()[0].basename.endswith('-00000.warc.open')
        assert tmpdir.listdir()[0].basename == wwp.writer_pool.default_warc_writer.finalname + '.open'

        # request close of default warc
        wwp.close_for_prefix()

        # write a record to some other prefix
        recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
        recorder.read()
        wwp.inq.put(RecordedUrl(
            url='http://example.com/2', content_type='text/plain',
            status=200, client_ip='127.0.0.2', request_data=b'abc',
            response_recorder=recorder, remote_ip='127.0.0.3',
            timestamp=datetime.utcnow(),
            payload_digest=recorder.block_digest,
            warcprox_meta={'warc-prefix': 'some-prefix'}))
        time.sleep(0.5)
        rurl = wwp.outq.get() # wait for it to finish

        assert rurl.url == b'http://example.com/2'
        assert len(tmpdir.listdir()) == 2
        basenames = sorted(f.basename for f in tmpdir.listdir())
        assert basenames[0].startswith('some-prefix-')
        assert basenames[0].endswith('-00000.warc.open')
        assert basenames[1].startswith('warcprox-')
        assert basenames[1].endswith('-00000.warc')

        # request close of warc with prefix
        wwp.close_for_prefix('some-prefix')

        # write another record to the default prefix
        recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
        recorder.read()
        wwp.inq.put(RecordedUrl(
            url='http://example.com/3', content_type='text/plain',
            status=200, client_ip='127.0.0.2', request_data=b'abc',
            response_recorder=recorder, remote_ip='127.0.0.3',
            timestamp=datetime.utcnow(),
            payload_digest=recorder.block_digest))
        time.sleep(0.5)
        rurl = wwp.outq.get() # wait for it to finish

        assert rurl.url == b'http://example.com/3'
        # now some-prefix warc is closed and a new default prefix warc is open
        basenames = sorted(f.basename for f in tmpdir.listdir())
        assert len(basenames) == 3
        assert basenames[0].startswith('some-prefix-')
        assert basenames[0].endswith('-00000.warc')
        assert basenames[1].startswith('warcprox-')
        assert basenames[1].endswith('-00000.warc')
        assert basenames[2].startswith('warcprox-')
        assert basenames[2].endswith('-00001.warc.open')

        # write another record to with prefix "some-prefix"
        recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
        recorder.read()
        wwp.inq.put(RecordedUrl(
            url='http://example.com/4', content_type='text/plain',
            status=200, client_ip='127.0.0.2', request_data=b'abc',
            response_recorder=recorder, remote_ip='127.0.0.3',
            timestamp=datetime.utcnow(),
            payload_digest=recorder.block_digest,
            warcprox_meta={'warc-prefix': 'some-prefix'}))
        time.sleep(0.5)
        rurl = wwp.outq.get() # wait for it to finish

        assert rurl.url == b'http://example.com/4'
        # new some-prefix warc will have a new random token and start over at
        # serial 00000
        basenames = sorted(f.basename for f in tmpdir.listdir())
        assert len(basenames) == 4
        assert basenames[0].startswith('some-prefix-')
        assert basenames[1].startswith('some-prefix-')
        # order of these two warcs depends on random token so we don't know
        # which is which
        assert basenames[0][-5:] != basenames[1][-5:]
        assert '-00000.' in basenames[0]
        assert '-00000.' in basenames[1]

        assert basenames[2].startswith('warcprox-')
        assert basenames[2].endswith('-00000.warc')
        assert basenames[3].startswith('warcprox-')
        assert basenames[3].endswith('-00001.warc.open')

    finally:
        wwp.stop.set()
        wwp.join()
