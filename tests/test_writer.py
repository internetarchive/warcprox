'''
tests/test_writer.py - warcprox warc writing tests

Copyright (C) 2017 Internet Archive

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

def lock_file(queue, filename):
    """Try to lock file and return 1 if successful, else return 0.
    It is necessary to run this method in a different process to test locking.
    """
    try:
        fi = open(filename, 'ab')
        fcntl.lockf(fi, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fi.close()
        queue.put('OBTAINED LOCK')
    except IOError:
        queue.put('FAILED TO OBTAIN LOCK')


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
        directory=dirname, no_warc_open_suffix=True, writer_threads=1))
    wwriter.write_records(recorded_url)
    warcs = [fn for fn in os.listdir(dirname) if fn.endswith('.warc')]
    assert warcs
    target_warc = os.path.join(dirname, warcs[0])
    # launch another process and try to lock WARC file
    queue = Queue()
    p = Process(target=lock_file, args=(queue, target_warc))
    p.start()
    p.join()
    assert queue.get() == 'FAILED TO OBTAIN LOCK'
    wwriter.close_writer()

    # locking must succeed after writer has closed the WARC file.
    p = Process(target=lock_file, args=(queue, target_warc))
    p.start()
    p.join()
    assert queue.get() == 'OBTAINED LOCK'

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

        wwt = warcprox.writerthread.WarcWriterProcessor(
                Options(prefix='-', writer_threads=1))
        wwt.inq = warcprox.TimestampedQueue(maxsize=1)
        wwt.outq = warcprox.TimestampedQueue(maxsize=1)
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
                Options(writer_threads=1, blackout_period=60, prefix='foo'))
        wwt.inq = warcprox.TimestampedQueue(maxsize=1)
        wwt.outq = warcprox.TimestampedQueue(maxsize=1)
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

        wwt = warcprox.writerthread.WarcWriterProcessor(
                Options(writer_threads=1))
        wwt.inq = warcprox.TimestampedQueue(maxsize=1)
        wwt.outq = warcprox.TimestampedQueue(maxsize=1)
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
        warc_filename='{timestamp17}_{prefix}_{timestamp14}_{serialno}',
        writer_threads=1))
    wwriter.write_records(recorded_url)
    warcs = [fn for fn in os.listdir(dirname)]
    assert warcs
    assert re.search(
            r'\d{17}_foo_\d{14}_00000.warc.open',
            wwriter._available_warcs.queue[0].path)
