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
from datetime import datetime
import pytest
from warcprox.mitmproxy import ProxyingRecorder
from warcprox.warcproxy import RecordedUrl
from warcprox.writer import WarcWriter
from warcprox import Options
import time
import warcprox
import io
import tempfile
import logging

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
            timestamp=datetime.utcnow())

    dirname = os.path.dirname(str(tmpdir.mkdir('test-warc-writer')))
    wwriter = WarcWriter(Options(directory=dirname, no_warc_open_suffix=True))
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
    class NotifyMe:
        def __init__(self):
            self.the_list = []
        def notify(self, recorded_url, records):
            self.the_list.append((recorded_url, records))

    with tempfile.TemporaryDirectory() as tmpdir:
        logging.debug('cd %s', tmpdir)
        os.chdir(tmpdir)

        q = warcprox.TimestampedQueue(maxsize=1)
        listener = NotifyMe()
        wwt = warcprox.writerthread.WarcWriterThread(
                recorded_url_q=q, options=Options(prefix='-'),
                listeners=[listener])
        try:
            wwt.start()
            # not to be written due to default prefix
            recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
            recorder.read()
            q.put(RecordedUrl(
                url='http://example.com/no', content_type='text/plain',
                status=200, client_ip='127.0.0.2', request_data=b'abc',
                response_recorder=recorder, remote_ip='127.0.0.3',
                timestamp=datetime.utcnow(),
                payload_digest=recorder.block_digest))
            # to be written due to warcprox-meta prefix
            recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
            recorder.read()
            q.put(RecordedUrl(
                url='http://example.com/yes', content_type='text/plain',
                status=200, client_ip='127.0.0.2', request_data=b'abc',
                response_recorder=recorder, remote_ip='127.0.0.3',
                timestamp=datetime.utcnow(),
                payload_digest=recorder.block_digest,
                warcprox_meta={'warc-prefix': 'normal-warc-prefix'}))
            wait(lambda: len(listener.the_list) == 2, 10.0)
            assert not listener.the_list[0][1]
            assert listener.the_list[1][1]
        finally:
            wwt.stop.set()
            wwt.join()

        q = warcprox.TimestampedQueue(maxsize=1)
        listener = NotifyMe()
        wwt = warcprox.writerthread.WarcWriterThread(
                recorded_url_q=q, listeners=[listener])
        try:
            wwt.start()
            # to be written due to default prefix
            recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
            recorder.read()
            q.put(RecordedUrl(
                url='http://example.com/yes', content_type='text/plain',
                status=200, client_ip='127.0.0.2', request_data=b'abc',
                response_recorder=recorder, remote_ip='127.0.0.3',
                timestamp=datetime.utcnow(),
                payload_digest=recorder.block_digest))
            # not to be written due to warcprox-meta prefix
            recorder = ProxyingRecorder(io.BytesIO(b'some payload'), None)
            recorder.read()
            q.put(RecordedUrl(
                url='http://example.com/no', content_type='text/plain',
                status=200, client_ip='127.0.0.2', request_data=b'abc',
                response_recorder=recorder, remote_ip='127.0.0.3',
                timestamp=datetime.utcnow(),
                payload_digest=recorder.block_digest,
                warcprox_meta={'warc-prefix': '-'}))
            wait(lambda: len(listener.the_list) == 2, 10.0)
            assert listener.the_list[0][1]
            assert not listener.the_list[1][1]
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
            timestamp=datetime.utcnow())

    dirname = os.path.dirname(str(tmpdir.mkdir('test-warc-writer')))
    wwriter = WarcWriter(Options(directory=dirname, prefix='foo',
        warc_filename='{timestamp17}-{prefix}-{timestamp14}-{serialno}'))
    wwriter.write_records(recorded_url)
    warcs = [fn for fn in os.listdir(dirname)]
    assert warcs
    target_warc = os.path.join(dirname, warcs[0])
    assert target_warc
    parts = warcs[0].split('-')
    assert len(parts[0]) == 17
    assert parts[1] == 'foo'
    assert len(parts[2]) == 14
    assert parts[3] == '00000.warc.open'
