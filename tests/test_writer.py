import os
import fcntl
from multiprocessing import Process, Queue
from datetime import datetime
import pytest
from warcprox.mitmproxy import ProxyingRecorder
from warcprox.warcproxy import RecordedUrl
from warcprox.writer import WarcWriter
from warcprox import Options

recorder = ProxyingRecorder(None, None, 'sha1', url='http://example.com')

recorded_url = RecordedUrl(url='http://example.com', content_type='text/plain',
                           status=200, client_ip='5.5.5.5',
                           request_data=b'abc',
                           response_recorder=recorder,
                           remote_ip='6.6.6.6',
                           timestamp=datetime.utcnow())


def lock_file(queue, filename):
    """Try to lock file and return 1 if successful, else return 0.
    It is necessary to run this method in a different process to test locking.
    """
    try:
        fi = open(filename, 'ab')
        fcntl.flock(fi, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fi.close()
        queue.put('1')
    except IOError:
        queue.put('0')


@pytest.mark.parametrize("no_warc_open_suffix,lock_result", [
                         (True, '0'),
                         (False, '1')])
def test_warc_writer_locking(tmpdir, no_warc_open_suffix, lock_result):
    """Test if WarcWriter is locking WARC files.
    When we don't have the .open suffix, WarcWriter locks the file and the
    external process trying to ``lock_file`` fails (result=0).
    """
    dirname = os.path.dirname(str(tmpdir.mkdir('test-warc-writer')))
    wwriter = WarcWriter(Options(directory=dirname,
                                 no_warc_open_suffix=no_warc_open_suffix))
    wwriter.write_records(recorded_url)

    if no_warc_open_suffix:
        suffix = '.warc'
    else:
        suffix = '.warc.open'
    warcs = [fn for fn in os.listdir(dirname) if fn.endswith(suffix)]
    assert warcs
    target_warc = os.path.join(dirname, warcs[0])
    # launch another process and try to lock WARC file
    queue = Queue()
    p = Process(target=lock_file, args=(queue, target_warc))
    p.start()
    p.join()
    assert queue.get() == lock_result
