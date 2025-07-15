"""
tests/test_writer.py - warcprox filter tests

Copyright (C) 2017-2025 Internet Archive

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
"""

import queue
import warcprox


class MockResponseRecorder:
    pass


def create_mime_type_filter():
    filter = warcprox.mime_type_filter.MimeTypeFilter(warcprox.Options())
    filter.inq = queue.Queue()
    filter.outq = queue.Queue()

    return filter


def create_recorded_url(content_type, warcprox_meta):
    return warcprox.warcproxy.RecordedUrl(
        url="http://example.com",
        request_data="blah",
        response_recorder=MockResponseRecorder(),
        remote_ip="127.0.0.1",
        content_type=content_type,
        warcprox_meta=warcprox_meta,
    )


def test_mime_type_filter_should_block():
    filter = create_mime_type_filter()

    url = create_recorded_url(
        content_type="some/mimetype",
        warcprox_meta={
            "mime-type-filters": [{"type": "REJECT", "regex": "some/mimetype"}]
        },
    )
    assert filter._should_block(url)

    filter.inq.put(url)
    filter._get_process_put()
    assert not filter.outq.empty()
    assert filter.outq.get(block=True, timeout=0.5).do_not_archive


def test_mime_type_filter_not_blocked():
    filter = create_mime_type_filter()

    url = create_recorded_url(
        content_type="text/plain",
        warcprox_meta={
            "mime-type-filters": [{"type": "REJECT", "regex": "some/mimetype"}]
        },
    )

    assert not filter._should_block(url)

    filter.inq.put(url)
    filter._get_process_put()
    assert filter.outq.not_empty


def test_mime_type_filter_limit_allowed():
    filter = create_mime_type_filter()

    url = create_recorded_url(
        content_type="text/plain",
        warcprox_meta={"mime-type-filters": [{"type": "LIMIT", "regex": "text/plain"}]},
    )
    assert not filter._should_block(url)

    filter.inq.put(url)
    filter._get_process_put()
    assert not filter.outq.empty()
    assert not filter.outq.get(block=True, timeout=0.5).do_not_archive


def test_mime_type_filter_limit_filtered_out():
    filter = create_mime_type_filter()

    url = create_recorded_url(
        content_type="text/plain",
        warcprox_meta={
            "mime-type-filters": [{"type": "LIMIT", "regex": "some/mimetype"}]
        },
    )
    assert filter._should_block(url)

    filter.inq.put(url)
    filter._get_process_put()
    assert not filter.outq.empty()
    assert filter.outq.get(block=True, timeout=0.5).do_not_archive
