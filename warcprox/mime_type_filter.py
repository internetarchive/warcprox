"""
warcprox/mime_type_filter.py - postfetch processor for filtering RecordedUrls
by MIME type specified in Content-Type header.

Copyright (C) 2024-2025 Internet Archive

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

import logging
import re
from enum import Enum
from typing import Dict, List

from warcprox.warcproxy import RequestedUrl

from warcprox import BasePostfetchProcessor


class MimeTypeFilterTypes(Enum):
    """
    Filtering types for the MimeTypeFilter warcprox postfetch processor.

    There are two types of filtering:
        - REJECT: Any Content-Type header value matching the regex will be
          rejected.
        - LIMIT: Only Content-Type values matching the regex will be allowed.
    """

    REJECT = "REJECT"
    LIMIT = "LIMIT"


class MimeTypeFilter(BasePostfetchProcessor):
    """
    A warcprox postfetch processor that filters WARC-writing based on the MIME
    type specified in the Content-Type header of a RecordedUrl. Uses MIME type
    filtering configuration stored in the Warcprox-Meta header.

    There are two expected keys in a MIME type filter block:
        - regex: A regex expression to be applied to the Content-Type header
          value.
        - type: The type of filtering logic to apply as defined in the
          MimeTypeFilterTypes enum.
    """

    logger = logging.getLogger(__module__ + "." + __qualname__)

    def _get_process_put(self) -> None:
        """
        Override of method from BasePostfetchProcessor to process each
        recorded_url as it's added to the inbound queue.
        """
        recorded_url = self.inq.get(block=True, timeout=0.5)
        if self._should_block(recorded_url):
            recorded_url.do_not_archive = True
        if self.outq:
            self.outq.put(recorded_url)

    # recorded_url is typed against RequestedUrl because FailedUrls can also be
    # added to the queue and both RecordedUrl and FailedUrl inherit from
    # RequestedUrl.
    def _should_block(self, recorded_url: RequestedUrl) -> bool:
        """
        Determines if the URL should be blocked from further processing based
        on the MIME type specified in the recorded_url's content_type.
        """
        mime_type_filters: List[Dict] = recorded_url.warcprox_meta.get(
            "mime-type-filters", []
        )
        is_filtered_results = self._is_filtered(mime_type_filters, recorded_url)

        return any(is_filtered_results)

    def _is_filtered(
        self, mime_type_filters: List[Dict], recorded_url: RequestedUrl
    ) -> List[bool]:
        """
        Checks each MIME type filter against the recorded_url's content_type
        and returns the list of results.
        """
        filtered_results: List[bool] = []

        if recorded_url.content_type is None:
            self.logger.warning(
                "content_type not known for %s; skipping match", recorded_url.url
            )
            return []

        for filter in mime_type_filters:
            filter_type = filter.get("type")
            filter_regex = filter.get("regex")

            try:
                match = re.match(filter_regex, recorded_url.content_type)
            except re.error:
                self.logger.warning(
                    "Could not compile regex %s; skipping", filter_regex
                )
                filtered_results.append(False)
                continue
            if filter_type == MimeTypeFilterTypes.REJECT.value:
                filtered_results.append(bool(match))
            if filter_type == MimeTypeFilterTypes.LIMIT.value:
                filtered_results.append(not bool(match))

        return filtered_results
