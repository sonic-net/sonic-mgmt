# -*- coding: utf-8 -*-

# source: https://github.com/tlastowka/calculate_multipart_etag/blob/master/calculate_multipart_etag.py
#
# calculate_multipart_etag  Copyright (C) 2015
#      Tony Lastowka <tlastowka at gmail dot com>
#      https://github.com/tlastowka
#
#
# calculate_multipart_etag is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# calculate_multipart_etag is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with calculate_multipart_etag.  If not, see <http://www.gnu.org/licenses/>.

import hashlib

try:
    from boto3.s3.transfer import TransferConfig

    DEFAULT_CHUNK_SIZE = TransferConfig().multipart_chunksize
except ImportError:
    DEFAULT_CHUNK_SIZE = 5 * 1024 * 1024
    pass  # Handled by AnsibleAWSModule


def calculate_multipart_etag(source_path, chunk_size=DEFAULT_CHUNK_SIZE):
    """
    calculates a multipart upload etag for amazon s3

    Arguments:

    source_path -- The file to calculate the etag for
    chunk_size -- The chunk size to calculate for.
    """

    md5s = []

    with open(source_path, "rb") as fp:
        while True:
            data = fp.read(chunk_size)

            if not data:
                break
            md5 = hashlib.new("md5", usedforsecurity=False)
            md5.update(data)
            md5s.append(md5)

    if len(md5s) == 1:
        new_etag = f'"{md5s[0].hexdigest()}"'
    else:  # > 1
        digests = b"".join(m.digest() for m in md5s)

        new_md5 = hashlib.md5(digests)
        new_etag = f'"{new_md5.hexdigest()}-{len(md5s)}"'

    return new_etag
