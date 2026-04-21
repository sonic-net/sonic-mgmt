# Copyright 2018 Red Hat | Ansible
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import os
from tempfile import NamedTemporaryFile

from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.module_utils.urls import Request

try:
    import urllib3

    urllib3.disable_warnings()
except ImportError:
    pass


def fetch_file_from_url(module, url):
    # Download file
    bufsize = 65536
    file_name, file_ext = os.path.splitext(str(url.rsplit("/", 1)[1]))
    temp_file = NamedTemporaryFile(
        dir=module.tmpdir, prefix=file_name, suffix=file_ext, delete=False
    )
    module.add_cleanup_file(temp_file.name)
    try:
        rsp = Request().open("GET", url)
        if not rsp:
            module.fail_json(msg="Failure downloading %s" % url)
        data = rsp.read(bufsize)
        while data:
            temp_file.write(data)
            data = rsp.read(bufsize)
        temp_file.close()
    except Exception as e:
        module.fail_json(msg="Failure downloading %s, %s" % (url, to_native(e)))
    return temp_file.name


def _encode_stringdata(definition):
    if definition["kind"] == "Secret" and "stringData" in definition:
        for k, v in definition["stringData"].items():
            encoded = base64.b64encode(to_bytes(v))
            definition.setdefault("data", {})[k] = to_text(encoded)
        del definition["stringData"]
    return definition
