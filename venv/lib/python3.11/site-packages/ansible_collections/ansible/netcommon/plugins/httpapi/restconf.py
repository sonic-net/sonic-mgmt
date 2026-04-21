# Copyright (c) 2018 Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
author:
 - Ansible Networking Team (@ansible-network)
name: restconf
short_description: HttpApi Plugin for devices supporting Restconf API
description:
- This HttpApi plugin provides methods to connect to Restconf API endpoints.
version_added: 1.0.0
options:
  root_path:
    type: str
    description:
    - Specifies the location of the Restconf root.
    default: /restconf
    vars:
    - name: ansible_httpapi_restconf_root
"""

import json

from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.connection import ConnectionError
from ansible.module_utils.six.moves.urllib.error import HTTPError

from ansible_collections.ansible.netcommon.plugins.plugin_utils.httpapi_base import HttpApiBase


CONTENT_TYPE = "application/yang-data+json"


class HttpApi(HttpApiBase):
    def send_request(self, data, **message_kwargs):
        if data:
            data = json.dumps(data)

        path = "/".join(
            [
                self.get_option("root_path").rstrip("/"),
                message_kwargs.get("path", "").lstrip("/"),
            ]
        )

        headers = {
            "Content-Type": message_kwargs.get("content_type") or CONTENT_TYPE,
            "Accept": message_kwargs.get("accept") or CONTENT_TYPE,
        }
        response, response_data = self.connection.send(
            path, data, headers=headers, method=message_kwargs.get("method")
        )

        return handle_response(response, response_data)


def handle_response(response, response_data):
    try:
        response_data = json.loads(response_data.read())
    except ValueError:
        response_data.seek(0)
        response_data = response_data.read()

    if isinstance(response, HTTPError):
        if response_data:
            if "errors" in response_data:
                errors = response_data["errors"]["error"]
                error_text = "\n".join((error["error-message"] for error in errors))
            else:
                error_text = response_data

            raise ConnectionError(error_text, code=response.code)
        raise ConnectionError(to_text(response), code=response.code)

    return response_data
