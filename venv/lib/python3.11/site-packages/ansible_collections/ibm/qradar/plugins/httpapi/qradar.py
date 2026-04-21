# (c) 2019 Red Hat Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
author: Ansible Security Team (@ansible-security)
name: qradar
short_description: HttpApi Plugin for IBM QRadar
description:
  - This HttpApi plugin provides methods to connect to IBM QRadar over a
    HTTP(S)-based api.
version_added: "1.0.0"
"""

import json

from ansible.module_utils.basic import to_text
from ansible.module_utils.connection import ConnectionError
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible_collections.ansible.netcommon.plugins.plugin_utils.httpapi_base import HttpApiBase

from ansible_collections.ibm.qradar.plugins.module_utils.qradar import BASE_HEADERS


class HttpApi(HttpApiBase):
    def send_request(self, request_method, path, payload=None, headers=None):
        headers = headers if headers else BASE_HEADERS

        try:
            self._display_request(request_method)
            response, response_data = self.connection.send(
                path,
                payload,
                method=request_method,
                headers=headers,
            )
            value = self._get_response_value(response_data)

            return response.getcode(), self._response_to_json(value)
        except HTTPError as e:
            error = json.loads(e.read())
            return e.code, error

    def _display_request(self, request_method):
        self.connection.queue_message(
            "vvvv",
            "Web Services: %s %s" % (request_method, self.connection._url),
        )

    def _get_response_value(self, response_data):
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except ValueError:
            raise ConnectionError("Invalid JSON response: %s" % response_text)

    def update_auth(self, response, response_text):
        cookie = response.info().get("Set-Cookie")
        # Set the 'SEC' header
        if "SEC" in cookie:
            return {"SEC": cookie.split(";")[0].split("=")[-1]}

        return None

    def logout(self):
        self.send_request("POST", "/auth/logout")

        # Clean up tokens
        self.connection._auth = None
