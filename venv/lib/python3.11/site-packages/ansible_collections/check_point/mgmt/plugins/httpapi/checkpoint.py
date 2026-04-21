# (c) 2018 Red Hat Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
author: Ansible Networking Team (@rcarrillocruz)
name: checkpoint
short_description: HttpApi Plugin for Checkpoint devices
description:
  - This HttpApi plugin provides methods to connect to Checkpoint
    devices over a HTTP(S)-based api.
version_added: "2.8.0"
options:
  domain:
    type: str
    description:
      - Specifies the domain of the Check Point device
    vars:
      - name: ansible_checkpoint_domain
  api_key:
    type: str
    description:
      - Login with api-key instead of user & password
    vars:
      - name: ansible_api_key
  cloud_mgmt_id:
    type: str
    description:
      - The Cloud Management ID
    vars:
      - name: ansible_cloud_mgmt_id
  target:
    type: str
    description:
      - target gateway
    vars:
      - name: ansible_checkpoint_target
"""

import json

from ansible.module_utils.basic import to_text
from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.connection import ConnectionError

BASE_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Ansible",
}


class HttpApi(HttpApiBase):
    def login(self, username, password):
        payload = {}
        cp_domain = self.get_option("domain")
        cp_api_key = self.get_option("api_key")
        if cp_domain:
            payload["domain"] = cp_domain
        if username and password and not cp_api_key:
            payload["user"] = username
            payload["password"] = password
        elif cp_api_key and not username and not password:
            payload["api-key"] = cp_api_key
        else:
            raise AnsibleConnectionFailure(
                "[Username and password] or api_key are required for login"
            )
        url = "/web_api/login"
        response, response_data = self.send_request(url, payload)
        if response != 200:
            raise ConnectionError("Login to server failed: %s" % response_data)
        try:
            self.connection._auth = {"X-chkp-sid": response_data["sid"]}
        except KeyError:
            raise ConnectionError(
                "Server returned response without token info during connection authentication: %s"
                % response
            )
        # Case of read-only
        if "uid" in response_data.keys():
            self.connection._session_uid = response_data["uid"]

    def logout(self):
        if any([
            not self.connection._auth,
            (self.connection._auth and "X-chkp-sid" not in self.connection._auth)
        ]):
            return
        url = "/web_api/logout"

        response, dummy = self.send_request(url, None)

    def get_session_uid(self):
        return self.connection._session_uid

    def send_request(self, path, body_params):
        cp_cloud_mgmt_id = self.get_option("cloud_mgmt_id")
        if cp_cloud_mgmt_id:
            path = "/" + cp_cloud_mgmt_id + path
        # we only replace gaia_ip/ with web_api/gaia-api/ if target is set and path contains gaia_ip/
        if 'gaia_api/' in path and self.get_option("target"):
            path = path.replace("gaia_api/", "web_api/gaia-api/")
            body_params['target'] = self.get_option("target")
        data = json.dumps(body_params) if body_params else '{}'
        try:
            self._display_request()
            response, response_data = self.connection.send(
                path, data, method="POST", headers=BASE_HEADERS
            )
            value = self._get_response_value(response_data)

            return response.getcode(), self._response_to_json(value)
        except AnsibleConnectionFailure as e:
            return 404, e.message
        except HTTPError as e:
            error = json.loads(e.read())
            return e.code, error

    def _display_request(self):
        self.connection.queue_message(
            "vvvv", "Web Services: %s %s" % ("POST", self.connection._url)
        )

    def _get_response_value(self, response_data):
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except ValueError:
            raise ConnectionError("Invalid JSON response: %s" % response_text)
