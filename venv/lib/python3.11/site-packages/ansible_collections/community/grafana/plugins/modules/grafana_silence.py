#!/usr/bin/python
# -*- coding: utf-8 -*-
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
#
# Copyright: (c) 2023, flkhndlr (@flkhndlr)

from __future__ import absolute_import, division, print_function

DOCUMENTATION = """
module: grafana_silence
author:
  - flkhndlr (@flkhndlr)
version_added: "1.9.0"
short_description: Manage Grafana Silences
description:
  - Create/delete Grafana Silences through the Alertmanager Silence API.
requirements:
  - The Alertmanager API is only available starting Grafana 8 and the module will fail if the server version is lower than version 8.
options:
  org_id:
    description:
      - The Grafana organization ID where the silence will be created or deleted.
      - Not used when I(grafana_api_key) is set, because the grafana_api_key only belongs to one organization.
      - Mutually exclusive with C(org_name).
    default: 1
    type: int
  org_name:
    description:
      - The Grafana organization name where the silence will be created or deleted.
      - Not used when I(grafana_api_key) is set, because the grafana_api_key only belongs to one organization.
      - Mutually exclusive with C(org_id).
    type: str
  comment:
    description:
      - The comment that describes the silence.
    required: true
    type: str
  created_by:
    description:
      - The author that creates the silence.
    required: true
    type: str
  starts_at:
    description:
      - ISO 8601 Timestamp with milliseconds  e.g. "2029-07-29T08:45:45.000Z" when the silence starts.
    type: str
    required: true
  ends_at:
    description:
      - ISO 8601 Timestamp with milliseconds  e.g. "2029-07-29T08:45:45.000Z" when the silence will end.
    type: str
    required: true
  matchers:
    description:
      - List of matchers to select which alerts are affected by the silence.
    type: list
    elements: dict
    required: true
  state:
    description:
      - Delete the first occurrence of a silence with the same settings. Can be "absent" or "present".
    default: present
    type: str
    choices: ["present", "absent"]
  skip_version_check:
    description:
      - Skip Grafana version check and try to reach api endpoint anyway.
      - This parameter can be useful if you enabled `hide_version` in grafana.ini
    required: False
    type: bool
    default: False
extends_documentation_fragment:
- community.grafana.basic_auth
- community.grafana.api_key
"""

EXAMPLES = """
---
- name: Create a silence
  community.grafana.grafana_silence:
    grafana_url: "https://grafana.example.com"
    grafana_api_key: "{{ some_api_token_value }}"
    comment: "a testcomment"
    created_by: "me"
    starts_at: "2029-07-29T08:45:45.000Z"
    ends_at: "2029-07-29T08:55:45.000Z"
    matchers:
      - isEqual: true
        isRegex: true
        name: environment
        value: test
    state: present

- name: Delete a silence
  community.grafana.grafana_silence:
    grafana_url: "https://grafana.example.com"
    grafana_api_key: "{{ some_api_token_value }}"
    comment: "a testcomment"
    created_by: "me"
    starts_at: "2029-07-29T08:45:45.000Z"
    ends_at: "2029-07-29T08:55:45.000Z"
    matchers:
      - isEqual: true
        isRegex: true
        name: environment
        value: test
    state: absent
"""

RETURN = """
---
silence:
  description: Information about the silence
  returned: On success
  type: complex
  contains:
    id:
      description: The id of the silence
      returned: success
      type: str
      sample:
        - ec27df6b-ac3c-412f-ae0b-6e3e1f41c9c3
    comment:
      description: The comment of the silence
      returned: success
      type: str
      sample:
        - this is a test
    createdBy:
      description: The author of the silence
      returned: success
      type: str
      sample:
        - me
    startsAt:
      description: The begin timestamp of the silence
      returned: success
      type: str
      sample:
        - "2029-07-29T08:45:45.000Z"
    endsAt:
      description: The end timestamp of the silence
      returned: success
      type: str
      sample:
        - "2029-07-29T08:55:45.000Z"
    matchers:
      description: The matchers of the silence
      returned: success
      type: list
      sample:
        - [{"isEqual": true, "isRegex": true, "name": "environment", "value": "test"}]
    status:
      description: The status of the silence
      returned: success
      type: dict
      sample:
        - {"state": "pending"}
    updatedAt:
      description: The timestamp of the last update for the silence
      returned: success
      type: str
      sample:
        - "2023-07-27T13:27:33.042Z"
"""

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, basic_auth_header
from ansible.module_utils._text import to_text
from ansible_collections.community.grafana.plugins.module_utils import base

__metaclass__ = type


class GrafanaError(Exception):
    pass


class GrafanaSilenceInterface(object):
    def __init__(self, module):
        self._module = module
        self.grafana_url = base.clean_url(module.params.get("url"))
        self.org_id = None
        # {{{ Authentication header
        self.headers = {"Content-Type": "application/json"}
        if module.params.get("grafana_api_key", None):
            self.headers["Authorization"] = (
                "Bearer %s" % module.params["grafana_api_key"]
            )
        else:
            self.headers["Authorization"] = basic_auth_header(
                module.params["url_username"], module.params["url_password"]
            )
            self.org_id = (
                self.organization_by_name(module.params["org_name"])
                if module.params["org_name"]
                else module.params["org_id"]
            )
            self.switch_organization(self.org_id)
        # }}}

        if module.params.get("skip_version_check") is False:
            try:
                grafana_version = self.get_version()
            except GrafanaError as e:
                self._module.fail_json(failed=True, msg=to_text(e))
            if grafana_version["major"] < 8:
                self._module.fail_json(
                    failed=True,
                    msg="Silences API is available starting with Grafana v8",
                )

    def _send_request(self, url, data=None, headers=None, method="GET"):
        if data is not None:
            data = json.dumps(data)
        if not headers:
            headers = []

        full_url = "{grafana_url}{path}".format(grafana_url=self.grafana_url, path=url)
        resp, info = fetch_url(
            self._module, full_url, data=data, headers=headers, method=method
        )
        status_code = info["status"]
        if status_code == 404:
            return None
        elif status_code == 401:
            self._module.fail_json(
                failed=True,
                msg="Unauthorized to perform action '%s' on '%s'" % (method, full_url),
            )
        elif status_code == 403:
            self._module.fail_json(failed=True, msg="Permission Denied")
        elif status_code in [200, 202]:
            return self._module.from_json(resp.read())
        elif status_code == 400:
            self._module.fail_json(failed=True, msg=info)
        self._module.fail_json(
            failed=True, msg="Grafana Silences API answered with HTTP %d" % status_code
        )

    def switch_organization(self, org_id):
        url = "/api/user/using/%d" % org_id
        self._send_request(url, headers=self.headers, method="POST")

    def organization_by_name(self, org_name):
        url = "/api/user/orgs"
        organizations = self._send_request(url, headers=self.headers, method="GET")
        orga = next((org for org in organizations if org["name"] == org_name))
        if orga:
            return orga["orgId"]

        return self._module.fail_json(
            failed=True, msg="Current user isn't member of organization: %s" % org_name
        )

    def get_version(self):
        url = "/api/health"
        response = self._send_request(
            url, data=None, headers=self.headers, method="GET"
        )
        version = response.get("version")
        if version is not None:
            return base.parse_grafana_version(version)
        raise GrafanaError("Failed to retrieve version from '%s'" % url)

    def create_silence(self, comment, created_by, starts_at, ends_at, matchers):
        url = "/api/alertmanager/grafana/api/v2/silences"
        silence = dict(
            comment=comment,
            createdBy=created_by,
            endsAt=ends_at,
            matchers=matchers,
            startsAt=starts_at,
        )
        response = self._send_request(
            url, data=silence, headers=self.headers, method="POST"
        )
        if self.get_version()["major"] == 8:
            response["silenceID"] = response["id"]
            response.pop("id", None)
        return response

    def get_silence(self, comment, created_by, starts_at, ends_at, matchers):
        url = "/api/alertmanager/grafana/api/v2/silences"

        responses = self._send_request(url, headers=self.headers, method="GET")

        for response in responses:
            if (
                response["comment"] == comment
                and response["createdBy"] == created_by
                and response["startsAt"] == starts_at
                and response["endsAt"] == ends_at
                and response["matchers"] == matchers
            ):
                return response
        return None

    def get_silence_by_id(self, silence_id):
        url = "/api/alertmanager/grafana/api/v2/silence/{SilenceId}".format(
            SilenceId=silence_id
        )
        response = self._send_request(url, headers=self.headers, method="GET")
        return response

    def get_silences(self):
        url = "/api/alertmanager/grafana/api/v2/silences"
        response = self._send_request(url, headers=self.headers, method="GET")
        return response

    def delete_silence(self, silence_id):
        url = "/api/alertmanager/grafana/api/v2/silence/{SilenceId}".format(
            SilenceId=silence_id
        )
        response = self._send_request(url, headers=self.headers, method="DELETE")
        return response


def setup_module_object():
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=base.grafana_required_together(),
        mutually_exclusive=base.grafana_mutually_exclusive(),
    )
    return module


argument_spec = base.grafana_argument_spec()
argument_spec.update(
    comment=dict(type="str", required=True),
    created_by=dict(type="str", required=True),
    ends_at=dict(type="str", required=True),
    matchers=dict(type="list", elements="dict", required=True),
    org_id=dict(default=1, type="int"),
    org_name=dict(type="str"),
    skip_version_check=dict(type="bool", default=False),
    starts_at=dict(type="str", required=True),
    state=dict(type="str", choices=["present", "absent"], default="present"),
)


def main():
    module = setup_module_object()
    comment = module.params["comment"]
    created_by = module.params["created_by"]
    ends_at = module.params["ends_at"]
    matchers = module.params["matchers"]
    starts_at = module.params["starts_at"]
    state = module.params["state"]

    changed = False
    failed = False
    grafana_iface = GrafanaSilenceInterface(module)

    silence = grafana_iface.get_silence(
        comment, created_by, starts_at, ends_at, matchers
    )

    if state == "present":
        if not silence:
            silence = grafana_iface.create_silence(
                comment, created_by, starts_at, ends_at, matchers
            )
            silence = grafana_iface.get_silence_by_id(silence["silenceID"])
            changed = True
        else:
            module.exit_json(
                failed=failed,
                changed=changed,
                msg="Silence with same parameters already exists! eg. '%s'"
                % silence["id"],
            )
    elif state == "absent":
        if silence:
            grafana_iface.delete_silence(silence["id"])
            changed = True
        else:
            module.exit_json(
                failed=False,
                changed=changed,
                msg="Silence does not exist",
            )

    module.exit_json(failed=failed, changed=changed, silence=silence)


if __name__ == "__main__":
    main()
