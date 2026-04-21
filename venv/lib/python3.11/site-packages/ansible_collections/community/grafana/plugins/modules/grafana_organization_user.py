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
# Copyright: (c) 2021

from __future__ import absolute_import, division, print_function

DOCUMENTATION = """
---
module: grafana_organization_user
author:
  - Aliaksandr Mianzhynski (@amenzhinsky)
version_added: "1.6.0"
short_description: Manage Grafana Organization Users.
description:
  - Add or remove users or change their roles in Grafana organizations through org API.
  - The user has to exist before using this module. See U(https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_user_module.html).
options:
  login:
    type: str
    required: True
    description:
      - Username or email.
  role:
    type: str
    choices:
      - viewer
      - editor
      - admin
    default: viewer
    description:
      - User's role in the organization.
  state:
    type: str
    default: present
    choices:
      - present
      - absent
    description:
      - Status of a user's organization membership.
  org_id:
    type: int
    default: 1
    description:
      - Organization ID.
      - Mutually exclusive with C(org_name).
  org_name:
    type: str
    description:
      - Organization name.
      - Mutually exclusive with C(org_id).

extends_documentation_fragment:
  - community.grafana.basic_auth
"""

EXAMPLES = """
---
- name: Add user to organization
  community.grafana.grafana_organization_user:
    url: "{{ grafana_url }}"
    url_username: "{{ grafana_username }}"
    url_password: "{{ grafana_password }}"
    login: john
    role: admin

- name: Remove user from organization
  community.grafana.grafana_organization_user:
    url: "{{ grafana_url }}"
    url_username: "{{ grafana_username }}"
    url_password: "{{ grafana_password }}"
    login: john
    state: absent
"""

RETURN = """
---
user:
    description: Information about the organization user
    returned: when state present
    type: complex
    contains:
        email:
            description: The User email address
            returned: always
            type: str
            sample:
                - "foo.bar@example.com"
        login:
            description: The User login
            returned: always
            type: str
            sample:
                - "batman"
        name:
            description: The User name (same as login)
            returned: always
            type: str
            sample:
                - "batman"
        orgId:
            description: The organization id that the team is part of.
            returned: always
            type: int
            sample:
                - 1
        role:
            description: The user role in the organization
            returned: always
            type: str
            choices:
                - Viewer
                - Editor
                - Admin
            sample:
              - Viewer
"""


import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url
from ansible.module_utils._text import to_text
from ansible_collections.community.grafana.plugins.module_utils.base import (
    grafana_argument_spec,
    clean_url,
)
from ansible.module_utils.urls import basic_auth_header

__metaclass__ = type


class GrafanaAPIException(Exception):
    pass


class GrafanaOrganizationUserInterface(object):
    def __init__(self, module):
        self._module = module
        # {{{ Authentication header
        self.headers = {"Content-Type": "application/json"}
        self.headers["Authorization"] = basic_auth_header(
            module.params["url_username"], module.params["url_password"]
        )
        # }}}
        self.grafana_url = clean_url(module.params.get("url"))

    def _api_call(self, method, path, payload):
        data = None
        if payload:
            data = json.dumps(payload)
        return fetch_url(
            self._module,
            self.grafana_url + "/api/" + path,
            headers=self.headers,
            method=method,
            data=data,
        )

    def _organization_by_name(self, org_name):
        r, info = self._api_call("GET", "orgs/name/%s" % org_name, None)
        if info["status"] != 200:
            raise GrafanaAPIException("Unable to retrieve organization: %s" % info)
        return json.loads(to_text(r.read()))

    def _organization_users(self, org_id):
        r, info = self._api_call("GET", "orgs/%d/users" % org_id, None)
        if info["status"] != 200:
            raise GrafanaAPIException(
                "Unable to retrieve organization users: %s" % info
            )
        return json.loads(to_text(r.read()))

    def _create_organization_user(self, org_id, login, role):
        return self._api_call(
            "POST",
            "orgs/%d/users" % org_id,
            {
                "loginOrEmail": login,
                "role": role,
            },
        )

    def _update_organization_user_role(self, org_id, user_id, role):
        return self._api_call(
            "PATCH",
            "orgs/%d/users/%s" % (org_id, user_id),
            {
                "role": role,
            },
        )

    def _remove_organization_user(self, org_id, user_id):
        return self._api_call("DELETE", "orgs/%d/users/%s" % (org_id, user_id), None)

    def _organization_user_by_login(self, org_id, login):
        for user in self._organization_users(org_id):
            if login in (user["login"], user["email"]):
                return user

    def create_or_update_user(self, org_id, login, role):
        r, info = self._create_organization_user(org_id, login, role)
        if info["status"] == 200:
            return {
                "state": "present",
                "changed": True,
                "user": self._organization_user_by_login(org_id, login),
            }
        if info["status"] == 409:  # already member
            user = self._organization_user_by_login(org_id, login)
            if not user:
                raise Exception("[BUG] User not found in organization")

            if user["role"] == role:
                return {"changed": False}

            r, info = self._update_organization_user_role(org_id, user["userId"], role)
            if info["status"] == 200:
                return {
                    "changed": True,
                    "user": self._organization_user_by_login(org_id, login),
                }
            else:
                raise GrafanaAPIException(
                    "Unable to update organization user: %s" % info
                )
        else:
            raise GrafanaAPIException("Unable to add user to organization: %s" % info)

    def remove_user(self, org_id, login):
        user = self._organization_user_by_login(org_id, login)
        if not user:
            return {"changed": False}

        r, info = self._remove_organization_user(org_id, user["userId"])
        if info["status"] == 200:
            return {"state": "absent", "changed": True}
        else:
            raise GrafanaAPIException("Unable to delete organization user: %s" % info)


def main():
    argument_spec = grafana_argument_spec()
    argument_spec.pop("grafana_api_key")
    argument_spec.update(
        org_id=dict(type="int", default=1),
        org_name=dict(type="str"),
        login=dict(type="str", required=True),
        role=dict(type="str", choices=["viewer", "editor", "admin"], default="viewer"),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        mutually_exclusive=[
            ("org_id", "org_name"),
        ],
        required_if=[
            ["state", "present", ["role"]],
        ],
    )

    org_id = module.params["org_id"]
    login = module.params["login"]
    iface = GrafanaOrganizationUserInterface(module)
    if module.params["org_name"]:
        org_name = module.params["org_name"]
        organization = iface._organization_by_name(org_name)
        org_id = organization["id"]
    if module.params["state"] == "present":
        role = module.params["role"].capitalize()
        result = iface.create_or_update_user(org_id, login, role)
        module.exit_json(failed=False, **result)
    else:
        result = iface.remove_user(org_id, login)
        module.exit_json(failed=False, **result)


if __name__ == "__main__":
    main()
