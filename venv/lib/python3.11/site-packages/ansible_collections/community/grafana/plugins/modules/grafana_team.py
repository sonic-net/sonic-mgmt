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
# Copyright: (c) 2019, Rémi REY (@rrey)

from __future__ import absolute_import, division, print_function

DOCUMENTATION = """
---
module: grafana_team
author:
  - Rémi REY (@rrey)
version_added: "1.0.0"
short_description: Manage Grafana Teams
description:
  - Create/update/delete Grafana Teams through the Teams API.
  - Also allows to add members in the team (if members exists).
requirements:
  - The Teams API is only available starting Grafana 5 and the module will fail if the server version is lower than version 5.
options:
  name:
    description:
      - The name of the Grafana Team.
    required: true
    type: str
  email:
    description:
      - The mail address associated with the Team.
    required: true
    type: str
  members:
    description:
      - List of team members (emails).
      - The list can be enforced with C(enforce_members) parameter.
    type: list
    elements: str
  state:
    description:
      - Delete the members not found in the C(members) parameters from the
      - list of members found on the Team.
    default: present
    type: str
    choices: ["present", "absent"]
  enforce_members:
    description:
      - Delete the members not found in the C(members) parameters from the
      - list of members found on the Team.
    default: false
    type: bool
  skip_version_check:
    description:
      - Skip Grafana version check and try to reach api endpoint anyway.
      - This parameter can be useful if you enabled C(hide_version) in grafana.ini
    required: False
    type: bool
    default: false
    version_added: "1.2.0"
  org_id:
    description:
      - Grafana organization ID in which the team should be created.
      - Not used when C(grafana_api_key) is set, because the C(grafana_api_key) only
        belongs to one organization.
      - Mutually exclusive with C(org_name).
    default: 1
    type: int
  org_name:
    description:
      - Grafana organization name in which the team should be created.
      - Not used when C(grafana_api_key) is set, because the C(grafana_api_key) only
        belongs to one organization.
      - Mutually exclusive with C(org_id).
    type: str
extends_documentation_fragment:
- community.grafana.basic_auth
- community.grafana.api_key
"""

EXAMPLES = """
---
- name: Create a team
  community.grafana.grafana_team:
    url: "https://grafana.example.com"
    grafana_api_key: "{{ some_api_token_value }}"
    name: "grafana_working_group"
    email: "foo.bar@example.com"
    state: present

- name: Create a team with members
  community.grafana.grafana_team:
    url: "https://grafana.example.com"
    grafana_api_key: "{{ some_api_token_value }}"
    name: "grafana_working_group"
    email: "foo.bar@example.com"
    members:
      - john.doe@example.com
      - jane.doe@example.com
    state: present

- name: Create a team with members and enforce the list of members
  community.grafana.grafana_team:
    url: "https://grafana.example.com"
    grafana_api_key: "{{ some_api_token_value }}"
    name: "grafana_working_group"
    email: "foo.bar@example.com"
    members:
      - john.doe@example.com
      - jane.doe@example.com
    enforce_members: true
    state: present

- name: Delete a team
  community.grafana.grafana_team:
    url: "https://grafana.example.com"
    grafana_api_key: "{{ some_api_token_value }}"
    name: "grafana_working_group"
    email: "foo.bar@example.com"
    state: absent

- name: Create a team in a specific organization by name
  community.grafana.grafana_team:
    url: "https://grafana.example.com"
    url_username: "admin"
    url_password: "admin"
    name: "foo_team"
    email: "foo@example.com"
    org_name: "Main Org."
    state: present

- name: Create a team in a specific organization by ID
  community.grafana.grafana_team:
    url: "https://grafana.example.com"
    url_username: "admin"
    url_password: "admin"
    name: "bar_team"
    email: "bar@example.com"
    org_id: 3
    state: present
"""

RETURN = """
---
team:
    description: Information about the Team
    returned: On success
    type: complex
    contains:
        avatarUrl:
            description: The url of the Team avatar on Grafana server
            returned: always
            type: str
            sample:
                - "/avatar/a7440323a684ea47406313a33156e5e9"
        email:
            description: The Team email address
            returned: always
            type: str
            sample:
                - "foo.bar@example.com"
        id:
            description: The Team email address
            returned: always
            type: int
            sample:
                - 42
        memberCount:
            description: The number of Team members
            returned: always
            type: int
            sample:
                - 42
        name:
            description: The name of the team.
            returned: always
            type: str
            sample:
                - "grafana_working_group"
        members:
            description: The list of Team members
            returned: always
            type: list
            sample:
                - ["john.doe@exemple.com"]
        orgId:
            description: The organization id that the team is part of.
            returned: always
            type: int
            sample:
                - 1
"""

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, basic_auth_header
from ansible.module_utils._text import to_text
from ansible_collections.community.grafana.plugins.module_utils import base
from ansible.module_utils.six.moves.urllib.parse import quote

__metaclass__ = type


class GrafanaError(Exception):
    pass


class GrafanaTeamInterface(object):
    def __init__(self, module):
        self._module = module
        self.grafana_url = base.clean_url(module.params.get("url"))

        # {{{ Authentication header
        self.headers = {"Content-Type": "application/json"}
        self.grafana_headers()
        # }}}

        if module.params.get("skip_version_check") is False:
            try:
                grafana_version = self.get_version()
            except GrafanaError as e:
                self._module.fail_json(failed=True, msg=to_text(e))
            if grafana_version["major"] < 5:
                self._module.fail_json(
                    failed=True, msg="Teams API is available starting Grafana v5"
                )

    def grafana_switch_organisation(self, org_id):
        r, info = fetch_url(
            self._module,
            "%s/api/user/using/%s" % (self.grafana_url, org_id),
            headers=self.headers,
            method="POST",
        )

        if info["status"] != 200:
            self._module.fail_json(
                failed=True,
                msg="Unable to switch to organization %s : %s" % (org_id, info),
            )

    def organization_by_name(self, org_name):
        url = "/api/user/orgs"
        organizations = self._send_request(url, headers=self.headers, method="GET")

        try:
            return next(
                org["orgId"] for org in organizations if org["name"] == org_name
            )
        except StopIteration:
            self._module.fail_json(
                failed=True,
                msg="Current user isn't member of organization: %s" % org_name,
            )

    def grafana_headers(self):
        if (
            "grafana_api_key" in self._module.params
            and self._module.params["grafana_api_key"]
        ):
            self.headers["Authorization"] = (
                "Bearer %s" % self._module.params["grafana_api_key"]
            )
        else:
            self.headers["Authorization"] = basic_auth_header(
                self._module.params["url_username"], self._module.params["url_password"]
            )
            self.org_id = (
                self.organization_by_name(self._module.params["org_name"])
                if self._module.params["org_name"]
                else self._module.params["org_id"]
            )
            self.grafana_switch_organisation(self.org_id)

    def _send_request(self, url, data=None, headers=None, method="GET"):
        if data is not None:
            data = json.dumps(data, sort_keys=True)
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
        elif status_code == 409:
            self._module.fail_json(failed=True, msg="Team name is taken")
        elif status_code == 200:
            return self._module.from_json(resp.read())
        self._module.fail_json(
            failed=True, msg="Grafana Teams API answered with HTTP %d" % status_code
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

    def create_team(self, name, email):
        url = "/api/teams"
        team = dict(email=email, name=name)
        response = self._send_request(
            url, data=team, headers=self.headers, method="POST"
        )
        return response

    def get_team(self, name):
        url = "/api/teams/search?name={team}".format(team=quote(name))
        response = self._send_request(url, headers=self.headers, method="GET")
        if not response.get("totalCount") <= 1:
            raise AssertionError("Expected 1 team, got %d" % response["totalCount"])

        if len(response.get("teams")) == 0:
            return None
        return response.get("teams")[0]

    def update_team(self, team_id, name, email):
        url = "/api/teams/{team_id}".format(team_id=team_id)
        team = dict(email=email, name=name)
        response = self._send_request(
            url, data=team, headers=self.headers, method="PUT"
        )
        return response

    def delete_team(self, team_id):
        url = "/api/teams/{team_id}".format(team_id=team_id)
        response = self._send_request(url, headers=self.headers, method="DELETE")
        return response

    def get_team_members(self, team_id):
        url = "/api/teams/{team_id}/members".format(team_id=team_id)
        response = self._send_request(url, headers=self.headers, method="GET")
        members = [item.get("email") for item in response]
        return members

    def add_team_member(self, team_id, email):
        url = "/api/teams/{team_id}/members".format(team_id=team_id)
        data = {"userId": self.get_user_id_from_mail(email)}
        self._send_request(url, data=data, headers=self.headers, method="POST")

    def delete_team_member(self, team_id, email):
        user_id = self.get_user_id_from_mail(email)
        url = "/api/teams/{team_id}/members/{user_id}".format(
            team_id=team_id, user_id=user_id
        )
        self._send_request(url, headers=self.headers, method="DELETE")

    def get_user_id_from_mail(self, email):
        url = "/api/users/lookup?loginOrEmail={email}".format(email=quote(email))
        user = self._send_request(url, headers=self.headers, method="GET")
        if user is None:
            self._module.fail_json(failed=True, msg="User '%s' does not exists" % email)
        return user.get("id")


def setup_module_object():
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=base.grafana_required_together()
        + [["url_username", "url_password", "org_id"]],
        mutually_exclusive=base.grafana_mutually_exclusive()
        + [
            ["org_id", "org_name"],
        ],
    )
    return module


argument_spec = base.grafana_argument_spec()
argument_spec.update(
    name=dict(type="str", required=True),
    org_id=dict(default=1, type="int"),
    org_name=dict(type="str"),
    email=dict(type="str", required=True),
    members=dict(type="list", elements="str", required=False),
    enforce_members=dict(type="bool", default=False),
    skip_version_check=dict(type="bool", default=False),
)


def main():
    module = setup_module_object()
    state = module.params["state"]
    name = module.params["name"]
    email = module.params["email"]
    members = module.params["members"]
    enforce_members = module.params["enforce_members"]

    grafana_iface = GrafanaTeamInterface(module)

    changed = False
    if state == "present":
        team = grafana_iface.get_team(name)
        if team is None:
            grafana_iface.create_team(name, email)
            team = grafana_iface.get_team(name)
            changed = True
        if members is not None:
            cur_members = grafana_iface.get_team_members(team.get("id"))
            plan = diff_members(members, cur_members)
            for member in plan.get("to_add"):
                grafana_iface.add_team_member(team.get("id"), member)
                changed = True
            if enforce_members:
                for member in plan.get("to_del"):
                    grafana_iface.delete_team_member(team.get("id"), member)
                    changed = True
            team = grafana_iface.get_team(name)
        team["members"] = grafana_iface.get_team_members(team.get("id"))
        module.exit_json(failed=False, changed=changed, team=team)
    elif state == "absent":
        team = grafana_iface.get_team(name)
        if team is None:
            module.exit_json(failed=False, changed=False, message="No team found")
        result = grafana_iface.delete_team(team.get("id"))
        module.exit_json(failed=False, changed=True, message=result.get("message"))


def diff_members(target, current):
    diff = {"to_del": [], "to_add": []}
    for member in target:
        if member not in current:
            diff["to_add"].append(member)
    for member in current:
        if member not in target:
            diff["to_del"].append(member)
    return diff


if __name__ == "__main__":
    main()
