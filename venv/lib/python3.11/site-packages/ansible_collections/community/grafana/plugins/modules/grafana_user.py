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
# Copyright: (c) 2020, Antoine Tanzilli (@Tailzip), Hong Viet Lê (@pomverte), Julien Alexandre (@jual), Marc Cyprien (@LeFameux)

from __future__ import absolute_import, division, print_function

DOCUMENTATION = """
---
module: grafana_user
author:
  - Antoine Tanzilli (@Tailzip)
  - Hong Viet LE (@pomverte)
  - Julien Alexandre (@jual)
  - Marc Cyprien (@LeFameux)
version_added: "1.0.0"
short_description: Manage Grafana User
description:
  - Create/update/delete Grafana User through the users and admin API.
  - Tested with Grafana v6.4.3
  - Password update is not supported at the time
options:
  name:
    description:
      - The name of the Grafana User.
    required: false
    type: str
  email:
    description:
      - The email of the Grafana User.
    required: false
    type: str
  login:
    description:
      - The login of the Grafana User.
    required: true
    type: str
  password:
    description:
      - The password of the Grafana User.
      - At the moment, this field is not updated yet.
    required: false
    type: str
  is_admin:
    description:
      - The Grafana User is an admin.
    required: false
    type: bool
    default: false
  state:
    description:
      - State if the user should be present in Grafana or not
    default: present
    type: str
    choices: ["present", "absent"]
notes:
- Unlike other modules from the collection, this module does not support C(grafana_api_key) authentication type. The Grafana API endpoint for users management
  requires basic auth and admin privileges.
extends_documentation_fragment:
- community.grafana.basic_auth
"""

EXAMPLES = """
---
- name: Create or update a Grafana user
  community.grafana.grafana_user:
    url: "https://grafana.example.com"
    url_username: admin
    url_password: changeme
    name: "Bruce Wayne"
    email: batman@gotham.city
    login: batman
    password: robin
    is_admin: true
    state: present

- name: Delete a Grafana user
  community.grafana.grafana_user:
    url: "https://grafana.example.com"
    url_username: admin
    url_password: changeme
    login: batman
    state: absent
"""

RETURN = """
---
user:
    description: Information about the User
    returned: when state present
    type: complex
    contains:
        id:
            description: The User id
            returned: always
            type: int
            sample:
                - 42
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
        theme:
            description: The Grafana theme
            returned: always
            type: str
            sample:
                - "light"
        orgId:
            description: The organization id that the team is part of.
            returned: always
            type: int
            sample:
                - 1
        isGrafanaAdmin:
            description: The Grafana user permission for admin
            returned: always
            type: bool
            sample:
                - false
        isDisabled:
            description: The Grafana account status
            returned: always
            type: bool
            sample:
                - false
        isExternal:
            description: The Grafana account information on external user provider
            returned: always
            type: bool
            sample:
                - false
"""

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, basic_auth_header
from ansible_collections.community.grafana.plugins.module_utils import base
from ansible.module_utils.six.moves.urllib.parse import quote

__metaclass__ = type


class GrafanaUserInterface(object):
    def __init__(self, module):
        self._module = module
        # {{{ Authentication header
        self.headers = {"Content-Type": "application/json"}
        self.headers["Authorization"] = basic_auth_header(
            module.params["url_username"], module.params["url_password"]
        )
        # }}}
        self.grafana_url = base.clean_url(module.params.get("url"))

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
                msg="Unauthorized to perform action '%s' on '%s' header: %s"
                % (method, full_url, self.headers),
            )
        elif status_code == 403:
            self._module.fail_json(failed=True, msg="Permission Denied")
        elif status_code == 200:
            return self._module.from_json(resp.read())
        self._module.fail_json(
            failed=True,
            msg="Grafana Users API answered with HTTP %d" % status_code,
            body=self._module.from_json(resp.read()),
        )

    def create_user(self, name, email, login, password):
        # https://grafana.com/docs/http_api/admin/#global-users
        if not password:
            self._module.fail_json(
                failed=True, msg="missing required arguments: password"
            )
        url = "/api/admin/users"
        user = dict(name=name, email=email, login=login, password=password)
        self._send_request(url, data=user, headers=self.headers, method="POST")
        return self.get_user_from_login(login)

    def get_user_from_login(self, login):
        # https://grafana.com/docs/grafana/latest/http_api/user/#get-single-user-by-usernamelogin-or-email
        url = "/api/users/lookup?loginOrEmail={login}".format(login=quote(login))
        return self._send_request(url, headers=self.headers, method="GET")

    def update_user(self, user_id, email, name, login):
        # https://grafana.com/docs/http_api/user/#user-update
        url = "/api/users/{user_id}".format(user_id=user_id)
        user = dict(email=email, name=name, login=login)
        self._send_request(url, data=user, headers=self.headers, method="PUT")
        return self.get_user_from_login(login)

    def update_user_permissions(self, user_id, is_admin):
        # https://grafana.com/docs/http_api/admin/#permissions
        url = "/api/admin/users/{user_id}/permissions".format(user_id=user_id)
        permissions = dict(isGrafanaAdmin=is_admin)
        return self._send_request(
            url, data=permissions, headers=self.headers, method="PUT"
        )

    def delete_user(self, user_id):
        # https://grafana.com/docs/http_api/admin/#delete-global-user
        url = "/api/admin/users/{user_id}".format(user_id=user_id)
        return self._send_request(url, headers=self.headers, method="DELETE")


def is_user_update_required(target_user, email, name, login, is_admin):
    # compare value before in target_user object and param
    target_user_dict = dict(
        email=target_user.get("email"),
        name=target_user.get("name"),
        login=target_user.get("login"),
        is_admin=target_user.get("isGrafanaAdmin"),
    )
    param_dict = dict(email=email, name=name, login=login, is_admin=is_admin)
    return target_user_dict != param_dict


def setup_module_object():
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_if=[
            ["state", "present", ["name", "email"]],
        ],
        required_together=base.grafana_required_together(),
    )
    return module


argument_spec = base.grafana_argument_spec()
argument_spec.update(
    state=dict(choices=["present", "absent"], default="present"),
    name=dict(type="str", required=False),
    email=dict(type="str", required=False),
    login=dict(type="str", required=True),
    password=dict(type="str", required=False, no_log=True),
    is_admin=dict(type="bool", default=False),
)
argument_spec.pop("grafana_api_key")


def main():
    module = setup_module_object()
    state = module.params["state"]
    name = module.params["name"]
    email = module.params["email"]
    login = module.params["login"]
    password = module.params["password"]
    is_admin = module.params["is_admin"]

    grafana_iface = GrafanaUserInterface(module)

    # search user by login
    actual_grafana_user = grafana_iface.get_user_from_login(login)
    if state == "present":
        has_changed = False

        if actual_grafana_user is None:
            # create new user
            actual_grafana_user = grafana_iface.create_user(
                name, email, login, password
            )
            has_changed = True

        if is_user_update_required(actual_grafana_user, email, name, login, is_admin):
            # update found user
            actual_grafana_user_id = actual_grafana_user.get("id")
            if is_admin != actual_grafana_user.get("isGrafanaAdmin"):
                grafana_iface.update_user_permissions(actual_grafana_user_id, is_admin)
            actual_grafana_user = grafana_iface.update_user(
                actual_grafana_user_id, email, name, login
            )
            has_changed = True

        module.exit_json(changed=has_changed, user=actual_grafana_user)

    elif state == "absent":
        if actual_grafana_user is None:
            module.exit_json(message="No user found, nothing to do")
        result = grafana_iface.delete_user(actual_grafana_user.get("id"))
        module.exit_json(changed=True, message=result.get("message"))


if __name__ == "__main__":
    main()
