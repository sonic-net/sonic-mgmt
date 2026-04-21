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
module: grafana_organization
author:
  - paytroff (@paytroff)
version_added: "1.3.0"
short_description: Manage Grafana Organization
description:
  - Create/delete Grafana organization through org API.
  - Tested with Grafana v6.5.0
options:
  name:
    description:
      - The name of the Grafana Organization.
    required: true
    type: str
  state:
    description:
      - State if the organization should be present in Grafana or not
    default: present
    type: str
    choices: ["present", "absent"]
extends_documentation_fragment:
- community.grafana.basic_auth
"""

EXAMPLES = """
---
- name: Create a Grafana organization
  community.grafana.grafana_organization:
    url: "https://grafana.example.com"
    url_username: admin
    url_password: changeme
    name: orgtest
    state: present

- name: Delete a Grafana organization
  community.grafana.grafana_organization:
    url: "https://grafana.example.com"
    url_username: admin
    url_password: changeme
    name: orgtest
    state: absent
"""

RETURN = """
---
org:
    description: Information about the organization
    returned: when state present
    type: complex
    contains:
        id:
            description: The org id
            returned: always
            type: int
            sample:
                - 42
        name:
            description: The org name
            returned: always
            type: str
            sample:
                - "org42"
        address:
            description: The org address
            returned: always
            type: dict
            sample:
                address1: ""
                address2: ""
                city: ""
                country: ""
                state: ""
                zipCode: ""
"""

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, basic_auth_header
from ansible_collections.community.grafana.plugins.module_utils import base
from ansible.module_utils.six.moves.urllib.parse import quote

__metaclass__ = type


class GrafanaOrgInterface(object):
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
        if resp is None:
            self._module.fail_json(
                failed=True,
                msg="Cannot connect to API Grafana %s" % info["msg"],
                status=status_code,
                url=info["url"],
            )
        else:
            self._module.fail_json(
                failed=True,
                msg="Grafana Org API answered with HTTP %d" % status_code,
                body=self._module.from_json(resp.read()),
            )

    def get_actual_org(self, name):
        # https://grafana.com/docs/grafana/latest/http_api/org/#get-organization-by-name
        url = "/api/orgs/name/{name}".format(name=quote(name))
        return self._send_request(url, headers=self.headers, method="GET")

    def create_org(self, name):
        # https://grafana.com/docs/http_api/org/#create-organization
        url = "/api/orgs"
        org = dict(name=name)
        self._send_request(url, data=org, headers=self.headers, method="POST")
        return self.get_actual_org(name)

    def delete_org(self, org_id):
        # https://grafana.com/docs/http_api/org/#delete-organization
        url = "/api/orgs/{org_id}".format(org_id=org_id)
        return self._send_request(url, headers=self.headers, method="DELETE")


def setup_module_object():
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=base.grafana_required_together(),
    )
    return module


argument_spec = base.grafana_argument_spec()
argument_spec.update(
    state=dict(choices=["present", "absent"], default="present"),
    name=dict(type="str", required=True),
)
argument_spec.pop("grafana_api_key")


def main():
    module = setup_module_object()
    state = module.params["state"]
    name = module.params["name"]

    grafana_iface = GrafanaOrgInterface(module)

    # search org by name
    actual_org = grafana_iface.get_actual_org(name)
    if state == "present":
        has_changed = False

        if actual_org is None:
            # create new org
            actual_org = grafana_iface.create_org(name)
            has_changed = True
            module.exit_json(
                changed=has_changed,
                msg="Organization %s created." % name,
                org=actual_org,
            )
        else:
            module.exit_json(
                changed=has_changed,
                msg="Organization %s already created." % name,
                org=actual_org,
            )

    elif state == "absent":
        if actual_org is None:
            module.exit_json(msg="No org found, nothing to do")
        # delete org
        result = grafana_iface.delete_org(actual_org.get("id"))
        module.exit_json(changed=True, msg=result.get("message"))


if __name__ == "__main__":
    main()
