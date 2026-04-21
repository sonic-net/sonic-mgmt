#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_service_node_type
short_description: Manage Service Node Types
description:
- Manage Service Node Types on Cisco ACI Multi-Site.
author:
- Shreyas Srish (@shrsr)
options:
  name:
    description:
    - The name of the node type.
    type: str
  display_name:
    description:
    - The name of the node type as displayed on the MSO web interface.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new Service Node Type
  cisco.mso.mso_schema_service_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    name: ips
    display_name: ips
    state: present

- name: Remove a Service Node Type
  cisco.mso.mso_schema_service_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    name: ips
    state: absent

- name: Query a specific Service Node Type
  cisco.mso.mso_schema_service_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    name: ips
    state: query
  register: query_result

- name: Query all Service Node Types
  cisco.mso.mso_schema_service_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        name=dict(type="str"),
        display_name=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
    )

    name = module.params.get("name")
    display_name = module.params.get("display_name")
    state = module.params.get("state")

    mso = MSOModule(module)

    mso.existing = {}
    service_node_id = None

    # Get service node id
    query_node_data = mso.query_service_node_types()
    service_nodes = [f.get("name") for f in query_node_data]
    if name in service_nodes:
        for node_data in query_node_data:
            if node_data.get("name") == name:
                service_node_id = node_data.get("id")
                mso.existing = node_data

    if state == "query":
        if name is None:
            mso.existing = query_node_data
        if name is not None and service_node_id is None:
            mso.fail_json(msg="Service Node Type '{service_node_type}' not found".format(service_node_type=name))
        mso.exit_json()

    service_nodes_path = "schemas/service-node-types"
    service_node_path = "schemas/service-node-types/{0}".format(service_node_id)

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            if module.check_mode:
                mso.existing = {}
            else:
                mso.existing = mso.request(service_node_path, method="DELETE")

    elif state == "present":
        if display_name is None:
            display_name = name

        payload = dict(
            name=name,
            displayName=display_name,
        )
        mso.sanitize(payload, collate=True)
        if not module.check_mode:
            if not mso.existing:
                mso.request(service_nodes_path, method="POST", data=payload)
            elif mso.existing.get("displayName") != display_name:
                mso.fail_json(
                    msg="Service Node Type '{0}' already exists with display name '{1}' which is different from provided display name '{2}'.".format(
                        name, mso.existing.get("displayName"), display_name
                    )
                )
        mso.existing = mso.proposed

    mso.exit_json()


if __name__ == "__main__":
    main()
