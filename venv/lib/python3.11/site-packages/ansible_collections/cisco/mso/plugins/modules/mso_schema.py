#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2023, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema
short_description: Manage schemas
description:
- Manage schemas on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
- Akini Ross (@akinross)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    aliases: [ name ]
  id:
    description:
    - The id of the schema.
    - This parameter is required when the C(schema) needs to be updated.
    type: str
  description:
    description:
    - The description of the schema.
    type: str
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating. Only supported on versions of MSO that are 4.1 or greater.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- Due to restrictions of the MSO REST API this module can only create empty schemas (i.e. schemas without templates) on versions of MSO that are 4.1 or greater.
  Use the M(cisco.mso.mso_schema_template) to automatically create schemas with templates.
seealso:
- module: cisco.mso.mso_schema_site
- module: cisco.mso.mso_schema_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create schema
  cisco.mso.mso_schema:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    state: present
  delegate_to: localhost

- name: Remove schemas
  cisco.mso.mso_schema:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    state: absent

- name: Query a schema
  cisco.mso.mso_schema:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    state: query
  register: query_result

- name: Query all schemas
  cisco.mso.mso_schema:
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
        schema=dict(type="str", aliases=["name"]),
        id=dict(type="str"),
        description=dict(type="str"),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["schema"]],
            ["state", "present", ["schema"]],
        ],
    )

    schema = module.params.get("schema")
    schema_id = module.params.get("id")
    description = module.params.get("description")
    state = module.params.get("state")

    mso = MSOModule(module)
    path = "schemas"

    # Query for existing object(s)
    if schema:
        if schema_id:
            mso.existing = mso.get_obj(path, id=schema_id)
        else:
            mso.existing = mso.get_obj(path, displayName=schema)

        if mso.existing:
            if not schema_id:
                schema_id = mso.existing.get("id")
            path = "schemas/{id}".format(id=schema_id)
    else:
        mso.existing = mso.query_objs(path)

    mso.previous = mso.existing
    if state == "present":
        mso.sanitize(dict(displayName=schema, id=schema_id, description=description), collate=True)
        if mso.existing:
            ops = []
            if mso.existing.get("displayName") != schema:
                ops.append(dict(op="replace", path="/displayName", value=schema))
            if mso.existing.get("description") != description and description is not None:
                ops.append(dict(op="replace", path="/description", value=description))

            if not module.check_mode:
                mso.request(path, method="PATCH", data=ops)
        else:
            if not module.check_mode:
                mso.request(path, method="POST", data=dict(displayName=schema, description=description))
        mso.existing = mso.proposed

    elif state == "absent":
        mso.previous = mso.existing
        if mso.existing:
            if module.check_mode:
                mso.existing = {}
            else:
                mso.existing = mso.request(path, method="DELETE")

    mso.exit_json()


if __name__ == "__main__":
    main()
