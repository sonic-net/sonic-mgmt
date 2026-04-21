#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_clone
short_description: Clone schemas
description:
- Clone schemas on Cisco ACI Multi-Site.
- Clones only template objects and not site objects.
- This module can only be used on versions of MSO that are 3.3 or greater.
author:
- Anvitha Jain (@anvitha-jain)
options:
  source_schema:
    description:
    - The name of the source_schema.
    type: str
  destination_schema:
    description:
    - The name of the destination_schema.
    type: str
  state:
    description:
    - Use C(clone) for adding.
    type: str
    choices: [ clone ]
    default: clone
seealso:
- module: cisco.mso.mso_schema
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Clone schema
  cisco.mso.mso_schema_clone:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    source_schema: Source_Schema
    destination_schema: Destination_Schema
    state: clone
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.constants import NDO_4_UNIQUE_IDENTIFIERS
import json


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        source_schema=dict(type="str"),
        destination_schema=dict(type="str"),
        state=dict(type="str", default="clone", choices=["clone"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "clone", ["destination_schema"]],
        ],
    )

    source_schema = module.params.get("source_schema")
    destination_schema = module.params.get("destination_schema")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get source schema details
    source_schema_path = "schemas/{0}".format(mso.lookup_schema(source_schema))
    source_schema_obj = mso.query_obj(source_schema_path, displayName=source_schema)

    source_data = source_schema_obj.get("templates")
    source_data = json.loads(json.dumps(source_data).replace("/{0}".format(source_schema_path), ""))
    # certain unique identifiers are present in NDO4.0> source which need to be deleted from source_data prior to POST
    for template in source_data:
        mso.delete_keys_from_dict(template, NDO_4_UNIQUE_IDENTIFIERS)

    path = "schemas"

    # Check if source and destination schema are named differently
    if source_schema == destination_schema:
        mso.fail_json(msg="Source and Destination schema cannot have same names.")
    # Query for existing object(s)
    if destination_schema:
        mso.existing = mso.get_obj(path, displayName=destination_schema)
        if mso.existing:
            mso.fail_json(msg="Schema with the name '{0}' already exists. Please use another name.".format(destination_schema))

    if state == "clone":
        mso.previous = mso.existing
        payload = dict(
            displayName=destination_schema,
            templates=source_data,
        )
        mso.sanitize(payload, collate=True)

        if not mso.existing:
            if module.check_mode:
                mso.existing = mso.proposed
            else:
                mso.existing = mso.request(path, method="POST", data=mso.sent)

    mso.exit_json()


if __name__ == "__main__":
    main()
