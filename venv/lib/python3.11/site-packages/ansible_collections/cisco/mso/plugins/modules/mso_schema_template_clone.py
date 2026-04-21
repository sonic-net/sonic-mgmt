#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_clone
short_description: Clone templates
description:
- Clone templates on Cisco ACI Multi-Site.
- Clones only template objects and not site objects.
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
  destination_tenant:
    description:
    - The name of the destination_schema.
    type: str
  source_template_name:
    description:
    - The name of the source template.
    type: str
  destination_template_name:
    description:
    - The name of the destination template.
    type: str
  destination_template_display_name:
    description:
    - The display name of the destination template.
    type: str
  state:
    description:
    - Use C(clone) for adding.
    type: str
    choices: [ clone ]
    default: clone
seealso:
- module: cisco.mso.mso_schema
- module: cisco.mso.mso_schema_clone
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Clone template in the same schema
  cisco.mso.mso_schema_template_clone:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    source_schema: Schema1
    destination_schema: Schema1
    destination_tenant: ansible_test
    source_template_name: Template1
    destination_template_name: Template1_clone
    destination_template_display_name: Template1_clone
    state: clone

- name: Clone template to different schema
  cisco.mso.mso_schema_template_clone:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    source_schema: Schema1
    destination_schema: Schema2
    destination_tenant: ansible_test
    source_template_name: Template2
    destination_template_name: Cloned_template_1
    destination_template_display_name: Cloned_template_1
    state: clone

- name: Clone template in the same schema but different tenant attached
  cisco.mso.mso_schema_template_clone:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    source_schema: Schema1
    destination_schema: Schema1
    destination_tenant: common
    source_template_name: Template1_clone
    destination_template_name: Template1_clone_2
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
        destination_tenant=dict(type="str"),
        source_template_name=dict(type="str"),
        destination_template_name=dict(type="str"),
        destination_template_display_name=dict(type="str"),
        state=dict(type="str", default="clone", choices=["clone"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "clone", ["source_schema", "source_template_name"]],
        ],
    )

    source_schema = module.params.get("source_schema")
    destination_schema = module.params.get("destination_schema")
    destination_tenant = module.params.get("destination_tenant")
    source_template_name = module.params.get("source_template_name")
    destination_template_name = module.params.get("destination_template_name")
    destination_template_display_name = module.params.get("destination_template_display_name")
    state = module.params.get("state")

    mso = MSOModule(module)

    source_schema_id = None
    destination_schema_id = None
    destination_tenant_id = None
    ops = []

    if destination_schema is None:
        destination_schema = source_schema

    if destination_template_name is None:
        destination_template_name = source_template_name

    if destination_template_display_name is None:
        destination_template_display_name = destination_template_name

    # Check if source and destination template are named differently if in same schema
    if source_schema == destination_schema:
        if source_template_name == destination_template_name:
            mso.fail_json(msg="Source and destination templates in the same schema cannot have same names.")

    # Get source schema id and destination schema id
    schema_summary = mso.query_objs("schemas/list-identity", key="schemas")

    for schema in schema_summary:
        if schema.get("displayName") == source_schema:
            source_schema_id = schema.get("id")

        if schema.get("displayName") == destination_schema:
            destination_schema_id = schema.get("id")
            for template in schema.get("templates"):
                if template.get("name") == destination_template_name:
                    mso.fail_json(msg="Template with the name '{0}' already exists. Please use another name.".format(destination_template_name))

    if source_schema_id is None:
        mso.fail_json(msg="Schema with the name '{0}' does not exist.".format(source_schema))
    elif destination_schema_id is None:
        mso.fail_json(msg="Schema with the name '{0}' does not exist.".format(destination_schema))

    # Get destination schema details before change
    destination_schema_path = "schemas/{0}".format(destination_schema_id)
    mso.existing = mso.query_obj(destination_schema_path, displayName=destination_schema)

    if state == "clone":
        # Get destination tenant id
        if destination_tenant is not None:
            destination_tenant_id = mso.lookup_tenant(destination_tenant)

        # Get source schema details
        source_schema_path = "schemas/{0}".format(source_schema_id)
        source_schema_obj = mso.query_obj(source_schema_path, displayName=source_schema)

        source_template_path = "/{0}/templates/{1}".format(source_schema_path, source_template_name)
        destination_template_path = "/{0}/templates/{1}".format(destination_schema_path, destination_template_name)

        source_templates = source_schema_obj.get("templates")
        new_template = None
        for template in source_templates:
            if template.get("name") == source_template_name:
                new_template = json.loads(json.dumps(template).replace(source_template_path, destination_template_path))
                new_template["name"] = destination_template_name
                new_template["displayName"] = destination_template_display_name
                if destination_tenant_id is not None:
                    new_template["tenantId"] = destination_tenant_id
                mso.delete_keys_from_dict(new_template, NDO_4_UNIQUE_IDENTIFIERS)
                break

        if new_template is None:
            mso.fail_json(msg="Source template with the name '{0}' does not exist.".format(source_template_name))

        new_template = mso.recursive_dict_from_ref(new_template)
        mso.previous = mso.existing

        ops.append(dict(op="add", path="/templates/-", value=new_template))
        if not module.check_mode:
            mso.request(destination_schema_path, method="PATCH", data=ops)

        mso.existing = mso.query_obj(destination_schema_path, displayName=destination_schema)

    mso.exit_json()


if __name__ == "__main__":
    main()
