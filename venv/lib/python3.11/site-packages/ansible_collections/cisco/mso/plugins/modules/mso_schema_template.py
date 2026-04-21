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
module: mso_schema_template
short_description: Manage templates in schemas
description:
- Manage templates on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
- Akini Ross (@akinross)
options:
  tenant:
    description:
    - The tenant used for this template.
    type: str
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  schema_description:
    description:
    - The description of Schema is supported on versions of MSO that are 3.3 or greater.
    type: str
  template_description:
    description:
    - The description of template is supported on versions of MSO that are 3.3 or greater.
    type: str
  template:
    description:
    - The name of the template.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    - Using C(present) on empty schemas M(cisco.mso.mso_schema) is supported on versions of MSO that are 4.2 or greater.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- Due to restrictions of the MSO REST API this module creates schemas when needed, and removes them when the last template has been removed.
seealso:
- module: cisco.mso.mso_schema
- module: cisco.mso.mso_schema_site
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new template to a schema
  cisco.mso.mso_schema_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: Tenant 1
    schema: Schema 1
    template: Template 1
    state: present

- name: Remove a template from a schema
  cisco.mso.mso_schema_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: Tenant 1
    schema: Schema 1
    template: Template 1
    state: absent

- name: Query a template
  cisco.mso.mso_schema_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: Tenant 1
    schema: Schema 1
    template: Template 1
    state: query
  register: query_result

- name: Query all templates
  cisco.mso.mso_schema_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: Tenant 1
    schema: Schema 1
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
        tenant=dict(type="str"),
        schema=dict(type="str", required=True),
        schema_description=dict(type="str"),
        template_description=dict(type="str"),
        template=dict(type="str", aliases=["name"]),
        display_name=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["template"]],
            ["state", "present", ["template", "tenant"]],
        ],
    )

    tenant = module.params.get("tenant")
    schema = module.params.get("schema")
    schema_description = module.params.get("schema_description")
    template_description = module.params.get("template_description")
    template = module.params.get("template")
    if template is not None:
        template = template.replace(" ", "")
    display_name = module.params.get("display_name")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema
    schema_obj = mso.get_obj("schemas", displayName=schema)

    mso.existing = {}
    if schema_obj:
        # Schema exists
        schema_path = "schemas/{id}".format(**schema_obj)

        # Get template
        templates = schema_obj.get("templates") if schema_obj.get("templates") is not None else []
        if template:
            mso.existing = next((item for item in templates if item.get("name") == template), {})
        else:
            mso.existing = templates
    else:
        schema_path = "schemas"

    if state == "query":
        if not mso.existing:
            if template:
                mso.fail_json(msg="Template '{0}' not found".format(template))
            else:
                mso.existing = []
        mso.exit_json()

    template_path = "/templates/{0}".format(template)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        mso.proposed = mso.sent = {}
        if not schema_obj:
            # There was no schema to begin with
            pass
        elif len(templates) == 1 and mso.existing:
            # There is only one tenant, remove schema
            mso.existing = {}
            if not module.check_mode:
                mso.request(schema_path, method="DELETE")
        elif mso.existing:
            # Remove existing template
            mso.existing = {}
            ops.append(dict(op="remove", path=template_path))

    elif state == "present":
        tenant_id = mso.lookup_tenant(tenant)

        if display_name is None:
            display_name = mso.existing.get("displayName", template)

        if not schema_obj:
            # Schema does not exist, so we have to create it
            payload = dict(
                displayName=schema,
                templates=[
                    dict(
                        name=template,
                        displayName=display_name,
                        tenantId=tenant_id,
                    )
                ],
                sites=[],
            )

            if schema_description is not None:
                payload.update(description=schema_description)
            if template_description is not None:
                payload["templates"][0].update(description=template_description)

            mso.existing = payload.get("templates")[0]

            if not module.check_mode:
                mso.request(schema_path, method="POST", data=payload)

        elif mso.existing:
            # Template exists, so we have to update it
            payload = dict(
                name=template,
                displayName=display_name,
                description=template_description,
                tenantId=tenant_id,
            )

            mso.sanitize(payload, collate=True)

            ops.append(dict(op="replace", path=template_path + "/displayName", value=display_name))
            ops.append(dict(op="replace", path=template_path + "/tenantId", value=tenant_id))

            mso.existing = mso.proposed
        else:
            # Template does not exist, so we have to add it
            payload = dict(
                name=template,
                displayName=display_name,
                tenantId=tenant_id,
            )

            mso.sanitize(payload, collate=True)

            ops.append(dict(op="add", path="/templates/-", value=payload))

            mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
