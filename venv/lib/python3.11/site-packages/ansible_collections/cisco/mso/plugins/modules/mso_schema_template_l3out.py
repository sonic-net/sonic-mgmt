#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_l3out
short_description: Manage l3outs in schema templates
description:
- Manage l3outs in schema templates on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  template:
    description:
    - The name of the template.
    type: str
    required: true
  l3out:
    description:
    - The name of the l3out to manage.
    type: str
    aliases: [ name ]
  description:
    description:
    - The description of l3out is supported on versions of MSO that are 3.3 or greater.
    type: str
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
  vrf:
    description:
    - The VRF associated to this L3out.
    type: dict
    suboptions:
      name:
        description:
        - The name of the VRF to associate with.
        required: true
        type: str
      schema:
        description:
        - The schema that defines the referenced VRF.
        - If this parameter is unspecified, it defaults to the current schema.
        type: str
      template:
        description:
        - The template that defines the referenced VRF.
        - If this parameter is unspecified, it defaults to the current schema.
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
- name: Add a new L3out
  cisco.mso.mso_schema_template_l3out:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    schema: Schema 1
    template: Template 1
    l3out: L3out 1
    vrf:
      name: vrfName
      schema: vrfSchema
      template: vrfTemplate
    state: present

- name: Remove an L3out
  cisco.mso.mso_schema_template_l3out:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    l3out: L3out 1
    state: absent

- name: Query a specific L3outs
  cisco.mso.mso_schema_template_l3out:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    schema: Schema 1
    template: Template 1
    l3out: L3out 1
    state: query
  register: query_result

- name: Query all L3outs
  cisco.mso.mso_schema_template_l3out:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    schema: Schema 1
    template: Template 1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_reference_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        l3out=dict(type="str", aliases=["name"]),  # This parameter is not required for querying all objects
        description=dict(type="str"),
        display_name=dict(type="str"),
        vrf=dict(type="dict", options=mso_reference_spec()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["l3out"]],
            ["state", "present", ["l3out", "vrf"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    l3out = module.params.get("l3out")
    description = module.params.get("description")
    display_name = module.params.get("display_name")
    vrf = module.params.get("vrf")
    if vrf is not None and vrf.get("template") is not None:
        vrf["template"] = vrf.get("template").replace(" ", "")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))
    template_idx = templates.index(template)

    # Get L3out
    l3outs = [l3.get("name") for l3 in schema_obj.get("templates")[template_idx]["intersiteL3outs"]]

    if l3out is not None and l3out in l3outs:
        l3out_idx = l3outs.index(l3out)
        mso.existing = schema_obj.get("templates")[template_idx]["intersiteL3outs"][l3out_idx]

    if state == "query":
        if l3out is None:
            mso.existing = schema_obj.get("templates")[template_idx]["intersiteL3outs"]
        elif not mso.existing:
            mso.fail_json(msg="L3out '{l3out}' not found".format(l3out=l3out))
        mso.exit_json()

    l3outs_path = "/templates/{0}/intersiteL3outs".format(template)
    l3out_path = "/templates/{0}/intersiteL3outs/{1}".format(template, l3out)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=l3out_path))

    elif state == "present":
        vrf_ref = mso.make_reference(vrf, "vrf", schema_id, template)

        if display_name is None and not mso.existing:
            display_name = l3out

        payload = dict(
            name=l3out,
            displayName=display_name,
            vrfRef=vrf_ref,
        )

        if description is not None:
            payload.update(description=description)

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op="replace", path=l3out_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=l3outs_path + "/-", value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
