#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_bd_l3out
short_description: Manage site-local BD l3out's in schema template
description:
- Manage site-local BDs l3out's in schema template on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
- Anvitha Jain (@anvitha-jain)
- Akini Ross (@akinross)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  site:
    description:
    - The name of the site.
    type: str
    required: true
  template:
    description:
    - The name of the template.
    type: str
    required: true
  bd:
    description:
    - The name of the BD.
    type: str
    required: true
  l3out:
    description:
    - The l3out associated to this BD.
    aliases: [ name ]
    type: dict
    suboptions:
      name:
        description:
        - The name of the l3out to associate with.
        required: true
        type: str
      schema:
        description:
        - The schema that defines the referenced l3out.
        - If this parameter is unspecified, it defaults to the current schema.
        - Mutually exclusive with O(l3out.tenant).
        type: str
      template:
        description:
        - The template that defines the referenced l3out.
        - If this parameter is unspecified, it defaults to the current schema.
        - Mutually exclusive with O(l3out.tenant).
        type: str
      tenant:
        description:
        - The tenant name of the referenced l3out.
        - If this parameter is specified, the constructed l3out reference will refer to a distinguished name (DN) in APIC.
        - Mutually exclusive with O(l3out.schema) and O(l3out.template).
        type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- The ACI MultiSite PATCH API has a deficiency requiring some objects to be referenced by index.
  This can cause silent corruption on concurrent access when changing/removing on object as
  the wrong object may be referenced. This module is affected by this deficiency.
seealso:
- module: cisco.mso.mso_schema_site_bd
- module: cisco.mso.mso_schema_template_bd
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new site BD l3out
  cisco.mso.mso_schema_site_bd_l3out:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    bd: BD1
    l3out:
      name: L3out1
    state: present

- name: Add a new site BD l3out with different schema and template
  cisco.mso.mso_schema_site_bd_l3out:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    bd: BD1
    l3out:
      name: L3out1
      schema: Schema2
      template: Template2
    state: present

- name: Remove a site BD l3out
  cisco.mso.mso_schema_site_bd_l3out:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    bd: BD1
    l3out:
      name: L3out1
    state: absent

- name: Query a specific site BD l3out
  cisco.mso.mso_schema_site_bd_l3out:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    bd: BD1
    l3out:
      name: L3out1
    state: query
  register: query_result

- name: Query all site BD l3outs
  cisco.mso.mso_schema_site_bd_l3out:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    bd: BD1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_l3out_reference_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        site=dict(type="str", required=True),
        template=dict(type="str", required=True),
        bd=dict(type="str", required=True),
        l3out=dict(
            type="dict", options=mso_l3out_reference_spec(), aliases=["name"], mutually_exclusive=[("tenant", "schema"), ("tenant", "template")]
        ),  # This parameter is not required for querying all objects
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["l3out"]],
            ["state", "present", ["l3out"]],
        ],
    )

    schema = module.params.get("schema")
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    bd = module.params.get("bd")
    l3out = module.params.get("l3out")
    state = module.params.get("state")

    mso = MSOModule(module)

    mso_schema = MSOSchema(mso, schema, template, site)
    mso_objects = mso_schema.schema_objects

    mso_schema.set_template_bd(bd)
    mso_schema.set_site_bd(bd, fail_module=False)

    bd_path = "/sites/{0}-{1}/bds".format(mso_objects.get("site").details.get("siteId"), template)
    ops = []
    payload = dict()

    if l3out:

        if l3out.get("tenant"):
            l3out_ref = "uni/tn-{0}/out-{1}".format(l3out.get("tenant"), l3out.get("name"))
        else:
            l3out_schema_id = mso.lookup_schema(l3out.get("schema")) if l3out.get("schema") else mso_schema.id
            l3out_template = l3out.get("template") if l3out.get("template") else template
            l3out_ref = mso.l3out_ref(schema_id=l3out_schema_id, template=l3out_template, l3out=l3out.get("name"))

        if not mso_objects.get("site_bd"):
            payload = dict(bdRef=dict(schemaId=mso_schema.id, templateName=template, bdName=bd), l3Outs=[l3out.get("name")], l3OutRefs=[l3out_ref])
        else:
            mso_objects.get("site_bd").details["bdRef"] = dict(schemaId=mso_schema.id, templateName=template, bdName=bd)
            l3out_refs = mso_objects.get("site_bd").details.get("l3OutRefs", [])
            l3outs = mso_objects.get("site_bd").details.get("l3Outs", [])
            # check on name because refs are handled differently between versions
            if l3out.get("name") in l3outs:
                mso.existing = mso.dict_from_ref(l3out_refs[l3outs.index(l3out.get("name"))])

    if state == "query":
        if l3out is None:
            if "l3OutRefs" in mso_objects.get("site_bd", {}).details.keys():
                mso.existing = [mso.dict_from_ref(l3) for l3 in mso_objects.get("site_bd", {}).details.get("l3OutRefs", [])]
            else:
                mso.existing = [dict(l3outName=l3) for l3 in mso_objects.get("site_bd", {}).details.get("l3Outs", [])]
        elif not mso.existing:
            mso.fail_json(msg="L3out '{0}' not found".format(l3out.get("name")))
        mso.exit_json()

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            if l3out.get("name") in l3outs:
                del l3outs[l3outs.index(l3out.get("name"))]
            if l3out_ref in l3out_refs:
                del l3out_refs[l3out_refs.index(l3out_ref)]
            ops.append(dict(op="replace", path="{0}/{1}".format(bd_path, bd), value=mso_objects.get("site_bd").details))

    elif state == "present":
        if payload:
            ops.append(dict(op="add", path="{0}/-".format(bd_path), value=payload))
        elif not mso.existing:
            l3outs.append(l3out.get("name"))
            l3out_refs.append(l3out_ref)
            ops.append(dict(op="replace", path="{0}/{1}".format(bd_path, bd), value=mso_objects.get("site_bd").details))

        if l3out.get("tenant"):
            mso.existing = mso.dict_from_ref(l3out_ref)
        else:
            mso.existing = mso.make_reference(l3out, "l3out", l3out_schema_id, l3out_template)

    if not module.check_mode:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
