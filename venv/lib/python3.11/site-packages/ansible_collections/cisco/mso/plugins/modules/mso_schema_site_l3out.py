#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_l3out
short_description: Manage site-local layer3 Out (L3Outs) in schema template
description:
- Manage site-local L3Outs in schema template on Cisco ACI Multi-Site.
- This module can only be used on versions of MSO that are 3.0 or greater.
- NOTE - Usage of this module for version lesser than 3.0 might break the MSO.
author:
- Anvitha Jain (@anvitha-jain)
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
  l3out:
    description:
    - The name of the l3out to manage.
    type: str
    aliases: [ name ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_site
- module: cisco.mso.mso_schema_template_l3out
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new site L3Out
  cisco.mso.mso_schema_site_l3out:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    l3out: L3out1
    vrf:
      name: vrfName
      template: TemplateName
      schema: schemaName
    state: present

- name: Remove a site L3Out
  cisco.mso.mso_schema_site_l3out:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    l3out: L3out1
    state: absent

- name: Query a specific site L3Out
  cisco.mso.mso_schema_site_l3out:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    l3out: L3out1
    state: query
  register: query_result

- name: Query all site l3outs
  cisco.mso.mso_schema_site_l3out:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
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
        site=dict(type="str", required=True),
        template=dict(type="str", required=True),
        vrf=dict(type="dict", options=mso_reference_spec()),
        l3out=dict(type="str", aliases=["name"]),  # This parameter is not required for querying all objects
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
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    l3out = module.params.get("l3out")
    vrf = module.params.get("vrf")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))

    # Get site
    site_id = mso.lookup_site(site)

    # Get site_idx
    if not schema_obj.get("sites"):
        mso.fail_json(msg="No site associated with template '{0}'. Associate the site with the template using mso_schema_site.".format(template))
    sites = [(s.get("siteId"), s.get("templateName")) for s in schema_obj.get("sites")]
    if (site_id, template) not in sites:
        mso.fail_json(msg="Provided template '{0}' is not associated to site".format(template))

    # Schema-access uses indexes
    site_idx = sites.index((site_id, template))
    # Path-based access uses site_id-template
    site_template = "{0}-{1}".format(site_id, template)

    # Get l3out
    l3out_ref = mso.l3out_ref(schema_id=schema_id, template=template, l3out=l3out)
    l3outs = [v.get("l3outRef") for v in schema_obj.get("sites")[site_idx]["intersiteL3outs"]]

    if l3out is not None and l3out_ref in l3outs:
        l3out_idx = l3outs.index(l3out_ref)
        l3out_path = "/sites/{0}/intersiteL3outs/{1}".format(site_template, l3out)
        mso.existing = schema_obj.get("sites")[site_idx]["intersiteL3outs"][l3out_idx]

    if state == "query":
        if l3out is None:
            mso.existing = schema_obj.get("sites")[site_idx]["intersiteL3outs"]
            for l3out in mso.existing:
                l3out["l3outRef"] = mso.dict_from_ref(l3out.get("l3outRef"))
        elif not mso.existing:
            mso.fail_json(msg="L3Out '{l3out}' not found".format(l3out=l3out))
        mso.exit_json()

    l3outs_path = "/sites/{0}/intersiteL3outs".format(site_template)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=l3out_path))

    elif state == "present":
        vrf_ref = mso.make_reference(vrf, "vrf", schema_id, template)

        payload = dict(
            l3outRef=dict(
                schemaId=schema_id,
                templateName=template,
                l3outName=l3out,
            ),
            vrfRef=vrf_ref,
        )

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
