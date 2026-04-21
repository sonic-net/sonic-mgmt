#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_external_epg_subnet
short_description: Manage External EPG subnets in schema templates
description:
- Manage External EPG subnets in schema templates on Cisco ACI Multi-Site.
author:
- Devarshi Shah (@devarshishah3)
- Anvitha Jain (@anvitha-jain)
- Akini Ross (@akinross)
version_added: '0.0.8'
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  template:
    description:
    - The name of the template to change.
    type: str
    required: true
  external_epg:
    description:
    - The name of the External EPG to manage.
    type: str
    required: true
  subnet:
    description:
    - The IP range in CIDR notation.
    type: str
  name:
    description:
    - The name of the External EPG Subnet.
    type: str
  scope:
    description:
    - The scope parameter contains two sections 1. Route Control and 2. External EPG Classification.
    - The existing Route Control parameters are C(export-rtctrl) for Export Route Control, C(import-rtctrl) for Import Route Control
    - and C(shared-rtctrl) for Shared Route Control
    - The existing External EPG Classification parameters are C(import-security) for External Subnets for External EPG
    - and C(shared-security) for Shared Security Import
    - The  C(shared-security) for Shared Security Import can only be used when External Subnets for External EPG is present
    type: list
    elements: str
    default: []
  aggregate:
    description:
    - The aggregate option aggregates shared routes for the subnet.
    - Use C(shared-rtctrl) to add Aggregate Shared Routes
    - The C(shared-rtctrl) option can only be used when scope parameter Shared Route Control in the Route Control section is selected.
    type: list
    elements: str
    default: []
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- Due to restrictions of the MSO REST API concurrent modifications to EPG subnets can be dangerous and corrupt data.
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new subnet to an External EPG
  cisco.mso.mso_schema_template_external_epg_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    external_epg: EPG 1
    subnet: 10.0.0.0/24
    state: present

- name: Remove a subnet from an External EPG
  cisco.mso.mso_schema_template_external_epg_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    external_epg: EPG 1
    subnet: 10.0.0.0/24
    state: absent

- name: Query a specific External EPG subnet
  cisco.mso.mso_schema_template_external_epg_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    external_epg: EPG 1
    subnet: 10.0.0.0/24
    state: query
  register: query_result

- name: Query all External EPGs subnets
  cisco.mso.mso_schema_template_external_epg_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
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
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        external_epg=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        subnet=dict(type="str"),
        name=dict(type="str"),
        scope=dict(type="list", elements="str", default=[]),
        aggregate=dict(type="list", elements="str", default=[]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["subnet"]],
            ["state", "present", ["subnet"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    external_epg = module.params.get("external_epg")
    subnet = module.params.get("subnet")
    name = module.params.get("name")
    scope = module.params.get("scope")
    aggregate = module.params.get("aggregate")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(
            msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template, templates=", ".join(templates))
        )
    template_idx = templates.index(template)

    # Get EPG
    external_epgs = [e.get("name") for e in schema_obj.get("templates")[template_idx]["externalEpgs"]]
    if external_epg not in external_epgs:
        mso.fail_json(msg="Provided External EPG '{epg}' does not exist. Existing epgs: {epgs}".format(epg=external_epg, epgs=", ".join(external_epgs)))
    epg_idx = external_epgs.index(external_epg)

    # Get Subnet
    subnets = [s.get("ip") for s in schema_obj.get("templates")[template_idx]["externalEpgs"][epg_idx]["subnets"]]
    if subnet in subnets:
        subnet_idx = subnets.index(subnet)
        # FIXME: Changes based on index are DANGEROUS
        subnet_path = "/templates/{0}/externalEpgs/{1}/subnets/{2}".format(template, external_epg, subnet_idx)
        mso.existing = schema_obj.get("templates")[template_idx]["externalEpgs"][epg_idx]["subnets"][subnet_idx]

    if state == "query":
        if subnet is None:
            mso.existing = schema_obj.get("templates")[template_idx]["externalEpgs"][epg_idx]["subnets"]
        elif not mso.existing:
            mso.fail_json(msg="Subnet '{subnet}' not found".format(subnet=subnet))
        mso.exit_json()

    subnets_path = "/templates/{0}/externalEpgs/{1}/subnets".format(template, external_epg)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.existing = {}
            ops.append(dict(op="remove", path=subnet_path))

    elif state == "present":
        payload = dict(
            ip=subnet,
            scope=scope,
            aggregate=aggregate,
            name=name,
        )

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op="replace", path=subnet_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=subnets_path + "/-", value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
