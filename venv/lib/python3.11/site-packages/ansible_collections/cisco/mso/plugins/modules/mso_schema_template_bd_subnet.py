#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_bd_subnet
short_description: Manage BD subnets in schema templates
description:
- Manage BD subnets in schema templates on Cisco ACI Multi-Site.
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
    - The name of the template to change.
    type: str
    required: true
  bd:
    description:
    - The name of the BD to manage.
    type: str
    required: true
  subnet:
    description:
    - The IP range in CIDR notation.
    type: str
    aliases: [ ip ]
  description:
    description:
    - The description of this subnet.
    type: str
  is_virtual_ip:
    description:
    - Treat as Virtual IP Address
    type: bool
    default: false
  scope:
    description:
    - The scope of the subnet.
    type: str
    choices: [ private, public ]
  shared:
    description:
    - Whether this subnet is shared between VRFs.
    type: bool
    default: false
  no_default_gateway:
    description:
    - Whether this subnet has a default gateway.
    type: bool
    default: false
  querier:
    description:
    - Whether this subnet is an IGMP querier.
    type: bool
    default: false
  primary:
    description:
    - Treat as Primary Subnet.
    - There can be only one primary subnet per address family under a BD.
    - This option can only be used on versions of MSO that are 3.1.1h or greater.
    type: bool
    default: false
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- Due to restrictions of the MSO REST API concurrent modifications to BD subnets can be dangerous and corrupt data.
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new subnet to a BD
  cisco.mso.mso_schema_template_bd_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD 1
    subnet: 10.0.0.0/24
    state: present

- name: Remove a subset from a BD
  cisco.mso.mso_schema_template_bd_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD 1
    subnet: 10.0.0.0/24
    state: absent

- name: Query a specific BD subnet
  cisco.mso.mso_schema_template_bd_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD 1
    subnet: 10.0.0.0/24
    state: query
  register: query_result

- name: Query all BD subnets
  cisco.mso.mso_schema_template_bd_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD 1
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
        bd=dict(type="str", required=True),
        subnet=dict(type="str", aliases=["ip"]),
        description=dict(type="str"),
        is_virtual_ip=dict(type="bool", default=False),
        scope=dict(type="str", choices=["private", "public"]),
        shared=dict(type="bool", default=False),
        no_default_gateway=dict(type="bool", default=False),
        querier=dict(type="bool", default=False),
        primary=dict(type="bool", default=False),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
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
    bd = module.params.get("bd")
    subnet = module.params.get("subnet")
    description = module.params.get("description")
    is_virtual_ip = module.params.get("is_virtual_ip")
    scope = module.params.get("scope")
    shared = module.params.get("shared")
    no_default_gateway = module.params.get("no_default_gateway")
    querier = module.params.get("querier")
    primary = module.params.get("primary")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))
    template_idx = templates.index(template)

    # Get BD
    bds = [b.get("name") for b in schema_obj.get("templates")[template_idx]["bds"]]
    if bd not in bds:
        mso.fail_json(msg="Provided BD '{0}' does not exist. Existing BDs: {1}".format(bd, ", ".join(bds)))
    bd_idx = bds.index(bd)

    # Get Subnet
    subnets = [s.get("ip") for s in schema_obj.get("templates")[template_idx]["bds"][bd_idx]["subnets"]]
    if subnet in subnets:
        subnet_idx = subnets.index(subnet)
        # FIXME: Changes based on index are DANGEROUS
        subnet_path = "/templates/{0}/bds/{1}/subnets/{2}".format(template, bd, subnet_idx)
        mso.existing = schema_obj.get("templates")[template_idx]["bds"][bd_idx]["subnets"][subnet_idx]

    if state == "query":
        if subnet is None:
            mso.existing = schema_obj.get("templates")[template_idx]["bds"][bd_idx]["subnets"]
        elif not mso.existing:
            mso.fail_json(msg="Subnet IP '{subnet}' not found".format(subnet=subnet))
        mso.exit_json()

    subnets_path = "/templates/{0}/bds/{1}/subnets".format(template, bd)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=subnet_path))

    elif state == "present":
        if not mso.existing:
            if description is None:
                description = subnet
            if scope is None:
                scope = "private"

        payload = dict(
            ip=subnet,
            description=description,
            virtual=is_virtual_ip,
            scope=scope,
            shared=shared,
            noDefaultGateway=no_default_gateway,
            querier=querier,
            primary=primary,
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
