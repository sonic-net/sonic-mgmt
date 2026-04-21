#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# Copyright: (c) 2019, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_bd_subnet
short_description: Manage site-local BD subnets in schema template
description:
- Manage site-local BD subnets in schema template on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
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
    aliases: [ name ]
  subnet:
    description:
    - The IP range in CIDR notation.
    type: str
    aliases: [ ip ]
  description:
    description:
    - The description of this subnet.
    type: str
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
  is_virtual_ip:
    description:
    - Treat as Virtual IP Address
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
- The ACI MultiSite PATCH API has a deficiency requiring some objects to be referenced by index.
  This can cause silent corruption on concurrent access when changing/removing on object as
  the wrong object may be referenced. This module is affected by this deficiency.
seealso:
- module: cisco.mso.mso_schema_site_bd
- module: cisco.mso.mso_schema_template_bd
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new site BD subnet
  cisco.mso.mso_schema_site_bd_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    bd: BD1
    subnet: 11.11.11.0/24
    state: present

- name: Remove a site BD subnet
  cisco.mso.mso_schema_site_bd_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    bd: BD1
    subnet: 11.11.11.0/24
    state: absent

- name: Query a specific site BD subnet
  cisco.mso.mso_schema_site_bd_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    bd: BD1
    subnet: 11.11.11.0/24
    state: query
  register: query_result

- name: Query all site BD subnets
  cisco.mso.mso_schema_site_bd_subnet:
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
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_subnet_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(mso_subnet_spec())
    argument_spec.update(
        schema=dict(type="str", required=True),
        site=dict(type="str", required=True),
        template=dict(type="str", required=True),
        bd=dict(type="str", aliases=["name"], required=True),
        subnet=dict(type="str", aliases=["ip"]),
        description=dict(type="str"),
        scope=dict(type="str", choices=["private", "public"]),
        shared=dict(type="bool", default=False),
        no_default_gateway=dict(type="bool", default=False),
        querier=dict(type="bool", default=False),
        primary=dict(type="bool", default=False),
        is_virtual_ip=dict(type="bool", default=False),
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
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    bd = module.params.get("bd")
    ip = module.params.get("subnet")
    description = module.params.get("description")
    scope = module.params.get("scope")
    shared = module.params.get("shared")
    no_default_gateway = module.params.get("no_default_gateway")
    querier = module.params.get("querier")
    primary = module.params.get("primary")
    is_virtual_ip = module.params.get("is_virtual_ip")
    state = module.params.get("state")

    mso = MSOModule(module)

    mso_schema = MSOSchema(mso, schema, template, site)
    mso_objects = mso_schema.schema_objects

    mso_schema.set_template_bd(bd)
    if mso_objects.get("template_bd") and mso_objects.get("template_bd").details.get("l2Stretch") is True and state == "present":
        mso.fail_json(
            msg="The l2Stretch of template bd should be false in order to create a site bd subnet. " "Set l2Stretch as false using mso_schema_template_bd"
        )

    if state == "query":
        mso_schema.set_site_bd(bd)
        if not ip:
            mso.existing = mso_objects.get("site_bd").details.get("subnets")
        else:
            mso_schema.set_site_bd_subnet(ip)
            mso.existing = mso_objects.get("site_bd_subnet").details
        mso.exit_json()

    mso_schema.set_site_bd(bd, fail_module=False)

    subnet = None
    if mso_objects.get("site_bd"):
        mso_schema.set_site_bd_subnet(ip, fail_module=False)
        subnet = mso_objects.get("site_bd_subnet")

    mso.previous = mso.existing = subnet.details if subnet else mso.existing

    bd_path = "/sites/{0}-{1}/bds".format(mso_objects.get("site").details.get("siteId"), template)
    subnet_path = "{0}/{1}/subnets".format(bd_path, bd)
    ops = []

    if state == "absent":
        if subnet:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=subnet_path))

    elif state == "present":
        if not mso_objects.get("site_bd"):
            bd_payload = dict(
                bdRef=dict(
                    schemaId=mso_schema.id,
                    templateName=template,
                    bdName=bd,
                ),
                hostBasedRouting=False,
            )
            ops.append(dict(op="add", path=bd_path + "/-", value=bd_payload))

        if not subnet:
            if description is None:
                description = ip
            if scope is None:
                scope = "private"

        subnet_payload = dict(
            ip=ip,
            description=description,
            scope=scope,
            shared=shared,
            noDefaultGateway=no_default_gateway,
            virtual=is_virtual_ip,
            querier=querier,
            primary=primary,
        )

        mso.sanitize(subnet_payload, collate=True)

        if subnet:
            ops.append(dict(op="replace", path="{0}/{1}".format(subnet_path, subnet.index), value=mso.sent))
        else:
            ops.append(dict(op="add", path="{0}/-".format(subnet_path), value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
