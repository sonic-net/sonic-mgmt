#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_schema_template_bd_dhcp_policy
short_description: Manage BD DHCP Policies in schema templates
description:
- Manage BD DHCP policies in schema templates on Cisco ACI Multi-Site.
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Akini Ross (@akinross)
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
  dhcp_relay_policy:
    description:
    - The name of the DHCP Relay Policy.
    type: str
  dhcp_option_policy:
    description:
    - The name of the DHCP Option Policy.
    - When the O(dhcp_option_policy) is provided, the O(dhcp_relay_policy) must also be provided.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- This module can only be used on versions of NDO that are 4.1 or greater.
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new DHCP policy to a BD
  cisco.mso.ndo_schema_template_bd_dhcp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    bd: BD1
    dhcp_relay_policy: ansible_test_relay
    dhcp_option_policy: ansible_test_option
    state: present

- name: Query a specific BD DHCP Policy
  cisco.mso.ndo_schema_template_bd_dhcp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    bd: BD1
    dhcp_relay_policy: ansible_test_relay
    state: query
  register: query_result

- name: Query all BD DHCP Policies
  cisco.mso.ndo_schema_template_bd_dhcp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    bd: BD1
    state: query
  register: query_result

- name: Remove a DHCP policy from a BD
  cisco.mso.ndo_schema_template_bd_dhcp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    bd: BD1
    dhcp_relay_policy: ansible_test_relay
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        bd=dict(type="str", required=True),
        dhcp_relay_policy=dict(type="str"),
        dhcp_option_policy=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["dhcp_relay_policy"]],
            ["state", "present", ["dhcp_relay_policy"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    bd = module.params.get("bd")
    dhcp_relay_policy = module.params.get("dhcp_relay_policy")
    dhcp_option_policy = module.params.get("dhcp_option_policy")
    state = module.params.get("state")

    dhcp_labels_path = "/templates/{0}/bds/{1}/dhcpLabels".format(template, bd)

    mso = MSOModule(module)

    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template_bd(bd)

    tenant_id = mso_schema.schema_objects["template"].details.get("tenantId")

    if dhcp_relay_policy:
        existing_dhcp_relay_policy = {}
        dhcp_relay_policy_uuid = get_dhcp_relay_policy_uuid(mso, tenant_id, dhcp_relay_policy)
        mso_schema.set_template_bd_dhcp_relay_policy(dhcp_relay_policy_uuid, False)
        if mso_schema.schema_objects.get("template_bd_dhcp_relay_policy") is not None:
            dhcp_labels_path = "{0}/{1}".format(dhcp_labels_path, mso_schema.schema_objects["template_bd_dhcp_relay_policy"].index)
            mso_schema.schema_objects["template_bd_dhcp_relay_policy"].details["name"] = dhcp_relay_policy
            dhcp_option_label_ref = mso_schema.schema_objects["template_bd_dhcp_relay_policy"].details.get("dhcpOptionLabel", {}).get("ref")
            if dhcp_option_label_ref:
                mso_schema.schema_objects["template_bd_dhcp_relay_policy"].details["dhcpOptionLabel"]["name"] = get_dhcp_option_label_name(
                    mso, dhcp_option_label_ref
                )
            existing_dhcp_relay_policy = mso_schema.schema_objects["template_bd_dhcp_relay_policy"].details
    else:
        existing_dhcp_relay_policy = mso_schema.schema_objects["template_bd"].details.get("dhcpLabels", [])
        for dhcp_relay_policy in existing_dhcp_relay_policy:
            dhcp_relay_policy["name"] = get_dhcp_relay_label_name(mso, dhcp_relay_policy.get("ref"))
            dhcp_option_label_ref = dhcp_relay_policy.get("dhcpOptionLabel", {}).get("ref")
            if dhcp_option_label_ref:
                dhcp_relay_policy["dhcpOptionLabel"]["name"] = get_dhcp_option_label_name(mso, dhcp_option_label_ref)

    if state == "query":
        mso.existing = existing_dhcp_relay_policy
        mso.exit_json()

    ops = []
    mso.previous = existing_dhcp_relay_policy

    if state == "absent" and existing_dhcp_relay_policy:
        ops.append(dict(op="remove", path=dhcp_labels_path))

    elif state == "present":

        payload = dict(ref=dhcp_relay_policy_uuid, name=dhcp_relay_policy)

        if dhcp_option_policy:
            dhcp_option_policy_uuid = get_dhcp_option_policy_uuid(mso, tenant_id, dhcp_option_policy)
            payload.update(dhcpOptionLabel=dict(ref=dhcp_option_policy_uuid, name=dhcp_option_policy))

        mso.sanitize(payload, collate=True)

        if existing_dhcp_relay_policy:
            ops.append(dict(op="replace", path=dhcp_labels_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path="{0}/{1}".format(dhcp_labels_path, "-"), value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode and mso.existing != mso.previous:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


def get_dhcp_relay_label_name(mso, dhcp_relay_uuid):
    dhcp_relay = mso.request("templates/objects?type=dhcpRelay&uuid={0}".format(dhcp_relay_uuid), "GET")
    if dhcp_relay:
        return dhcp_relay.get("name")


def get_dhcp_option_label_name(mso, dhcp_option_uuid):
    dhcp_option = mso.request("templates/objects?type=dhcpOption&uuid={0}".format(dhcp_option_uuid), "GET")
    if dhcp_option:
        return dhcp_option.get("name")


def get_dhcp_option_policy_uuid(mso, tenant_id, dhcp_option_label):
    dhcp_options = mso.request("templates/objects?type=dhcpOption&name={0}".format(dhcp_option_label), "GET")
    for dhcp_option in dhcp_options:
        if dhcp_option.get("tenantId") == tenant_id and dhcp_option.get("name") == dhcp_option_label:
            return dhcp_option.get("uuid")
    mso.fail_json("Provided DHCP Option Policy with '{0}' not found.".format(dhcp_option_label))


def get_dhcp_relay_policy_uuid(mso, tenant_id, dhcp_relay_label):
    dhcp_relays = mso.request("templates/objects?type=dhcpRelay&name={0}".format(dhcp_relay_label), "GET")
    for dhcp_relay in dhcp_relays:
        if dhcp_relay.get("tenantId") == tenant_id and dhcp_relay.get("name") == dhcp_relay_label:
            return dhcp_relay.get("uuid")
    mso.fail_json("Provided DHCP Relay Policy with '{0}' not found.".format(dhcp_relay_label))


if __name__ == "__main__":
    main()
