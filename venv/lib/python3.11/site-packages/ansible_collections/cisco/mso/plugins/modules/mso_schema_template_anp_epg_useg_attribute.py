#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_anp_epg_useg_attribute
short_description: Manage EPG uSeg Attributes in schema templates
description:
- Manage uSeg Attributes in the schema template EPGs on Cisco ACI Multi-Site.
author:
- Sabari Jaganathan (@sajagana)
options:
  schema:
    description:
    - The name of the Schema.
    type: str
    required: true
  template:
    description:
    - The name of the Template.
    type: str
    required: true
  anp:
    description:
    - The name of the Application Profile.
    type: str
    required: true
  epg:
    description:
    - The name of the EPG.
    type: str
    required: true
  name:
    description:
    - The name and display name of the uSeg Attribute.
    type: str
    aliases: [ useg ]
  description:
    description:
    - The description of the uSeg Attribute.
    type: str
    aliases: [ descr ]
  type:
    description:
    - The type of the uSeg Attribute.
    type: str
    choices: [ vm_name, ip, mac, vmm_domain, vm_operating_system, vm_tag, vm_hypervisor_identifier, dns, vm_datacenter, vm_identifier, vnic_dn ]
    aliases: [ attribute_type ]
  value:
    description:
    - The value of the uSeg Attribute.
    type: str
    aliases: [ attribute_value ]
  operator:
    description:
    - The operator type of the uSeg Attribute.
    type: str
    choices: [ equals, contains, starts_with, ends_with ]
  useg_subnet:
    description:
    - The uSeg Subnet can only be used when the I(attribute_type) is IP.
    - Use C(false) to set the custom uSeg Subnet IP address to the uSeg Attribute.
    - Use C(true) to set the default uSeg Subnet IP address 0.0.0.0.
    type: bool
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
- name: Add an uSeg attr with attribute_type - ip
  cisco.mso.mso_schema_template_anp_epg_useg_attribute:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    name: useg_attr_ip
    attribute_type: ip
    useg_subnet: false
    value: 10.0.0.0/24
    state: present

- name: Query a specific EPG uSeg attr with name
  cisco.mso.mso_schema_template_anp_epg_useg_attribute:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    name: useg_attr_ip
    state: query
  register: query_result

- name: Query all EPG uSeg attrs
  cisco.mso.mso_schema_template_anp_epg_useg_attribute:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    state: query
  register: query_result

- name: Remove a uSeg attr from an EPG with name
  cisco.mso.mso_schema_template_anp_epg_useg_attribute:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    name: useg_attr_ip
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.constants import EPG_U_SEG_ATTR_TYPE_MAP, EPG_U_SEG_ATTR_OPERATOR_LIST
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", required=True),
        epg=dict(type="str", required=True),
        name=dict(type="str", aliases=["useg"]),
        description=dict(type="str", aliases=["descr"]),
        type=dict(type="str", aliases=["attribute_type"], choices=list(EPG_U_SEG_ATTR_TYPE_MAP.keys())),
        value=dict(type="str", aliases=["attribute_value"]),
        operator=dict(type="str", choices=EPG_U_SEG_ATTR_OPERATOR_LIST),
        useg_subnet=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name", "type"]],
            ["useg_subnet", False, ["value"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    name = module.params.get("name")
    description = module.params.get("description")
    attribute_type = module.params.get("type")
    value = module.params.get("value")
    operator = module.params.get("operator")
    useg_subnet = module.params.get("useg_subnet")
    state = module.params.get("state")
    mso = MSOModule(module)

    if state == "present":
        if attribute_type in ["mac", "dns"] and value is None:
            mso.fail_json(msg="Failed due to invalid 'value' and the attribute_type is: {0}.".format(attribute_type))
        elif attribute_type not in ["mac", "dns", "ip"] and (value is None or operator is None):
            mso.fail_json(msg="Failed due to invalid 'value' or 'operator' and the attribute_type is: {0}.".format(attribute_type))

    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)
    mso_schema.set_template_anp(anp)
    mso_schema.set_template_anp_epg(epg)

    useg_attr_path = None

    if mso_schema.schema_objects["template_anp_epg"].details.get("uSegEpg"):
        mso_schema.set_template_anp_epg_useg_attr(name, fail_module=False)
        if mso_schema.schema_objects["template_anp_epg_useg_attribute"] is not None:
            useg_attr_path = "/templates/{0}/anps/{1}/epgs/{2}/uSegAttrs/{3}".format(
                template, anp, epg, mso_schema.schema_objects["template_anp_epg_useg_attribute"].index
            )
            mso.existing = mso_schema.schema_objects["template_anp_epg_useg_attribute"].details
    else:
        mso.fail_json(msg="{0}: is not a valid uSeg EPG.".format(epg))

    if state == "query":
        if name is None:
            mso.existing = mso_schema.schema_objects["template_anp_epg"].details.get("uSegAttrs")
        elif not mso.existing:
            mso.fail_json(msg="The uSeg Attribute: {0} not found.".format(name))
        mso.exit_json()

    useg_attrs_path = "/templates/{0}/anps/{1}/epgs/{2}/uSegAttrs".format(template, anp, epg)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing and useg_attr_path:
            mso.existing = {}
            ops.append(dict(op="remove", path=useg_attr_path))

    if state == "present":
        if not mso.existing and description is None:
            description = name

        payload = dict(name=name, displayName=name, description=description, type=EPG_U_SEG_ATTR_TYPE_MAP[attribute_type], value=value)

        if attribute_type == "ip":
            if useg_subnet:
                if value != "" and value != "0.0.0.0" and value is not None:
                    mso.fail_json(msg="The value of uSeg subnet IP should be an empty string or 0.0.0.0, when the useg_subnet is set to true.")
                payload["fvSubnet"] = useg_subnet
                payload["value"] = "0.0.0.0"
            else:
                payload["fvSubnet"] = useg_subnet

        mso.sanitize(payload, collate=True)

        if mso.existing and useg_attr_path:
            ops.append(dict(op="replace", path=useg_attr_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=useg_attrs_path + "/-", value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
