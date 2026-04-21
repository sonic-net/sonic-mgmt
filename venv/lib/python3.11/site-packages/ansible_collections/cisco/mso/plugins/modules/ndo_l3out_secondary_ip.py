#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
module: ndo_l3out_secondary_ip
version_added: "2.12.0"
short_description: Manage L3Out Secondary IP Address on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Out L3Out Secondary IP Address on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Akini Ross (@akinross)
options:
  template:
    description:
    - The name of the L3Out template.
    - This parameter or O(template_id) is required.
    type: str
    aliases: [ l3out_template ]
  template_id:
    description:
    - The ID of the L3Out template.
    - This parameter or O(template) is required.
    type: str
    aliases: [ l3out_template_id ]
  l3out:
    description:
    - The name of the L3Out.
    - This parameter or O(l3out_uuid) is required.
    type: str
  l3out_uuid:
    description:
    - The UUID of the L3Out.
    - This parameter or O(l3out) is required.
    type: str
  parent_type:
    description:
    - The parent type of the L3Out.
    type: str
    required: true
    choices: [ floating_svi, routed, routed_sub, svi, floating_svi_path_attributes ]
  node_id:
    description:
    - The ID of the node (border leaf switch).
    type: str
    aliases: [ node, border_leaf, anchor_node ]
  path:
    description:
    - The path of the interface.
    - The path must be an existing physical port (eg. eth1/1).
    type: str
    aliases: [ interface ]
  port_channel:
    description:
    - The port channel details.
    type: dict
    aliases: [ pc ]
    suboptions:
      uuid:
        description:
        - The UUID of the port channel.
        - This parameter or O(port_channel.reference) is required.
        type: str
      reference:
        description:
        - The reference details of the port channel.
        - This parameter or O(port_channel.uuid) is required.
        type: dict
        aliases: [ ref ]
        suboptions:
          name:
            description:
            - The name of the port channel.
            type: str
            required: true
          template:
            description:
            - The name of the template that contains the port channel.
            - This parameter or O(port_channel.reference.template_id) is required.
            type: str
          template_id:
            description:
            - The ID of the template that contains the port channel.
            - This parameter or O(port_channel.reference.template) is required.
            type: str
  virtual_port_channel:
    description:
    - The virtual port channel details.
    type: dict
    aliases: [ vpc ]
    suboptions:
      uuid:
        description:
        - The UUID of the virtual port channel.
        - This parameter or O(virtual_port_channel.reference) is required.
        type: str
      reference:
        description:
        - The reference details of the virtual port channel.
        - This parameter or O(virtual_port_channel.uuid) is required.
        type: dict
        aliases: [ ref ]
        suboptions:
          name:
            description:
            - The name of the virtual port channel.
            type: str
            required: true
          template:
            description:
            - The name of the template that contains the virtual port channel.
            - This parameter or O(virtual_port_channel.reference.template_id) is required.
            type: str
          template_id:
            description:
            - The ID of the template that contains the virtual port channel.
            - This parameter or O(virtual_port_channel.reference.template) is required.
            type: str
      side_b:
        description:
        - Whether the side of the virtual port channel interface is side B.
        type: bool
        default: false
  encapsulation_type:
    description:
    - The encapsulation type of the interface.
    type: str
    aliases: [ encap_type ]
    choices: [ vlan, vxlan ]
  encapsulation_value:
    description:
    - The encapsulation value of the interface.
    - The option O(encapsulation_type=vlan), specifies VLAN ID which must be in the range 1 - 4094.
    - The option O(encapsulation_type=vxlan), specifies VXLAN Network Identifier (VNI) which must be in the range 5000 - 16777215.
    type: int
    aliases: [ encap, encapsulation, encapsulation_id ]
  domain_type:
    description:
    - The type of the domain.
    type: str
    choices: [ vmm, physical ]
  domain_provider:
    description:
    - The provider of the domain.
    type: str
    choices: [ cloudfoundry, kubernetes, microsoft, openshift, openstack, redhat, vmware, nutanix ]
  domain:
    description:
    - The name of the domain.
    type: str
    aliases: [ domain_name ]
  secondary_address:
    description:
    - The secondary IP address.
    type: str
    aliases: [ ipv4, ipv6, ip ]
  dhcp_relay:
    description:
    - Whether to enable Dynamic Host Configuration Protocol (DHCP) relay.
    - If this parameter is unspecified, NDO defaults to O(dhcp_relay=false).
    type: bool
  nd_ra_prefix:
    description:
    - Whether to enable Neighbor Discovery (ND) Router Advertisement (RA).
    - If this parameter is unspecified, NDO defaults to O(nd_ra_prefix=false).
    type: bool
  ipv6_dad:
    description:
    - Whether to enable IPv6 Duplicate Address Detection (DAD).
    - If this parameter is unspecified, NDO defaults to O(ipv6_dad=disabled) when O(parent_type=floating_svi_path_attributes).
    - If this parameter is unspecified, NDO defaults to O(ipv6_dad=enabled) for all other parent types.
    type: str
    choices: [ enabled, disabled ]
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the L3Out template.
- The O(l3out) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_l3out_template) to create the L3Out.
- The parent object defined by O(parent_type) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_l3out_routed_interface) to create the L3Out Routed Interface.
  Use M(cisco.mso.ndo_l3out_routed_sub_interface) to create the L3Out Routed Sub-Interface.
  Use M(cisco.mso.ndo_l3out_svi_interface) to create the L3Out SVI Interface.
  Use M(cisco.mso.ndo_l3out_floating_svi_interface) to create the L3Out Floating SVI Interface.
  Use M(cisco.mso.ndo_l3out_floating_svi_interface_path_attributes) to create the L3Out Floating SVI Interface Path Attributes.

seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_l3out_template
- module: cisco.mso.ndo_l3out_routed_interface
- module: cisco.mso.ndo_l3out_routed_sub_interface
- module: cisco.mso.ndo_l3out_svi_interface
- module: cisco.mso.ndo_l3out_floating_svi_interface
- module: cisco.mso.ndo_l3out_floating_svi_interface_path_attributes
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a secondary address on a L3out Routed Interface of type port
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_id: 101
    path: eth1/3
    parent_type: routed
    secondary_address: 3::102/16
    state: present

- name: Create a secondary address on a L3out Routed Interface of type port channel
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    port_channel:
      uuid: '{{ port_channel_interface_3.current.uuid }}'
    parent_type: routed
    secondary_address: 10.2.0.2/24
    state: present

- name: Create a secondary address on a L3out SVI Interface of type port
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_id: 101
    path: eth1/1
    encapsulation_type: vlan
    encapsulation_value: 103
    parent_type: svi
    secondary_address: 10.0.0.2/24
    state: present

- name: Create a secondary address on a L3out SVI Interface of type port channel
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    port_channel:
      uuid: '{{ port_channel_interface_1.current.uuid }}'
    encapsulation_type: vxlan
    encapsulation_value: 50001
    parent_type: svi
    secondary_address: 1::102/16
    state: present

- name: Create a secondary address on a L3out SVI Interface of type virtual port channel side a
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    virtual_port_channel:
      uuid: '{{ virtual_port_channel_interface_1.current.uuid }}'
    encapsulation_type: vlan
    encapsulation_value: 1000
    parent_type: svi
    secondary_address: 10.0.2.3/24
    state: present

- name: Create a secondary address on a L3out SVI Interface of type virtual port channel side b
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    virtual_port_channel:
      uuid: '{{ virtual_port_channel_interface_1.current.uuid }}'
      side_b: true
    encapsulation_type: vlan
    encapsulation_value: 1000
    parent_type: svi
    secondary_address: 10.0.2.4/24
    state: present

- name: Create a secondary address on a L3out Routed Sub-Interface of type port
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_id: 101
    path: eth1/2
    encapsulation_type: vlan
    encapsulation_value: 101
    parent_type: routed_sub
    secondary_address: 10.1.0.2/24
    state: present

- name: Create a secondary address on a L3out Routed Sub-Interface of type port channel
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    port_channel:
      uuid: '{{ port_channel_interface_2.current.uuid }}'
    encapsulation_type: vlan
    encapsulation_value: 101
    parent_type: routed_sub
    secondary_address: 2::102/16
    state: present

- name: Create a secondary address on a L3Out Floating SVI Interface
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_id: 101
    encapsulation_type: vlan
    encapsulation_value: 100
    parent_type: floating_svi
    secondary_address: 10.4.0.3/24
    state: present

- name: Create a secondary address on a L3Out Floating SVI Interface path attributes
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_id: 101
    encapsulation_type: vlan
    encapsulation_value: 100
    domain_type: vmm
    domain_provider: vmware
    domain: ansible_test_vmm
    parent_type: floating_svi_path_attributes
    secondary_address: 10.4.0.4/24
    state: present

- name: Update a secondary address on a L3out Routed Interface of type port
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_id: 101
    path: eth1/3
    parent_type: routed
    secondary_address: 3::102/16
    dhcp_relay: true
    ipv6_dad: disabled
    nd_ra_prefix: true

- name: Get a secondary address on a L3out Routed Interface of type port
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_id: 101
    path: eth1/3
    parent_type: routed
    secondary_address: 3::102/16
    state: query
  register: query_secondary_address

- name: Get all secondary addresses on a L3out Routed Interface of type port
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_id: 101
    path: eth1/3
    parent_type: routed
    state: query
  register: query_all

- name: Delete a secondary address on a L3out Routed Interface of type port
  cisco.mso.ndo_l3out_secondary_ip:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_id: 101
    path: eth1/3
    parent_type: routed
    secondary_address: 3::102/16
    state: absent
"""

RETURN = r"""
"""


import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
    ndo_l3out_port_channel_spec,
    ndo_l3out_virtual_port_channel_spec,
)
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.constants import DOMAIN_TYPE_MAP, VM_DOMAIN_PROVIDER_MAP
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", aliases=["l3out_template"]),
        template_id=dict(type="str", aliases=["l3out_template_id"]),
        l3out=dict(type="str"),
        l3out_uuid=dict(type="str"),
        parent_type=dict(type="str", choices=["floating_svi", "routed", "routed_sub", "svi", "floating_svi_path_attributes"], required=True),
        node_id=dict(type="str", aliases=["node", "border_leaf", "anchor_node"]),
        path=dict(type="str", aliases=["interface"]),
        port_channel=ndo_l3out_port_channel_spec(micro_bfd=False),
        virtual_port_channel=ndo_l3out_virtual_port_channel_spec(side_b=False, secondary_address=True),
        encapsulation_type=dict(type="str", choices=["vlan", "vxlan"], aliases=["encap_type"]),
        encapsulation_value=dict(type="int", aliases=["encap", "encapsulation", "encapsulation_id"]),
        domain_type=dict(type="str", choices=list(DOMAIN_TYPE_MAP)),
        domain_provider=dict(type="str", choices=list(VM_DOMAIN_PROVIDER_MAP)),
        domain=dict(type="str", aliases=["domain_name"]),
        secondary_address=dict(type="str", aliases=["ip", "ipv4", "ipv6"]),
        dhcp_relay=dict(type="bool"),
        nd_ra_prefix=dict(type="bool"),
        ipv6_dad=dict(type="str", choices=["enabled", "disabled"]),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["secondary_address"]],
            ["state", "absent", ["secondary_address"]],
            ["parent_type", "routed", ["path", "port_channel"], True],
            ["parent_type", "routed_sub", ["path", "port_channel"], True],
            ["parent_type", "routed_sub", ["encapsulation_type", "encapsulation_value"]],
            ["parent_type", "svi", ["path", "port_channel", "virtual_port_channel"], True],
            ["parent_type", "svi", ["encapsulation_type", "encapsulation_value"]],
            ["parent_type", "floating_svi", ["node_id", "encapsulation_type", "encapsulation_value"]],
            ["parent_type", "floating_svi_path_attributes", ["node_id", "encapsulation_type", "encapsulation_value", "domain", "domain_type"]],
        ],
        required_by={"path": ("node_id")},
        mutually_exclusive=[
            ("template", "template_id"),
            ("l3out", "l3out_uuid"),
            ("port_channel", "path"),
            ("port_channel", "node_id"),
            ("port_channel", "virtual_port_channel"),
            ("virtual_port_channel", "path"),
            ("virtual_port_channel", "node_id"),
        ],
        required_one_of=[
            ["template", "template_id"],
            ["l3out", "l3out_uuid"],
        ],
    )

    mso = MSOModule(module)
    mso_templates = MSOTemplates(mso)

    template = module.params.get("template")
    template_id = module.params.get("template_id")
    l3out = module.params.get("l3out")
    l3out_uuid = module.params.get("l3out_uuid")
    parent_type = module.params.get("parent_type")
    secondary_address = module.params.get("secondary_address")
    dhcp_relay = module.params.get("dhcp_relay")
    nd_ra_prefix = module.params.get("nd_ra_prefix")
    ipv6_dad = module.params.get("ipv6_dad")
    side_b = None
    virtual_port_channel = module.params.get("virtual_port_channel")
    if virtual_port_channel:
        side_b = virtual_port_channel.get("side_b")

    state = module.params.get("state")

    mso_template = mso_templates.get_template("l3out", template, template_id)
    mso_template.validate_template("l3out")

    l3out_object = mso_template.get_l3out_object(uuid=l3out_uuid, name=l3out, fail_module=True)
    parent_object, parent_path = mso_template.get_parent_details_for_nested_object_in_l3out(mso_templates, l3out_object)
    match = mso_template.get_l3out_secondary_address(
        parent_object.details,
        parent_type,
        secondary_address,
        side_b,
    )
    if match and (secondary_address):
        set_secondary_ip_details(mso_template, parent_type, parent_object.details, match.details, side_b)
        mso.existing = mso.previous = copy.deepcopy(match.details)
    elif match:
        mso.existing = [
            set_secondary_ip_details(mso_template, parent_type, parent_object.details, bgp_peer, side_b) for bgp_peer in match
        ]  # Query all objects

    if parent_type == "floating_svi_path_attributes":
        secondary_path = "secondaryAddresses"
    elif side_b:
        secondary_path = "sideBAddresses/secondary"
    else:
        secondary_path = "addresses/secondary"

    secondary_ip_path = "{0}/{1}/{2}".format(parent_path, secondary_path, match.index if match else "-")
    ops = []

    if state == "present":
        mso_values = {"address": secondary_address, "dhcpRelay": dhcp_relay, "v6RAPrefix": nd_ra_prefix, "ipV6DAD": ipv6_dad}
        mso.sanitize(mso_values)
        if match:
            append_update_ops_data(ops, match.details, secondary_ip_path, mso_values)
            mso.sanitize(match.details, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=secondary_ip_path, value=mso.sent))
        set_secondary_ip_details(mso_template, parent_type, parent_object.details, mso.proposed, side_b)

    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path=secondary_ip_path))

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        l3out_object = mso_template.get_l3out_object(uuid=l3out_uuid, name=l3out, fail_module=True)
        parent_object = mso_template.get_parent_details_for_nested_object_in_l3out(mso_templates, l3out_object)
        match = mso_template.get_l3out_secondary_address(parent_object[0].details, parent_type, secondary_address, side_b)
        if match:
            set_secondary_ip_details(mso_template, parent_type, parent_object[0].details, match.details, side_b)
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}
    mso.exit_json()


def set_secondary_ip_details(mso_template, parent_type, parent_object, match_object, side_b):
    if side_b is not None:
        match_object["virtualPortChannelSide"] = "B" if side_b else "A"
    mso_template.update_config_with_template_and_references(match_object)
    mso_template.set_parent_details_for_nested_object_in_l3out(parent_type, parent_object, match_object)
    return match_object


if __name__ == "__main__":
    main()
