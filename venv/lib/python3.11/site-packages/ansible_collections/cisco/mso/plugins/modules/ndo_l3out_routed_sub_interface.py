#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_l3out_routed_sub_interface
version_added: "2.11.0"
short_description: Manage L3Out Routed Sub-Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Out Routed Sub-Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Akini Ross (@akinross)
options:
  template:
    description:
    - The name of the template.
    - The template must be an L3Out template.
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
    aliases: [ l3out_name ]
  l3out_uuid:
    description:
    - The UUID of the L3Out.
    - This parameter or O(l3out) is required.
    type: str
  node_id:
    description:
    - The ID of the node (border leaf switch) where to deploy the L3Out routing protocol and node-level protocol configurations.
    - This parameter is required when O(path) is specified.
    - When specified, the node configuration is created under the L3Out template when it does not exist.
    - When specified, the node configuration is updated under the L3Out template when it already exists.
    - When specified, the node configuration is deleted under the L3Out template when there are no interfaces referencing it.
    type: str
    aliases: [ node, border_leaf ]
  node_router_id:
    description:
    - The router ID of the node.
    type: str
    aliases: [ router_id ]
  node_group_policy:
    description:
    - The name of the node group policy.
    type: str
  use_router_id_as_loopback:
    description:
    - Whether to use the router ID as the loopback address of the node.
    type: bool
  node_loopback_ip:
    description:
    - The loopback IP address of the node.
    type: str
    aliases: [ loopback_ip ]
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
  interface_group_policy:
    description:
    - The name of the interface group policy.
    type: str
  ipv4_address:
    description:
    - The IPv4 address of the interface.
    type: str
  ipv6_address:
    description:
    - The IPv6 address of the interface.
    type: str
  ipv6_link_local_address:
    description:
    - The IPv6 link-local address of the interface.
    type: str
  ipv6_dad:
    description:
    - Whether to enable IPv6 Duplicate Address Detection (DAD).
    - If this parameter is unspecified during create, NDO defaults to O(ipv6_dad=enabled).
    type: str
    choices: [ enabled, disabled ]
  mac:
    description:
    - The MAC address of the interface.
    type: str
  mtu:
    description:
    - The Maximum Transmission Unit (MTU) of the interface.
    - Use O(mtu=inherit) to inherit the value configured under the fabric L2 MTU settings.
    - The value must be 1, or in the range 576 - 9216 or O(mtu=inherit).
    type: str
  target_dscp:
    description:
    - The target Differentiated Services Code Point (DSCP) of the interface.
    - If this parameter is unspecified during create, NDO defaults to O(target_dscp=unspecified).
    type: str
    choices:
    - af11
    - af12
    - af13
    - af21
    - af22
    - af23
    - af31
    - af32
    - af33
    - af41
    - af42
    - af43
    - cs0
    - cs1
    - cs2
    - cs3
    - cs4
    - cs5
    - cs6
    - cs7
    - expedited_forwarding
    - unspecified
    - voice_admit
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
  state:
    description:
    - Determines the desired state of the resource.
    - Use C(absent) to remove the resource.
    - Use C(query) to list the resource.
    - Use C(present) to create or update the resource.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) or O(template_id) must exist before using this module in your playbook.
  The M(cisco.mso.ndo_template) module can be used for this.
- The O(l3out) or O(l3out_uuid) must exist before using this module in your playbook.
  The M(cisco.mso.ndo_l3out_template) module can be used for this.
- The O(node_group_policy) must exist before using this module in your playbook.
  The M(cisco.mso.ndo_l3out_node_group_policy) module can be used for this.
- The O(interface_group_policy) must exist before using this module in your playbook.
  The M(cisco.mso.ndo_l3out_interface_group_policy) module can be used for this.
- The O(port_channel) must exist before using this module in your playbook.
  The M(cisco.mso.ndo_port_channel_interface) module can be used for this.
- The O(ptp.user_profile) must exist before using this module in your playbook.
  The M(cisco.mso.ndo_ptp_policy_profiles) module can be used for this.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_l3out_template
- module: cisco.mso.ndo_l3out_node_group_policy
- module: cisco.mso.ndo_l3out_interface_group_policy
- module: cisco.mso.ndo_port_channel_interface
- module: cisco.mso.ndo_ptp_policy_profiles
extends_documentation_fragment:
- cisco.mso.modules
- cisco.mso.l3out_interface_ptp
"""

EXAMPLES = r"""
- name: Create a L3Out Routed Sub-Interface of type port
  cisco.mso.ndo_l3out_routed_sub_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    ipv4_address: 10.0.0.1/24
    ipv6_address: 2::101/16
    ipv6_link_local_address: FE80::10
    ipv6_dad: enabled
    mac: 00:22:BD:F8:19:FF
    mtu: inherit
    node_id: 101
    path: eth1/1
    encapsulation_type: vlan
    encapsulation_value: 100
    interface_group_policy: interface_group_policy_name
    node_router_id: 1.1.1.1
    node_group_policy: node_group_policy_name
    use_router_id_as_loopback: true
    ptp:
      user_profile:
        uuid: '{{ ptp_profile.current.uuid }}'
    state: present

- name: Create a L3Out Routed Sub-Interface of type port_channel with reference
  cisco.mso.ndo_l3out_routed_sub_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    ipv4_address: 10.1.0.1/24
    ipv6_address: 1::112/16
    ipv6_link_local_address: FE80::20
    ipv6_dad: disabled
    mac: 00:22:BD:F8:19:EE
    mtu: 2000
    port_channel:
      reference:
        name: port_channel_interface_name
        template: fabric_resource_template_name
    encapsulation_type: vlan
    encapsulation_value: 100
    interface_group_policy: interface_group_policy_name
    node_router_id: 2.2.2.2
    node_group_policy: node_group_policy_name
    use_router_id_as_loopback: false
    node_loopback_ip: 10.0.0.1
    ptp:
      mode: unicast_master
      user_profile:
        reference:
          name: ptp_profile_name
          template: fabric_policy_template_name
      source_address: 12.0.0.1
      unicast_destinations:
        - 12.0.0.2
        - 12.0.0.3
    state: present

- name: Update a L3Out Routed Sub-Interface of type port_channel with uuid
  cisco.mso.ndo_l3out_routed_sub_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: "{{ l3out_template.current.templateId }}"
    l3out_uuid: "{{ l3out.current.uuid }}"
    ipv4_address: 10.1.0.1/24
    ipv6_address: 1::112/16
    ipv6_link_local_address: FE80::20
    ipv6_dad: disabled
    mac: 00:22:BD:F8:19:EE
    mtu: 2000
    port_channel:
      uuid: "{{ port_channel_interface.current.uuid }}"
    encapsulation_type: vlan
    encapsulation_value: 100
    interface_group_policy: interface_group_policy_name
    node_router_id: 2.2.2.2
    node_group_policy: node_group_policy_name
    use_router_id_as_loopback: false
    node_loopback_ip: 10.0.0.1
    state: present

- name: Remove PTP configuration from a L3Out Routed Sub-Interface of type port
  cisco.mso.ndo_l3out_routed_sub_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    node_id: 101
    path: eth1/1
    encapsulation_type: vlan
    encapsulation_value: 100
    ptp: {}
    state: present

- name: Query an existing L3Out Routed Sub-Interface of type port
  cisco.mso.ndo_l3out_routed_sub_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    node_id: 101
    path: eth1/1
    encapsulation_type: vlan
    encapsulation_value: 100
    state: query
  register: query_with_name

- name: Query an existing L3Out Routed Sub-Interface of type port_channel
  cisco.mso.ndo_l3out_routed_sub_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    port_channel:
      reference:
        name: port_channel_interface_name
        template: fabric_resource_template_name
    encapsulation_type: vlan
    encapsulation_value: 100
    state: query
  register: query_with_name

- name: Query all existing Routed Sub-Interfaces of a L3Out
  cisco.mso.ndo_l3out_routed_sub_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    state: query

- name: Delete an existing L3Out Routed Sub-Interface
  cisco.mso.ndo_l3out_routed_sub_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    node_id: 101
    path: eth1/1
    encapsulation_type: vlan
    encapsulation_value: 100
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, ndo_l3out_port_channel_spec, ndo_l3out_ptp_spec
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.constants import TARGET_DSCP_MAP, PTP_MODES
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data, delete_none_values, check_if_all_elements_are_none
from ansible_collections.cisco.mso.plugins.module_utils.l3out_node import L3OutNode
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", aliases=["l3out_template"]),
        template_id=dict(type="str", aliases=["l3out_template_id"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        l3out_uuid=dict(type="str"),
        node_id=dict(type="str", aliases=["node", "border_leaf"]),
        node_group_policy=dict(type="str"),
        node_router_id=dict(type="str", aliases=["router_id"]),
        use_router_id_as_loopback=dict(type="bool"),
        node_loopback_ip=dict(type="str", aliases=["loopback_ip"]),
        path=dict(type="str", aliases=["interface"]),
        port_channel=ndo_l3out_port_channel_spec(micro_bfd=False),
        interface_group_policy=dict(type="str"),
        ipv4_address=dict(type="str"),
        ipv6_address=dict(type="str"),
        ipv6_link_local_address=dict(type="str"),
        ipv6_dad=dict(type="str", choices=["enabled", "disabled"]),
        mac=dict(type="str"),
        mtu=dict(type="str"),
        target_dscp=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        encapsulation_type=dict(type="str", choices=["vlan", "vxlan"], aliases=["encap_type"]),
        encapsulation_value=dict(type="int", aliases=["encap", "encapsulation", "encapsulation_id"]),
        ptp=ndo_l3out_ptp_spec(),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["path", "port_channel"], True],
            ["state", "absent", ["path", "port_channel"], True],
        ],
        required_by={
            "path": ("node_id", "encapsulation_type", "encapsulation_value"),
            "port_channel": ("encapsulation_type", "encapsulation_value"),
        },
        required_one_of=[
            ["template", "template_id"],
            ["l3out", "l3out_uuid"],
        ],
        mutually_exclusive=[
            ["template", "template_id"],
            ["l3out", "l3out_uuid"],
            ["port_channel", "path"],
            ["port_channel", "node_id"],
        ],
    )

    mso = MSOModule(module)
    mso_templates = MSOTemplates(mso)

    template_name = mso.params.get("template")
    template_id = mso.params.get("template_id")
    l3out = mso.params.get("l3out")
    l3out_uuid = mso.params.get("l3out_uuid")
    node_id = mso.params.get("node_id")
    node_router_id = mso.params.get("node_router_id")
    node_group_policy = mso.params.get("node_group_policy")
    use_router_id_as_loopback = mso.params.get("use_router_id_as_loopback")
    node_loopback_ip = mso.params.get("node_loopback_ip")
    path = mso.params.get("path")
    port_channel = mso.params.get("port_channel")
    interface_group_policy = mso.params.get("interface_group_policy")
    ipv4_address = mso.params.get("ipv4_address")
    ipv6_address = mso.params.get("ipv6_address")
    ipv6_link_local_address = mso.params.get("ipv6_link_local_address")
    ipv6_dad = mso.params.get("ipv6_dad")
    mac = mso.params.get("mac")
    mtu = mso.params.get("mtu")
    target_dscp = mso.params.get("target_dscp")
    encapsulation_type = mso.params.get("encapsulation_type")
    encapsulation_value = mso.params.get("encapsulation_value")
    encap = None
    if encapsulation_type and encapsulation_value:
        encap = {"encapType": encapsulation_type, "value": encapsulation_value}
    ptp = mso.params.get("ptp")
    if ptp is not None and check_if_all_elements_are_none(ptp.values()):
        ptp = {}

    state = mso.params.get("state")

    mso_template = mso_templates.get_template("l3out", template_name, template_id)
    mso_template.validate_template("l3out")
    l3out_object = mso_template.get_l3out_object(l3out_uuid, l3out, True)

    port_channel_uuid = None
    if port_channel:
        if port_channel.get("uuid"):
            port_channel_uuid = port_channel.get("uuid")
            port_channel_match = mso_template.get_template_object_by_uuid("portChannel", port_channel_uuid, True)
        else:
            fabric_resource_mso_template = mso_templates.get_template(
                "fabric_resource",
                port_channel.get("reference").get("template"),
                port_channel.get("reference").get("template_id"),
                fail_module=True,
            )
            port_channel_match = fabric_resource_mso_template.get_port_channel(
                port_channel_uuid,
                port_channel.get("reference").get("name"),
                fail_module=True,
            ).details
            port_channel_uuid = port_channel_match.get("uuid")
        node_id = port_channel_match.get("node")

    pod_id = None
    if path or port_channel:
        pod_id = mso.get_site_interface_details(
            site_id=mso_template.template.get("l3outTemplate", {}).get("siteId"),
            node=node_id,
            port=path,
            port_channel_uuid=port_channel_uuid,
        ).get("pod")

    match = mso_template.get_l3out_routed_sub_interface(l3out_object.details, pod_id, node_id, path, port_channel_uuid, encap)
    if (path or port_channel) and encap and match:
        set_routed_sub_interface_details(mso_template, match.details, l3out_object, mso_templates)
        mso.existing = mso.previous = copy.deepcopy(match.details)  # Query a specific object
    elif match:
        mso.existing = [set_routed_sub_interface_details(mso_template, obj, l3out_object, mso_templates) for obj in match]

    l3out_sub_interface_path = "/l3outTemplate/l3outs/{0}/subInterfaces/{1}".format(l3out_object.index, match.index if match else "-")

    ops = []

    if state != "query":
        l3out_node = L3OutNode(mso.params, mso_template, l3out_object, pod_id, node_id)

    if state == "present":

        mso_values = {
            "path": path,
            "pathRef": port_channel_uuid,
            "pathType": "port" if path else "pc",
            "group": interface_group_policy,
            "mac": mac,
            "mtu": mtu,
            "targetDscp": target_dscp,
            "encap": encap,
        }

        ptp_policy_profile_uuid = None
        if ptp and ptp.get("user_profile") is not None:
            ptp_user_profile = ptp.get("user_profile")
            if ptp_user_profile.get("uuid"):
                ptp_policy_profile_uuid = ptp_user_profile.get("uuid")
            else:
                ptp_policy_profile_uuid = (
                    mso_templates.get_template(
                        "fabric_policy",
                        ptp_user_profile.get("reference").get("template"),
                        ptp_user_profile.get("reference").get("template_id"),
                        fail_module=True,
                    )
                    .get_ptp_policy_profile_object(
                        ptp_policy_profile_uuid,
                        ptp_user_profile.get("reference").get("name"),
                        fail_module=True,
                    )
                    .details.get("uuid")
                )

        if path:
            mso_values["nodeID"] = node_id
            mso_values["podID"] = pod_id

        if match:
            remove_data = []
            mso_values[("addresses", "primaryV4")] = ipv4_address
            mso_values[("addresses", "primaryV6")] = ipv6_address
            mso_values[("addresses", "linkLocalV6")] = ipv6_link_local_address
            mso_values[("addresses", "ipV6DAD")] = ipv6_dad

            if ptp == {}:
                remove_data.append("ptpConfig")
            elif ptp:
                if not match.details.get("ptpConfig"):
                    mso_values["ptpConfig"] = {}
                if ptp.get("unicast_destinations") == []:
                    remove_data.append(("ptpConfig", "destIPs"))
                elif ptp.get("unicast_destinations"):
                    mso_values[("ptpConfig", "destIPs")] = ptp.get("unicast_destinations")
                mso_values[("ptpConfig", "mode")] = PTP_MODES.get(ptp.get("mode"))
                mso_values[("ptpConfig", "srcIP")] = ptp.get("source_address")
                mso_values[("ptpConfig", "ptpProfileRef")] = ptp_policy_profile_uuid

            append_update_ops_data(ops, match.details, l3out_sub_interface_path, mso_values, remove_data)
            mso.sanitize(match.details, collate=True, unwanted=remove_data)

        else:
            mso_values["addresses"] = {
                "primaryV4": ipv4_address,
                "primaryV6": ipv6_address,
                "linkLocalV6": ipv6_link_local_address,
                "ipV6DAD": ipv6_dad,
            }

            if ptp:
                mso_values["ptpConfig"] = {
                    "mode": PTP_MODES.get(ptp.get("mode")),
                    "ptpProfileRef": ptp_policy_profile_uuid,
                    "srcIP": ptp.get("source_address"),
                    "destIPs": ptp.get("unicast_destinations"),
                }

            mso_values = delete_none_values(mso_values)
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=l3out_sub_interface_path, value=mso.sent))

            # update mso.proposed with interface details that are not included in the interface payload and node details
            mso.proposed["node"] = l3out_node.construct_node_payload()

        set_routed_sub_interface_details(mso_template, mso.proposed, l3out_object, mso_templates)
        l3out_node.update_ops(ops)

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=l3out_sub_interface_path))

    if not mso.module.check_mode and ops:
        ignore_errors = ["node {0}-{1} doesn't have an interface configured".format(pod_id, node_id)]
        remove_ops = {ignore_errors[0]: l3out_node.get_node_remove_op()}
        response = mso.l3out_interface_request(mso_template, ops, ignore_errors, state, remove_ops)
        l3out_object = mso_template.get_l3out_object(l3out_uuid, l3out, True, search_object=response)
        match = mso_template.get_l3out_routed_sub_interface(l3out_object.details, pod_id, node_id, path, port_channel_uuid, encap)
        if match:
            set_routed_sub_interface_details(mso_template, match.details, l3out_object, mso_templates)
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif mso.module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}
    mso.exit_json()


def set_routed_sub_interface_details(mso_template, routed_sub_interface, l3out_object, mso_templates):
    mso_template.update_config_with_port_channel_references(routed_sub_interface)
    mso_template.update_config_with_node_references(routed_sub_interface, l3out_object)
    mso_template.update_config_with_ptp_references(routed_sub_interface, mso_templates)
    return routed_sub_interface


if __name__ == "__main__":
    main()
