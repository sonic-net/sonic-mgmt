#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_interface_setting
short_description: Manage Interface Policy Groups on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Interface Policy Groups on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Anvitha Jain (@anvjain)
options:
  template:
    description:
    - The name of the template.
    - The template must be a fabric policy template.
    type: str
    required: true
  name:
    description:
    - The name of the interface policy group.
    type: str
    aliases: [ interface_policy_group, interface_setting ]
  uuid:
    description:
    - The UUID of the interface policy group.
    - This parameter is required when the O(name) attribute needs to be updated.
    type: str
    aliases: [ interface_policy_group_uuid, interface_setting_uuid ]
  description:
    description:
    - The description of the interface policy group.
    type: str
  interface_type:
    description:
    - The type of the interface policy group.
    - This parameter is required when interface policy group needs to be created or updated.
    type: str
    choices: [ physical, port_channel ]
  speed:
    description:
    - The port speed for the port(s) associated with the interface policy group.
    - The default value is C(inherit).
    type: str
    choices: [ 100M, 1G, 10G, 25G, 40G, 50G, 100G, 200G, 400G, inherit ]
  auto_negotiation:
    description:
    - The auto negotiation state of the port(s) in the interface policy group.
    - The default value is C(on).
    type: str
    choices: [ 'on', 'off', on_enforce ]
  vlan_scope:
    description:
    - The scope of the VLAN encapsulation of the port(s) in the interface policy group.
    - The default value is C(global).
    type: str
    choices: [ global, port_local ]
  cdp_admin_state:
    description:
    - The CDP admin state enables Cisco Discovery Protocol (CDP) on the interface.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  domains:
    description:
    - The domains with which you want to associate this interface policy.
    - The domains must be defined in the same fabric policy template.
    - The old O(domains) will be replaced by the new entries during an update.
    - Providing an empty list will remove the O(domains) from the interface policy.
    type: list
    elements: str
  port_channel_mode:
    description:
    - The port channel mode of the interface policy group.
    - The default value is C(static_channel_mode_on).
    - The value is available only when the interface_type is C(port_channel).
    type: str
    choices: [ static_channel_mode_on, lacp_passive, lacp_active, mac_pinning, mac_pinning_physical_nic_load, use_explicit_failover_order ]
  min_links:
    description:
    - The minimum number of active links in a port-channel of the interface policy group.
    - The default value is 1.
    - The value must be between 1 and 16.
    - The value is available only when the interface_type is C(port_channel).
    type: int
  max_links:
    description:
    - The maximum number of links in a port-channel of the interface policy group.
    - The default value is 16.
    - The value must be between 1 and 64.
    - The value is available only when the interface_type is C(port_channel).
    type: int
  controls:
    description:
    - The port-channel control flags of the interface policy group.
    - The default value is C(fast_sel_hot_stdby), C(graceful_conv), C(susp_individual).
    - The value is available only when the interface_type is C(port_channel).
    - Providing an empty list will remove the O(controls) from the interface policy.
    - The old O(controls) will be replaced by the new entries during an update.
    type: list
    elements: str
    choices: [ fast_sel_hot_stdby, graceful_conv, susp_individual, load_defer, symmetric_hash ]
  load_balance_hashing:
    description:
    - The IP header information used by the port-channel load balance hashing algorithm of the interface policy group.
    - The value is available only when the interface_type is C(port_channel).
    type: str
    choices: [ destination_ip, layer_4_destination_ip, layer_4_source_ip, source_ip ]
  synce:
    description:
    - The syncE policy assigned to the interface policy group.
    - The syncE policy must be defined in the same fabric policy template.
    type: str
  link_level_debounce_interval:
    description:
    - The debounce interval of the link level in milliseconds.
    - The default value is 100.
    - The value must be an integer between 0 and 5000.
    type: int
  link_level_bring_up_delay:
    description:
    - The time in milliseconds that the decision feedback equalizer (DFE) tuning is delayed when a port is coming up.
    - The default value is 0.
    - The value must be an integer between 0 and 10000.
    type: int
  link_level_fec:
    description:
    - The type of Forwarding Error Correction (FEC) used by the port(s) in the interface policy group.
    - The default value is C(inherit).
    type: str
    choices: [ inherit, cl74_fc_fec, cl91_rs_fec, cons16_rs_fec, ieee_rs_fec, kp_fec, disable_fec ]
  l2_interface_qinq:
    description:
    - The QinQ state for the port(s) in the interface policy group to define how to map double-tagged VLAN traffic.
    - The default value is C(disabled).
    type: str
    choices: [ core_port, double_q_tag_port, edge_port, disabled ]
  l2_interface_reflective_relay:
    description:
    - Enables or disables reflective relay (802.1Qbg) to forward traffic back to the destination or target.
    - The term Virtual Ethernet Port Aggregator (VEPA) is also used to describe 802.1Qbg functionality.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  lldp:
    description:
    - The Link Layer Discovery Protocol (LLDP) configuration of the interface policy group.
    type: dict
    suboptions:
      status:
        description:
        - The state of LLDP on the interface.
        - The default value is C(enabled).
        type: str
        choices: [ enabled, disabled ]
      transmit_state:
        description:
        - The transmit state allows LLDP packets to be sent from the interface.
        - The default value is C(enabled).
        type: str
        choices: [ enabled, disabled ]
      receive_state:
        description:
        - The receive state allows LLDP packets to be received by the interface.
        - The default value is C(enabled).
        type: str
        choices: [ enabled, disabled ]
  stp_bpdu_filter:
    description:
    - Enabling the Bridge Protocol Data Unit (BPDU) filter prevents any BPDUs on the port(s)
    - in the interface policy group by filtering the BPDUs.
    - Disabling the BPDU filter allows BPDUs to be received on the port.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  stp_bpdu_guard:
    description:
    - Enabling the STP BPDU guard shutdown the port(s) by placing them in 'error-disable' mode when BPDUs are received.
    - Disabling the STP BPDU guard allows BPDUs to be received on the port.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  llfc_transmit_state:
    description:
    - The LLFC transmit state allows Link Level Flow Control (LLFC) packets to be sent from the interface.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  llfc_receive_state:
    description:
    - The LLFC receive state allows LLFC packets to be received by the interface.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  mcp:
    description:
    - The MisCabling Protocol (MCP) settings.
    type: dict
    suboptions:
      admin_state:
        description:
        - The MCP admin state enables MisCabling Protocol (MCP) on the interface.
        - The default value is C(enabled).
        type: str
        choices: [ enabled, disabled ]
      strict_mode:
        description:
        - The MCP strict mode.
        - The value is available only when the MCP admin_state is C(enabled).
        - The default value is C(off).
        type: str
        choices: [ 'on', 'off' ]
        aliases: [ mcp_mode ]
      initial_delay_time:
        description:
        - The MCP initial delay time in seconds.
        - The default value is 180.
        - The value must be between 0 and 1800.
        - The value is available only when the MCP strict_mode is C(on).
        type: int
      transmission_frequency_sec:
        description:
        - The MCP transmission frequency in seconds.
        - The default value is 2.
        - The value must be between 0 and 300.
        - The value is available only when the MCP strict_mode is C(on).
        type: int
      transmission_frequency_msec:
        description:
        - The MCP transmission frequency in milliseconds.
        - The default value is 0.
        - The value must be between 0 and 999.
        - The value is available only when the MCP strict_mode is C(on).
        type: int
      grace_period_sec:
        description:
        - The MCP grace period in seconds.
        - The default value is 3.
        - The value must be between 0 and 300.
        - The value is available only when the MCP strict_mode is C(on).
        type: int
      grace_period_msec:
        description:
        - The MCP grace period in milliseconds.
        - The default value is 0.
        - The value must be between 0 and 999.
        - The value is available only when the MCP strict_mode is C(on).
        type: int
  pfc_admin_state:
    description:
    - The Priority Flow Control (PFC) admin state.
    - The default value is C(auto).
    type: str
    choices: [ 'on', 'off', auto ]
  access_macsec_policy:
    description:
    - The access MACsec policy.
    - The value is available only when the mcp_admin_state is C(enabled).
    - The MACsec policy must be defined in the same fabric policy template.
    type: str
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
  Use M(cisco.mso.ndo_template) to create the Tenant template.
- The O(access_macsec_policy) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_macsec_policy) to create the MACsec policy.
- The O(domains) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_physical_domain) or M(cisco.mso.ndo_l3_domain) to create the domain.
- The O(synce) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_synce_interface_policy) to create the syncE policy.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_macsec_policy
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create an Interface policy group of interface_type physical
  cisco.mso.ndo_interface_setting:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    name: ansible_test_interface_policy_group_physical
    description: "Interface Policy Group for Ansible Test"
    interface_type: physical
    state: present

- name: Create an Interface policy group of interface_type port_channel
  cisco.mso.ndo_interface_setting:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    name: ansible_test_interface_policy_group_port_channel
    description: "Interface Policy Group for Ansible Test"
    interface_type: port_channel
    state: present

- name: Create an Interface policy group with all attributes
  cisco.mso.ndo_interface_setting:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    name: ansible_test_interface_policy_group_all
    description: "Interface Policy Group for Ansible Test"
    interface_type: port_channel
    speed: 1G
    auto_negotiation: on_enforce
    vlan_scope: port_local
    cdp_admin_state: enabled
    port_channel_mode: lacp_active
    min_links: 1
    max_links: 16
    controls: ["fast_sel_hot_stdby", "graceful_conv", "susp_individual"]
    load_balance_hashing: destination_ip
    synce: ansible_test_sync_e
    link_level_debounce_interval: 100
    link_level_bring_up_delay: 0
    link_level_fec: ieee_rs_fec
    l2_interface_qinq: edge_port
    l2_interface_reflective_relay: enabled
    lldp:
      status: enabled
      transmit_state: enabled
      receive_state: enabled
    domains:
      - ansible_test_domain1
      - ansible_test_domain2
    stp_bpdu_filter: enabled
    stp_bpdu_guard: enabled
    llfc_transmit_state: enabled
    llfc_receive_state: enabled
    mcp:
      admin_state: enabled
      strict_mode: 'on'
      initial_delay_time: 180
      transmission_frequency_sec: 2
      transmission_frequency_msec: 10
      grace_period_sec: 3
      grace_period_msec: 10
    pfc_admin_state: 'on'
    state: present

- name: Query all Interface policy groups
  cisco.mso.ndo_interface_setting:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    state: query
    register: query_all

- name: Query a specific Interface policy group with name
  cisco.mso.ndo_interface_setting:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    name: ansible_test_interface_policy_group_physical
    state: query
    register: query_one_name

- name: Query a specific Interface policy group with UUID
  cisco.mso.ndo_interface_setting:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    uuid: "{{ query_one_name.current.uuid }}"
    state: query
    register: query_one_uuid

- name: Delete an Interface policy group with name
  cisco.mso.ndo_interface_setting:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    name: ansible_test_interface_policy_group_physical
    state: absent

- name: Delete an Interface policy group with UUID
  cisco.mso.ndo_interface_setting:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    uuid: "{{ query_one_name.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import (
    PORT_CHANNEL_MODE_MAP,
    CONTROL_MAP,
    LINK_LEVEL_FEC_MAP,
    L2_INTERFACE_QINQ_MAP,
    LOAD_BALANCE_HASHING_MAP,
)
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        dict(
            template=dict(type="str", required=True),
            name=dict(type="str", aliases=["interface_policy_group", "interface_setting"]),
            uuid=dict(type="str", aliases=["interface_policy_group_uuid", "interface_setting_uuid"]),
            description=dict(type="str"),
            interface_type=dict(type="str", choices=["physical", "port_channel"]),
            speed=dict(type="str", choices=["100M", "1G", "10G", "25G", "40G", "50G", "100G", "200G", "400G", "inherit"]),
            auto_negotiation=dict(type="str", choices=["on", "off", "on_enforce"]),
            vlan_scope=dict(type="str", choices=["global", "port_local"]),
            cdp_admin_state=dict(type="str", choices=["enabled", "disabled"]),
            lldp=dict(
                type="dict",
                options=dict(
                    status=dict(type="str", choices=["enabled", "disabled"]),
                    transmit_state=dict(type="str", choices=["enabled", "disabled"]),
                    receive_state=dict(type="str", choices=["enabled", "disabled"]),
                ),
            ),
            domains=dict(type="list", elements="str"),
            port_channel_mode=dict(type="str", choices=list(PORT_CHANNEL_MODE_MAP)),
            min_links=dict(type="int"),
            max_links=dict(type="int"),
            controls=dict(type="list", elements="str", choices=list(CONTROL_MAP)),
            load_balance_hashing=dict(type="str", choices=list(LOAD_BALANCE_HASHING_MAP)),
            synce=dict(type="str"),
            link_level_debounce_interval=dict(type="int"),
            link_level_bring_up_delay=dict(type="int"),
            link_level_fec=dict(type="str", choices=list(LINK_LEVEL_FEC_MAP)),
            l2_interface_qinq=dict(type="str", choices=list(L2_INTERFACE_QINQ_MAP)),
            l2_interface_reflective_relay=dict(type="str", choices=["enabled", "disabled"]),
            stp_bpdu_filter=dict(type="str", choices=["enabled", "disabled"]),
            stp_bpdu_guard=dict(type="str", choices=["enabled", "disabled"]),
            llfc_transmit_state=dict(type="str", choices=["enabled", "disabled"]),
            llfc_receive_state=dict(type="str", choices=["enabled", "disabled"]),
            mcp=dict(
                type="dict",
                options=dict(
                    admin_state=dict(type="str", choices=["enabled", "disabled"]),
                    strict_mode=dict(type="str", choices=["on", "off"], aliases=["mcp_mode"]),
                    initial_delay_time=dict(type="int"),
                    transmission_frequency_sec=dict(type="int"),
                    transmission_frequency_msec=dict(type="int"),
                    grace_period_sec=dict(type="int"),
                    grace_period_msec=dict(type="int"),
                ),
            ),
            pfc_admin_state=dict(type="str", choices=["on", "off", "auto"]),
            access_macsec_policy=dict(type="str"),
            state=dict(type="str", choices=["absent", "query", "present"], default="query"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["name", "uuid"], True],
            ["state", "absent", ["name", "uuid"], True],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    interface_type = module.params.get("interface_type")
    if interface_type == "port_channel":
        interface_type = "portchannel"
    speed = module.params.get("speed")
    auto_negotiation = module.params.get("auto_negotiation")
    if auto_negotiation == "on_enforce":
        auto_negotiation = "on-enforce"
    vlan_scope = module.params.get("vlan_scope")
    if vlan_scope == "port_local":
        vlan_scope = "portlocal"
    cdp_admin_state = module.params.get("cdp_admin_state")
    lldp = module.params.get("lldp")
    domains = module.params.get("domains")
    port_channel_mode = PORT_CHANNEL_MODE_MAP.get(module.params.get("port_channel_mode"))
    min_links = module.params.get("min_links")
    max_links = module.params.get("max_links")
    controls = module.params.get("controls")
    if controls:
        controls = [CONTROL_MAP.get(v) for v in controls]
    load_balance_hashing = LOAD_BALANCE_HASHING_MAP.get(module.params.get("load_balance_hashing"))
    synce = module.params.get("synce")
    link_level_debounce_interval = module.params.get("link_level_debounce_interval")
    link_level_bring_up_delay = module.params.get("link_level_bring_up_delay")
    link_level_fec = LINK_LEVEL_FEC_MAP.get(module.params.get("link_level_fec"))
    l2_interface_qinq = L2_INTERFACE_QINQ_MAP.get(module.params.get("l2_interface_qinq"))
    l2_interface_reflective_relay = module.params.get("l2_interface_reflective_relay")
    stp_bpdu_filter = module.params.get("stp_bpdu_filter")
    stp_bpdu_guard = module.params.get("stp_bpdu_guard")
    llfc_transmit_state = module.params.get("llfc_transmit_state")
    llfc_receive_state = module.params.get("llfc_receive_state")
    mcp = module.params.get("mcp")
    pfc_admin_state = module.params.get("pfc_admin_state")
    access_macsec_policy = module.params.get("access_macsec_policy")
    state = module.params.get("state")

    ops = []
    match = None
    interface_path = None

    mso_template = MSOTemplate(mso, "fabric_policy", template)
    mso_template.validate_template("fabricPolicy")

    object_description = "Interface Policy Groups"

    template_info = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {})

    existing_interface_policies = template_info.get("interfacePolicyGroups", [])

    if state in ["query", "absent"] and existing_interface_policies == []:
        mso.exit_json()
    elif state == "query" and not (name or uuid):
        for interface in existing_interface_policies:
            map_interface_settings_ref_name(mso_template, template_info, interface, "uuid")
        mso.existing = existing_interface_policies
    elif existing_interface_policies and (name or uuid):
        match = mso_template.get_object_by_key_value_pairs(
            object_description, existing_interface_policies, [KVPair("uuid", uuid) if uuid else KVPair("name", name)]
        )
        if match:
            interface_path = "/fabricPolicyTemplate/template/interfacePolicyGroups/{0}".format(match.index)
            mso.existing = mso.previous = copy.deepcopy(map_interface_settings_ref_name(mso_template, template_info, match.details, "uuid"))

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        if mso.existing and match:
            proposed_payload = copy.deepcopy(match.details)

            if name and mso.existing.get("name") != name:
                ops.append(dict(op="replace", path=interface_path + "/name", value=name))
                proposed_payload["name"] = name

            if description is not None and mso.existing.get("description") != description:
                ops.append(dict(op="replace", path=interface_path + "/description", value=description))
                proposed_payload["description"] = description

            if interface_type and mso.existing.get("type") != interface_type:
                mso.fail_json(msg="Interface type cannot be changed.")

            if domains == []:
                ops.append(dict(op="remove", path=interface_path + "/domains"))
                proposed_payload.pop("domains", None)
            elif domains:
                domain_uuid_list, domain_uuid_name_list = validate_domains(mso, domains, template, template_info)
                if set(domain_uuid_list) != set(mso.existing.get("domains", [])):
                    ops.append(dict(op="replace", path=interface_path + "/domains", value=domain_uuid_list))
                proposed_payload["domains"] = domain_uuid_list

            if synce:
                existing_sync_e = validate_sync_e(mso, synce, template, template_info)
                if existing_sync_e[synce] != mso.existing.get("syncEthPolicy"):
                    ops.append(dict(op="replace", path=interface_path + "/syncEthPolicy", value=existing_sync_e[synce]))
                    proposed_payload["syncEthPolicy"] = existing_sync_e[synce]

            if access_macsec_policy:
                existing_access_macsec_policy = validate_macsec_policy(mso, access_macsec_policy, template, template_info)
                if existing_access_macsec_policy[access_macsec_policy] != mso.existing.get("accessMACsecPolicy"):
                    ops.append(dict(op="replace", path=interface_path + "/accessMACsecPolicy", value=existing_access_macsec_policy[access_macsec_policy]))
                    proposed_payload["accessMACsecPolicy"] = existing_access_macsec_policy[access_macsec_policy]

            if cdp_admin_state and mso.existing.get("cdp", {}).get("adminState") != cdp_admin_state:
                ops.append(dict(op="replace", path=interface_path + "/cdp/adminState", value=cdp_admin_state))
                proposed_payload["cdp"]["adminState"] = cdp_admin_state

            if pfc_admin_state and mso.existing.get("pfc", {}).get("adminState") != pfc_admin_state:
                ops.append(dict(op="replace", path=interface_path + "/pfc/adminState", value=pfc_admin_state))
                proposed_payload["pfc"]["adminState"] = pfc_admin_state

            if llfc_transmit_state and mso.existing.get("llfc", {}).get("transmitState") != llfc_transmit_state:
                ops.append(dict(op="replace", path=interface_path + "/llfc/transmitState", value=llfc_transmit_state))
                proposed_payload["llfc"]["transmitState"] = llfc_transmit_state

            if llfc_receive_state and mso.existing.get("llfc", {}).get("receiveState") != llfc_receive_state:
                ops.append(dict(op="replace", path=interface_path + "/llfc/receiveState", value=llfc_receive_state))
                proposed_payload["llfc"]["receiveState"] = llfc_receive_state

            if stp_bpdu_filter and mso.existing.get("stp", {}).get("bpduFilterEnabled") != stp_bpdu_filter:
                ops.append(dict(op="replace", path=interface_path + "/stp/bpduFilterEnabled", value=stp_bpdu_filter))
                proposed_payload["stp"]["bpduFilterEnabled"] = stp_bpdu_filter

            if stp_bpdu_guard and mso.existing.get("stp", {}).get("bpduGuardEnabled") != stp_bpdu_guard:
                ops.append(dict(op="replace", path=interface_path + "/stp/bpduGuardEnabled", value=stp_bpdu_guard))
                proposed_payload["stp"]["bpduGuardEnabled"] = stp_bpdu_guard

            if l2_interface_qinq and mso.existing.get("l2Interface", {}).get("qinq") != l2_interface_qinq:
                ops.append(dict(op="replace", path=interface_path + "/l2Interface/qinq", value=l2_interface_qinq))
                proposed_payload["l2Interface"]["qinq"] = l2_interface_qinq

            if l2_interface_reflective_relay and mso.existing.get("l2Interface", {}).get("reflectiveRelay") != l2_interface_reflective_relay:
                ops.append(dict(op="replace", path=interface_path + "/l2Interface/reflectiveRelay", value=l2_interface_reflective_relay))
                proposed_payload["l2Interface"]["reflectiveRelay"] = l2_interface_reflective_relay

            if vlan_scope and mso.existing.get("l2Interface", {}).get("vlanScope") != vlan_scope:
                ops.append(dict(op="replace", path=interface_path + "/l2Interface/vlanScope", value=vlan_scope))
                proposed_payload["l2Interface"]["vlanScope"] = vlan_scope

            if lldp:
                validate_lldp(mso, lldp)
                if lldp["receive_state"] and mso.existing.get("lldp", {}).get("receiveState") != lldp["receive_state"]:
                    ops.append(dict(op="replace", path=interface_path + "/lldp/receiveState", value=lldp["receive_state"]))
                    proposed_payload["lldp"]["receiveState"] = lldp["receive_state"]
                if lldp["transmit_state"] and mso.existing.get("lldp", {}).get("transmitState") != lldp["transmit_state"]:
                    ops.append(dict(op="replace", path=interface_path + "/lldp/transmitState", value=lldp["transmit_state"]))
                    proposed_payload["lldp"]["transmitState"] = lldp["transmit_state"]

            if link_level_debounce_interval and mso.existing.get("linkLevel", {}).get("debounceInterval") != link_level_debounce_interval:
                ops.append(dict(op="replace", path=interface_path + "/linkLevel/debounceInterval", value=link_level_debounce_interval))
                proposed_payload["linkLevel"]["debounceInterval"] = link_level_debounce_interval

            if link_level_bring_up_delay and mso.existing.get("linkLevel", {}).get("bringUpDelay") != link_level_bring_up_delay:
                ops.append(dict(op="replace", path=interface_path + "/linkLevel/bringUpDelay", value=link_level_bring_up_delay))
                proposed_payload["linkLevel"]["bringUpDelay"] = link_level_bring_up_delay

            if link_level_fec and mso.existing.get("linkLevel", {}).get("fec") != link_level_fec:
                ops.append(dict(op="replace", path=interface_path + "/linkLevel/fec", value=link_level_fec))
                proposed_payload["linkLevel"]["fec"] = link_level_fec

            if speed and mso.existing.get("linkLevel", {}).get("speed") != speed:
                ops.append(dict(op="replace", path=interface_path + "/linkLevel/speed", value=speed))
                proposed_payload["linkLevel"]["speed"] = speed

            if auto_negotiation and mso.existing.get("linkLevel", {}).get("autoNegotiation") != auto_negotiation:
                ops.append(dict(op="replace", path=interface_path + "/linkLevel/autoNegotiation", value=auto_negotiation))
                proposed_payload["linkLevel"]["autoNegotiation"] = auto_negotiation

            if mcp:
                if mcp["admin_state"] and mso.existing.get("mcp", {}).get("adminState") != mcp["admin_state"]:
                    ops.append(dict(op="replace", path=interface_path + "/mcp/adminState", value=mcp["admin_state"]))
                    proposed_payload["mcp"]["adminState"] = mcp["admin_state"]
                if mcp["strict_mode"] and mso.existing.get("mcp", {}).get("mcpMode") != mcp["strict_mode"]:
                    ops.append(dict(op="replace", path=interface_path + "/mcp/mcpMode", value=mcp["strict_mode"]))
                    proposed_payload["mcp"]["mcpMode"] = mcp["strict_mode"]
                if mcp["initial_delay_time"] and mso.existing.get("mcp", {}).get("initialDelayTime") != mcp["initial_delay_time"]:
                    ops.append(dict(op="replace", path=interface_path + "/mcp/initialDelayTime", value=mcp["initial_delay_time"]))
                    proposed_payload["mcp"]["initialDelayTime"] = mcp["initial_delay_time"]
                if mcp["transmission_frequency_sec"] and mso.existing.get("mcp", {}).get("txFreq") != mcp["transmission_frequency_sec"]:
                    ops.append(dict(op="replace", path=interface_path + "/mcp/txFreq", value=mcp["transmission_frequency_sec"]))
                    proposed_payload["mcp"]["txFreq"] = mcp["transmission_frequency_sec"]
                if mcp["transmission_frequency_msec"] and mso.existing.get("mcp", {}).get("txFreqMsec") != mcp["transmission_frequency_msec"]:
                    ops.append(dict(op="replace", path=interface_path + "/mcp/txFreqMsec", value=mcp["transmission_frequency_msec"]))
                    proposed_payload["mcp"]["txFreqMsec"] = mcp["transmission_frequency_msec"]
                if mcp["grace_period_sec"] and mso.existing.get("mcp", {}).get("gracePeriod") != mcp["grace_period_sec"]:
                    ops.append(dict(op="replace", path=interface_path + "/mcp/gracePeriod", value=mcp["grace_period_sec"]))
                    proposed_payload["mcp"]["gracePeriod"] = mcp["grace_period_sec"]
                if mcp["grace_period_msec"] and mso.existing.get("mcp", {}).get("gracePeriodMsec") != mcp["grace_period_msec"]:
                    ops.append(dict(op="replace", path=interface_path + "/mcp/gracePeriodMsec", value=mcp["grace_period_msec"]))
                    proposed_payload["mcp"]["gracePeriodMsec"] = mcp["grace_period_msec"]

            if port_channel_mode and mso.existing.get("portChannelPolicy", {}).get("mode") != port_channel_mode:
                ops.append(dict(op="replace", path=interface_path + "/portChannelPolicy/mode", value=port_channel_mode))
                proposed_payload["portChannelPolicy"]["mode"] = port_channel_mode

            if min_links and mso.existing.get("portChannelPolicy", {}).get("minLinks") != min_links:
                ops.append(dict(op="replace", path=interface_path + "/portChannelPolicy/minLinks", value=min_links))
                proposed_payload["portChannelPolicy"]["minLinks"] = min_links

            if max_links and mso.existing.get("portChannelPolicy", {}).get("maxLinks") != max_links:
                ops.append(dict(op="replace", path=interface_path + "/portChannelPolicy/maxLinks", value=max_links))
                proposed_payload["portChannelPolicy"]["maxLinks"] = max_links

            if load_balance_hashing and mso.existing.get("portChannelPolicy", {}).get("hashFields") != load_balance_hashing:
                ops.append(dict(op="replace", path=interface_path + "/portChannelPolicy/hashFields", value=load_balance_hashing))
                proposed_payload["portChannelPolicy"]["hashFields"] = load_balance_hashing

            if controls and mso.existing.get("portChannelPolicy", {}).get("control") != controls:
                ops.append(dict(op="replace", path=interface_path + "/portChannelPolicy/control", value=controls))
                proposed_payload["portChannelPolicy"]["control"] = controls
            elif controls == []:
                ops.append(dict(op="remove", path=interface_path + "/portChannelPolicy/control"))
                mso.existing.pop("controls", None)

            mso.sanitize(map_interface_settings_ref_name(mso_template, template_info, proposed_payload, "uuid"), collate=True)

        else:
            if not interface_type:
                mso.fail_json(msg="Error: Missing required argument 'interface_type' for creating an Interface Policy Group.")
            payload = {
                "name": name,
                "type": interface_type,
                "templateId": mso_template.template.get("templateId"),
                "schemaId": mso_template.template.get("schemaId"),
                "llfc": {},
                "stp": {},
                "l2Interface": {},
                "lldp": {},
                "linkLevel": {},
                "mcp": {},
                "portChannelPolicy": {},
            }

            if description:
                payload["description"] = description

            if domains:
                payload["domains"], domain_uuid_name_list = validate_domains(mso, domains, template, template_info)

            if synce:
                existing_sync_e = validate_sync_e(mso, synce, template, template_info)
                payload["syncEthPolicy"] = existing_sync_e[synce]

            if access_macsec_policy:
                existing_access_macsec_policy = validate_macsec_policy(mso, access_macsec_policy, template, template_info)
                payload["accessMACsecPolicy"] = existing_access_macsec_policy[access_macsec_policy]

            if cdp_admin_state:
                payload["cdp"] = {"adminState": cdp_admin_state}

            if pfc_admin_state:
                payload["pfc"] = {"adminState": pfc_admin_state}

            if llfc_transmit_state:
                payload["llfc"]["transmitState"] = llfc_transmit_state
            if llfc_receive_state:
                payload["llfc"]["receiveState"] = llfc_receive_state

            if stp_bpdu_filter:
                payload["stp"]["bpduFilterEnabled"] = stp_bpdu_filter
            if stp_bpdu_guard:
                payload["stp"]["bpduGuardEnabled"] = stp_bpdu_guard

            if l2_interface_qinq:
                payload["l2Interface"]["qinq"] = l2_interface_qinq
            if l2_interface_reflective_relay:
                payload["l2Interface"]["reflectiveRelay"] = l2_interface_reflective_relay
            if vlan_scope:
                payload["l2Interface"]["vlanScope"] = vlan_scope

            if lldp:
                validate_lldp(mso, lldp)
                payload["lldp"]["receiveState"] = lldp["receive_state"]
                payload["lldp"]["transmitState"] = lldp["transmit_state"]

            if link_level_debounce_interval:
                payload["linkLevel"]["debounceInterval"] = link_level_debounce_interval
            if link_level_bring_up_delay:
                payload["linkLevel"]["bringUpDelay"] = link_level_bring_up_delay
            if link_level_fec:
                payload["linkLevel"]["fec"] = link_level_fec
            if speed:
                payload["linkLevel"]["speed"] = speed
            if auto_negotiation:
                payload["linkLevel"]["autoNegotiation"] = auto_negotiation

            if mcp:
                if mcp["admin_state"]:
                    payload["mcp"]["adminState"] = mcp["admin_state"]
                if mcp["strict_mode"]:
                    payload["mcp"]["mcpMode"] = mcp["strict_mode"]
                if mcp["initial_delay_time"]:
                    payload["mcp"]["initialDelayTime"] = mcp["initial_delay_time"]
                if mcp["transmission_frequency_sec"]:
                    payload["mcp"]["txFreq"] = mcp["transmission_frequency_sec"]
                if mcp["transmission_frequency_msec"]:
                    payload["mcp"]["txFreqMsec"] = mcp["transmission_frequency_msec"]
                if mcp["grace_period_sec"]:
                    payload["mcp"]["gracePeriod"] = mcp["grace_period_sec"]
                if mcp["grace_period_msec"]:
                    payload["mcp"]["gracePeriodMsec"] = mcp["grace_period_msec"]

            if port_channel_mode:
                payload["portChannelPolicy"]["mode"] = port_channel_mode
            if min_links:
                payload["portChannelPolicy"]["minLinks"] = min_links
            if max_links:
                payload["portChannelPolicy"]["maxLinks"] = max_links
            if load_balance_hashing:
                payload["portChannelPolicy"]["hashFields"] = load_balance_hashing
            if controls:
                payload["portChannelPolicy"]["control"] = controls

            ops.append(dict(op="add", path="/fabricPolicyTemplate/template/interfacePolicyGroups/-", value=copy.deepcopy(payload)))
            mso.sanitize(map_interface_settings_ref_name(mso_template, template_info, payload, "uuid"))

        mso.existing = mso.proposed

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=interface_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        interface_policies = response.get("fabricPolicyTemplate", {}).get("template", {}).get("interfacePolicyGroups", [])
        match = mso_template.get_object_by_key_value_pairs(object_description, interface_policies, [KVPair("uuid", uuid) if uuid else KVPair("name", name)])
        if match:
            mso.existing = map_interface_settings_ref_name(mso_template, template_info, match.details, "uuid")  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = map_interface_settings_ref_name(mso_template, template_info, mso.proposed, "uuid") if state == "present" else {}

    mso.exit_json()


def map_interface_settings_ref_name(mso_template, template_info, interface_settings, domain_input_type="name"):
    if interface_settings.get("accessMACsecPolicy"):
        interface_settings["accessMACsecPolicyName"] = validate_macsec_policy(
            mso_template.mso, interface_settings.get("accessMACsecPolicy"), mso_template, template_info
        ).get(interface_settings["accessMACsecPolicy"])

    if interface_settings.get("syncEthPolicy"):
        interface_settings["syncEthPolicyName"] = validate_sync_e(mso_template.mso, interface_settings.get("syncEthPolicy"), mso_template, template_info).get(
            interface_settings["syncEthPolicy"]
        )

    if interface_settings.get("domains"):
        domain_uuid_list, interface_settings["domainsName"] = validate_domains(
            mso_template.mso, interface_settings.get("domains"), mso_template.template_name, template_info, domain_input_type
        )
    return interface_settings


def validate_domains(mso, domains, template, template_info, input_type="name"):
    domain_uuid_list = []
    domain_uuid_name_list = dict()
    # Combine physical and L3 domains into a single dictionary
    existing_domains = dict()

    for domain in template_info.get("domains", []):
        existing_domains[domain["name"]] = domain["uuid"]
        existing_domains[domain["uuid"]] = domain["name"]

    for domain in template_info.get("l3Domains", []):
        existing_domains[domain["name"]] = domain["uuid"]
        existing_domains[domain["uuid"]] = domain["name"]

    for domain in domains:
        if domain in existing_domains:
            if input_type == "name":
                domain_uuid_list.append(existing_domains[domain])
                domain_uuid_name_list[domain] = existing_domains[domain]
            else:
                domain_uuid_list.append(domain)
                domain_uuid_name_list[existing_domains[domain]] = domain
        else:
            mso.fail_json(msg="Domain '{0}' not found in the template '{1}'.".format(domain, template))
    return domain_uuid_list, domain_uuid_name_list


def validate_macsec_policy(mso, access_macsec_policy, template, template_info):
    existing_access_macsec_policy = dict()
    for macsec_policy in template_info.get("macsecPolicies", []):
        existing_access_macsec_policy[macsec_policy["name"]] = macsec_policy["uuid"]
        existing_access_macsec_policy[macsec_policy["uuid"]] = macsec_policy["name"]
    if access_macsec_policy not in existing_access_macsec_policy:
        mso.fail_json(msg="Access MACsec policy '{0}' not found in the template '{1}'.".format(access_macsec_policy, template))
    return existing_access_macsec_policy


def validate_sync_e(mso, synce, template, template_info):
    existing_sync_e = dict()
    for synceth_intf_policy in template_info.get("syncEthIntfPolicies", []):
        existing_sync_e[synceth_intf_policy["name"]] = synceth_intf_policy["uuid"]
        existing_sync_e[synceth_intf_policy["uuid"]] = synceth_intf_policy["name"]
    if synce not in existing_sync_e:
        mso.fail_json(msg="SyncE policy '{0}' not found in the template '{1}'.".format(synce, template))
    return existing_sync_e


def validate_lldp(mso, lldp):
    if lldp["status"] == "disabled" and not (lldp["receive_state"] == "disabled" and lldp["transmit_state"] == "disabled"):
        mso.fail_json(msg="LLDP receive_state and transmit_state must be 'disabled' when LLDP status is disabled.")


if __name__ == "__main__":
    main()
