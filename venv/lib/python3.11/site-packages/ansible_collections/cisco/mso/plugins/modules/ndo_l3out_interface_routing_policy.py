#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_l3out_interface_routing_policy
short_description: Manage L3Out Interface Routing Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Out Interface Routing Policies on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Sabari Jaganathan (@sajagana)
options:
  template:
    description:
    - The name of the template.
    - The template must be a Tenant Policy Template.
    type: str
    required: true
  name:
    description:
    - The name of the L3Out Interface Routing Policy.
    type: str
    aliases: [ l3out_interface_routing_policy_name ]
  uuid:
    description:
    - The UUID of the L3Out Interface Routing Policy.
    - This parameter is required when the O(name) needs to be updated.
    type: str
    aliases: [ l3out_interface_routing_policy_uuid ]
  description:
    description:
    - The description of the L3Out Interface Routing Policy.
    type: str
  bfd_multi_hop_settings:
    description:
    - The Bidirectional Forwarding Detection (BFD) multi-hop configuration of the L3Out Interface Routing Policy.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the BFD MultiHop Settings.
        - Use C(disabled) to remove the BFD MultiHop Settings.
        type: str
        choices: [ enabled, disabled ]
      admin_state:
        description:
        - The administrative state of the BFD MultiHop Settings.
        - Defaults to C(enabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      detection_multiplier:
        description:
        - The detection multiplier of the BFD MultiHop Settings.
        - Defaults to 3 when unset during creation.
        - The value must be between 1 and 50.
        type: int
      min_receive_interval:
        description:
        - The minimum receive interval of the BFD MultiHop Settings.
        - Defaults to 250 when unset during creation.
        - The value must be between 250 and 999 microseconds.
        type: int
      min_transmit_interval:
        description:
        - The minimum transmit interval of the BFD MultiHop Settings.
        - Defaults to 250 when unset during creation.
        - The value must be between 250 and 999 microseconds.
        type: int
  bfd_settings:
    description:
    - The BFD Settings of the L3Out Interface Routing Policy.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the BFD Settings.
        - Use C(disabled) to remove the BFD Settings.
        type: str
        choices: [ enabled, disabled ]
      admin_state:
        description:
        - The administrative state of the BFD Settings.
        - Defaults to C(enabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      detection_multiplier:
        description:
        - The detection multiplier of the BFD Settings.
        - Defaults to 3 when unset during creation.
        - The value must be between 1 and 50.
        type: int
      min_receive_interval:
        description:
        - The minimum receive interval in microseconds of the BFD Settings.
        - Defaults to 50 when unset during creation.
        - The value must be between 50 and 999.
        type: int
      min_transmit_interval:
        description:
        - The minimum transmit interval in microseconds of the BFD Settings.
        - Defaults to 50 when unset during creation.
        - The value must be between 50 and 999.
        type: int
      echo_receive_interval:
        description:
        - The echo receive interval in microseconds of the BFD Settings
        - Defaults to 50 when unset during creation.
        - The value must be between 50 and 999.
        type: int
      echo_admin_state:
        description:
        - The echo administrative state of the BFD Settings.
        - Defaults to C(enabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      interface_control:
        description:
        - The interface control of the BFD Settings.
        - Defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
  ospf_interface_settings:
    description:
    - The Open Shortest Path First (OSPF) Interface Settings of the L3Out Interface Routing Policy.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the OSPF Interface Settings.
        - Use C(disabled) to remove the OSPF Interface Settings.
        type: str
        choices: [ enabled, disabled ]
      network_type:
        description:
        - The network type of the OSPF Interface Settings.
        - Defaults to C(broadcast) when unset during creation.
        type: str
        choices: [ broadcast, point_to_point ]
      priority:
        description:
        - The priority of the OSPF Interface Settings.
        - Defaults to 1 when unset during creation.
        - The value must be between 0 and 255.
        type: int
      cost_of_interface:
        description:
        - The cost of the OSPF Interface Settings.
        - Defaults to 0 when unset during creation.
        - The value must be between 0 and 65535.
        type: int
      hello_interval:
        description:
        - The hello interval in seconds of the OSPF Interface Settings.
        - Defaults to 10 when unset during creation.
        - The value must be between 1 and 65535.
        type: int
      dead_interval:
        description:
        - The dead interval in seconds of the OSPF Interface Settings.
        - Defaults to 40 when unset during creation.
        - The value must be between 1 and 65535.
        type: int
      retransmit_interval:
        description:
        - The retransmit interval in seconds of the OSPF Interface Settings.
        - Defaults to 5 when unset during creation.
        - The value must be between 1 and 65535.
        type: int
      transmit_delay:
        description:
        - The transmit delay in seconds of the OSPF Interface Settings.
        - Defaults to 1 when unset during creation.
        - The value must be between 1 and 450.
        type: int
      advertise_subnet:
        description:
        - The advertise subnet of the OSPF Interface Settings.
        - Defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      bfd:
        description:
        - Enables or disables BFD in the OSPF Interface Settings.
        - Defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      mtu_ignore:
        description:
        - Enables or disables ignoring the Maximum Transmission Unit (MTU) in the OSPF Interface Settings.
        - Defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      passive_participation:
        description:
        - Enables or disables passive participation in the OSPF Interface Settings.
        - Defaults to C(disabled) when unset during creation.
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
  Use M(cisco.mso.ndo_template) to create the Tenant Policy Template.
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new L3Out Interface Routing Policy with default values
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: irp_1
    bfd_settings:
      state: enabled
    bfd_multi_hop_settings:
      state: enabled
    state: present
  register: irp_1_present

- name: Update an existing L3Out Interface Routing Policy with UUID
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ irp_1_present.current.uuid }}"
    name: irp_1_updated
    bfd_multi_hop_settings:
      admin_state: disabled
      detection_multiplier: 10
      min_receive_interval: 255
      min_transmit_interval: 255
    bfd_settings:
      admin_state: disabled
      detection_multiplier: 10
      min_receive_interval: 266
      min_transmit_interval: 266
      echo_receive_interval: 60
      echo_admin_state: disabled
      interface_control: enabled
    ospf_interface_settings:
      network_type: point_to_point
      priority: 10
      cost_of_interface: 100
      advertise_subnet: enabled
      bfd: enabled
      mtu_ignore: enabled
      passive_participation: enabled
      hello_interval: 20
      dead_interval: 30
      retransmit_interval: 20
      transmit_delay: 10
    state: present
  register: irp_1_present

- name: Clear an existing L3Out Interface Routing Policy BFD and OSPF interface settings
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ irp_1_present.current.uuid }}"
    bfd_settings:
      state: disabled
    ospf_interface_settings:
      state: disabled
    state: present

- name: Query an L3Out Interface Routing Policy with name
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: irp_1_updated
    state: query
  register: query_with_name

- name: Query an L3Out Interface Routing Policy with UUID
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ irp_1_present.current.uuid }}"
    state: query
  register: query_with_uuid

- name: Query all L3Out Interface Routing Policies
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    state: query
  register: query_all

- name: Delete an L3Out Interface Routing Policy
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: irp_1_updated
    state: absent

- name: Delete an L3Out Interface Routing Policy using UUID
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ irp_1_present.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, ndo_bfd_multi_hop_settings_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.constants import ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True),
        uuid=dict(type="str", aliases=["l3out_interface_routing_policy_uuid"]),
        name=dict(type="str", aliases=["l3out_interface_routing_policy_name"]),
        description=dict(type="str"),
        bfd_settings=dict(
            type="dict",
            options=dict(
                state=dict(type="str", choices=["enabled", "disabled"]),
                admin_state=dict(type="str", choices=["enabled", "disabled"]),
                detection_multiplier=dict(type="int"),
                min_receive_interval=dict(type="int"),
                min_transmit_interval=dict(type="int"),
                echo_receive_interval=dict(type="int"),
                echo_admin_state=dict(type="str", choices=["enabled", "disabled"]),
                interface_control=dict(type="str", choices=["enabled", "disabled"]),
            ),
        ),
        bfd_multi_hop_settings=ndo_bfd_multi_hop_settings_spec(),
        ospf_interface_settings=dict(
            type="dict",
            options=dict(
                state=dict(type="str", choices=["enabled", "disabled"]),
                network_type=dict(type="str", choices=["broadcast", "point_to_point"]),
                priority=dict(type="int"),
                cost_of_interface=dict(type="int"),
                advertise_subnet=dict(type="str", choices=["enabled", "disabled"]),
                bfd=dict(type="str", choices=["enabled", "disabled"]),
                mtu_ignore=dict(type="str", choices=["enabled", "disabled"]),
                passive_participation=dict(type="str", choices=["enabled", "disabled"]),
                hello_interval=dict(type="int"),
                dead_interval=dict(type="int"),
                retransmit_interval=dict(type="int"),
                transmit_delay=dict(type="int"),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    bfd_settings = module.params.get("bfd_settings")
    bfd_multi_hop_settings = module.params.get("bfd_multi_hop_settings")
    ospf_interface_settings = module.params.get("ospf_interface_settings")
    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "tenant", template)
    mso_template.validate_template("tenantPolicy")

    l3out_interface_routing_policy = mso_template.get_l3out_interface_routing_policy_object(uuid, name)

    if (uuid or name) and l3out_interface_routing_policy:
        mso.existing = mso.previous = copy.deepcopy(l3out_interface_routing_policy.details)  # Query a specific object
    elif l3out_interface_routing_policy:
        mso.existing = l3out_interface_routing_policy  # Query all objects

    if state != "query":
        interface_routing_policy_path = "/tenantPolicyTemplate/template/l3OutIntfPolGroups/{0}".format(
            l3out_interface_routing_policy.index if l3out_interface_routing_policy else "-"
        )

    ops = []
    if state == "present":
        if mso.existing:
            proposed_payload = copy.deepcopy(mso.existing)
            mso_values = dict()
            mso_values_remove = list()

            mso_values["name"] = name
            mso_values["description"] = description

            # BFD MultiHop Settings
            if bfd_multi_hop_settings is not None:
                if bfd_multi_hop_settings.get("state") == "disabled" and proposed_payload.get("bfdMultiHopPol"):
                    mso_values_remove.append("bfdMultiHopPol")

                elif bfd_multi_hop_settings.get("state") != "disabled":
                    if not proposed_payload.get("bfdMultiHopPol"):
                        mso_values["bfdMultiHopPol"] = dict()

                    mso_values[("bfdMultiHopPol", "adminState")] = bfd_multi_hop_settings.get("admin_state")
                    mso_values[("bfdMultiHopPol", "detectionMultiplier")] = bfd_multi_hop_settings.get("detection_multiplier")
                    mso_values[("bfdMultiHopPol", "minRxInterval")] = bfd_multi_hop_settings.get("min_receive_interval")
                    mso_values[("bfdMultiHopPol", "minTxInterval")] = bfd_multi_hop_settings.get("min_transmit_interval")

            # BFD Settings
            if bfd_settings is not None:
                if bfd_settings.get("state") == "disabled" and proposed_payload.get("bfdPol"):
                    mso_values_remove.append("bfdPol")

                elif bfd_settings.get("state") != "disabled":
                    if not proposed_payload.get("bfdPol"):
                        mso_values["bfdPol"] = dict()

                    mso_values[("bfdPol", "adminState")] = bfd_settings.get("admin_state")
                    mso_values[("bfdPol", "detectionMultiplier")] = bfd_settings.get("detection_multiplier")
                    mso_values[("bfdPol", "minRxInterval")] = bfd_settings.get("min_receive_interval")
                    mso_values[("bfdPol", "minTxInterval")] = bfd_settings.get("min_transmit_interval")
                    mso_values[("bfdPol", "echoRxInterval")] = bfd_settings.get("echo_receive_interval")
                    mso_values[("bfdPol", "echoAdminState")] = bfd_settings.get("echo_admin_state")
                    mso_values[("bfdPol", "ifControl")] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(bfd_settings.get("interface_control"))

            # OSPF Interface Settings
            if ospf_interface_settings is not None:
                if ospf_interface_settings.get("state") == "disabled" and proposed_payload.get("ospfIntfPol"):
                    mso_values_remove.append(("ospfIntfPol",))

                elif ospf_interface_settings.get("state") != "disabled":
                    if not proposed_payload.get("ospfIntfPol"):
                        mso_values[("ospfIntfPol")] = dict()
                        mso_values[("ospfIntfPol", "ifControl")] = dict()

                    mso_values[("ospfIntfPol", "networkType")] = (
                        "pointToPoint" if ospf_interface_settings.get("network_type") == "point_to_point" else ospf_interface_settings.get("network_type")
                    )
                    mso_values[("ospfIntfPol", "prio")] = ospf_interface_settings.get("priority")
                    mso_values[("ospfIntfPol", "cost")] = ospf_interface_settings.get("cost_of_interface")
                    mso_values[("ospfIntfPol", "helloInterval")] = ospf_interface_settings.get("hello_interval")
                    mso_values[("ospfIntfPol", "deadInterval")] = ospf_interface_settings.get("dead_interval")
                    mso_values[("ospfIntfPol", "retransmitInterval")] = ospf_interface_settings.get("retransmit_interval")
                    mso_values[("ospfIntfPol", "transmitDelay")] = ospf_interface_settings.get("transmit_delay")
                    mso_values[("ospfIntfPol", "ifControl", "advertiseSubnet")] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(
                        ospf_interface_settings.get("advertise_subnet")
                    )
                    mso_values[("ospfIntfPol", "ifControl", "bfd")] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(ospf_interface_settings.get("bfd"))
                    mso_values[("ospfIntfPol", "ifControl", "ignoreMtu")] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(
                        ospf_interface_settings.get("mtu_ignore")
                    )
                    mso_values[("ospfIntfPol", "ifControl", "passiveParticipation")] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(
                        ospf_interface_settings.get("passive_participation")
                    )

            append_update_ops_data(ops, proposed_payload, interface_routing_policy_path, mso_values, mso_values_remove)
            mso.sanitize(proposed_payload)
        else:
            mso_values = dict(name=name, description=description)

            # OSPF Interface Settings
            if ospf_interface_settings is not None:
                ospf_interface_pol = dict()
                interface_controls = dict()

                if ospf_interface_settings.get("advertise_subnet"):
                    interface_controls["advertiseSubnet"] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(ospf_interface_settings.get("advertise_subnet"))

                if ospf_interface_settings.get("bfd"):
                    interface_controls["bfd"] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(ospf_interface_settings.get("bfd"))

                if ospf_interface_settings.get("mtu_ignore"):
                    interface_controls["ignoreMtu"] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(ospf_interface_settings.get("mtu_ignore"))

                if ospf_interface_settings.get("passive_participation"):
                    interface_controls["passiveParticipation"] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(
                        ospf_interface_settings.get("passive_participation")
                    )

                if interface_controls:
                    ospf_interface_pol["ifControl"] = interface_controls

                if ospf_interface_settings.get("network_type"):
                    ospf_interface_pol["networkType"] = (
                        "pointToPoint" if ospf_interface_settings.get("network_type") == "point_to_point" else ospf_interface_settings.get("network_type")
                    )

                if ospf_interface_settings.get("priority"):
                    ospf_interface_pol["prio"] = ospf_interface_settings.get("priority")

                if ospf_interface_settings.get("cost_of_interface"):
                    ospf_interface_pol["cost"] = ospf_interface_settings.get("cost_of_interface")

                if ospf_interface_settings.get("hello_interval"):
                    ospf_interface_pol["helloInterval"] = ospf_interface_settings.get("hello_interval")

                if ospf_interface_settings.get("dead_interval"):
                    ospf_interface_pol["deadInterval"] = ospf_interface_settings.get("dead_interval")

                if ospf_interface_settings.get("retransmit_interval"):
                    ospf_interface_pol["retransmitInterval"] = ospf_interface_settings.get("retransmit_interval")

                if ospf_interface_settings.get("transmit_delay"):
                    ospf_interface_pol["transmitDelay"] = ospf_interface_settings.get("transmit_delay")

                if ospf_interface_pol or ospf_interface_settings.get("state") == "enabled":
                    mso_values["ospfIntfPol"] = ospf_interface_pol

            # BFD MultiHop Settings
            if bfd_multi_hop_settings is not None:
                bfd_multi_hop_pol = dict()
                if bfd_multi_hop_settings.get("admin_state"):
                    bfd_multi_hop_pol["adminState"] = bfd_multi_hop_settings.get("admin_state")

                if bfd_multi_hop_settings.get("detection_multiplier"):
                    bfd_multi_hop_pol["detectionMultiplier"] = bfd_multi_hop_settings.get("detection_multiplier")

                if bfd_multi_hop_settings.get("min_receive_interval"):
                    bfd_multi_hop_pol["minRxInterval"] = bfd_multi_hop_settings.get("min_receive_interval")

                if bfd_multi_hop_settings.get("min_transmit_interval"):
                    bfd_multi_hop_pol["minTxInterval"] = bfd_multi_hop_settings.get("min_transmit_interval")

                if bfd_multi_hop_pol or bfd_multi_hop_settings.get("state") == "enabled":
                    mso_values["bfdMultiHopPol"] = bfd_multi_hop_pol

            # BFD Settings
            if bfd_settings is not None:
                bfd_settings_map = dict()

                if bfd_settings.get("admin_state"):
                    bfd_settings_map["adminState"] = bfd_settings.get("admin_state")

                if bfd_settings.get("detection_multiplier"):
                    bfd_settings_map["detectionMultiplier"] = bfd_settings.get("detection_multiplier")

                if bfd_settings.get("min_receive_interval"):
                    bfd_settings_map["minRxInterval"] = bfd_settings.get("min_receive_interval")

                if bfd_settings.get("min_transmit_interval"):
                    bfd_settings_map["minTxInterval"] = bfd_settings.get("min_transmit_interval")

                if bfd_settings.get("echo_receive_interval"):
                    bfd_settings_map["echoRxInterval"] = bfd_settings.get("echo_receive_interval")

                if bfd_settings.get("echo_admin_state"):
                    bfd_settings_map["echoAdminState"] = bfd_settings.get("echo_admin_state")

                if bfd_settings.get("interface_control"):
                    bfd_settings_map["ifControl"] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(bfd_settings.get("interface_control"))

                if bfd_settings_map or bfd_settings.get("state") == "enabled":
                    mso_values["bfdPol"] = bfd_settings_map

            ops.append(dict(op="add", path=interface_routing_policy_path, value=copy.deepcopy(mso_values)))

            mso.sanitize(mso_values)
    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path=interface_routing_policy_path))

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        l3out_interface_routing_policy = mso_template.get_l3out_interface_routing_policy_object(uuid, name)
        if l3out_interface_routing_policy:
            mso.existing = l3out_interface_routing_policy.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
