#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["deprecated"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
author:
  - Kevin Breit (@kbreit)
deprecated:
  alternative: cisco.meraki.devices_switch_ports
  removed_in: 3.0.0
  why: Updated modules released with increased functionality
description:
  - Allows for management of switchports settings for Meraki MS switches.
extends_documentation_fragment: cisco.meraki.meraki
module: meraki_ms_switchport
options:
  access_policy_number:
    description:
      - Number of the access policy to apply.
      - Only applicable to access port types.
    type: int
  access_policy_type:
    choices:
      - Open
      - Custom access policy
      - MAC allow list
      - Sticky MAC allow list
    description:
      - Type of access policy to apply to port.
    type: str
  allowed_vlans:
    default: all
    description:
      - List of VLAN numbers to be allowed on switchport.
    elements: str
    type: list
  enabled:
    default: true
    description:
      - Whether a switchport should be enabled or disabled.
    type: bool
  flexible_stacking_enabled:
    description:
      - Whether flexible stacking capabilities are supported on the port.
    type: bool
  isolation_enabled:
    default: false
    description:
      - Isolation status of switchport.
    type: bool
  link_negotiation:
    choices:
      - 1 Gigabit full duplex (auto)
      - 1 Gigabit full duplex (forced)
      - 10 Gigabit full duplex (auto)
      - 10 Gigabit full duplex (forced)
      - 100 Megabit (auto)
      - 100 Megabit full duplex (forced)
      - 2.5 Gigabit full duplex (auto)
      - 2.5 Gigabit full duplex (forced)
      - 5 Gigabit full duplex (auto)
      - 5 Gigabit full duplex (forced)
      - Auto negotiate
    default: Auto negotiate
    description:
      - Link speed for the switchport.
    type: str
  mac_allow_list:
    description:
      - MAC addresses list that are allowed on a port.
      - Only applicable to access port type.
      - Only applicable to access_policy_type "MAC allow list".
    suboptions:
      macs:
        description:
          - List of MAC addresses to update with based on state option.
        elements: str
        type: list
      state:
        choices:
          - merged
          - replaced
          - deleted
        default: replaced
        description:
          - The state the configuration should be left in.
          - Merged, MAC addresses provided will be added to the current allow list.
          - Replaced, All MAC addresses are overwritten, only the MAC addresses provided
            with exist in the allow list.
          - Deleted, Remove the MAC addresses provided from the current allow list.
        type: str
    type: dict
  name:
    aliases:
      - description
    description:
      - Switchport description.
    type: str
  number:
    description:
      - Port number.
    type: str
  poe_enabled:
    default: true
    description:
      - Enable or disable Power Over Ethernet on a port.
    type: bool
  rstp_enabled:
    default: true
    description:
      - Enable or disable Rapid Spanning Tree Protocol on a port.
    type: bool
  serial:
    description:
      - Serial nubmer of the switch.
    required: true
    type: str
  state:
    choices:
      - query
      - present
    default: query
    description:
      - Specifies whether a switchport should be queried or modified.
    type: str
  sticky_mac_allow_list:
    description:
      - MAC addresses list that are allowed on a port.
      - Only applicable to access port type.
      - Only applicable to access_policy_type "Sticky MAC allow list".
    suboptions:
      macs:
        description:
          - List of MAC addresses to update with based on state option.
        elements: str
        type: list
      state:
        choices:
          - merged
          - replaced
          - deleted
        default: replaced
        description:
          - The state the configuration should be left in.
          - Merged, MAC addresses provided will be added to the current allow list.
          - Replaced, All MAC addresses are overwritten, only the MAC addresses provided
            with exist in the allow list.
          - Deleted, Remove the MAC addresses provided from the current allow list.
        type: str
    type: dict
  sticky_mac_allow_list_limit:
    description:
      - The number of MAC addresses allowed in the sticky port allow list.
      - Only applicable to access port type.
      - Only applicable to access_policy_type "Sticky MAC allow list".
      - The value must be equal to or greater then the list size of sticky_mac_allow_list.
        Value will be checked for validity, during processing.
    type: int
  stp_guard:
    choices:
      - disabled
      - root guard
      - bpdu guard
      - loop guard
    default: disabled
    description:
      - Set state of STP guard.
    type: str
  tags:
    description:
      - List of tags to assign to a port.
    elements: str
    type: list
  type:
    choices:
      - access
      - trunk
    default: access
    description:
      - Set port type.
    type: str
  vlan:
    description:
      - VLAN number assigned to port.
      - If a port is of type trunk, the specified VLAN is the native VLAN.
      - Setting value to 0 on a trunk will clear the VLAN.
    type: int
  voice_vlan:
    description:
      - VLAN number assigned to a port for voice traffic.
      - Only applicable to access port type.
      - Only applicable if voice_vlan_state is set to present.
    type: int
  voice_vlan_state:
    choices:
      - absent
      - present
    default: present
    description:
      - Specifies whether voice vlan configuration should be present or absent.
    type: str
short_description: Manage switchports on a switch in the Meraki cloud
"""

EXAMPLES = r"""
- name: Query information about all switchports on a switch
  meraki_switchport:
    auth_key: abc12345
    state: query
    serial: ABC-123
  delegate_to: localhost
- name: Query information about all switchports on a switch
  meraki_switchport:
    auth_key: abc12345
    state: query
    serial: ABC-123
    number: 2
  delegate_to: localhost
- name: Name switchport
  meraki_switchport:
    auth_key: abc12345
    state: present
    serial: ABC-123
    number: 7
    name: Test Port
  delegate_to: localhost
- name: Configure access port with voice VLAN
  meraki_switchport:
    auth_key: abc12345
    state: present
    serial: ABC-123
    number: 7
    enabled: true
    name: Test Port
    tags: desktop
    type: access
    vlan: 10
    voice_vlan: 11
  delegate_to: localhost
- name: Check access port for idempotency
  meraki_switchport:
    auth_key: abc12345
    state: present
    serial: ABC-123
    number: 7
    enabled: true
    name: Test Port
    tags: desktop
    type: access
    vlan: 10
    voice_vlan: 11
  delegate_to: localhost
- name: Configure trunk port with specific VLANs
  meraki_switchport:
    auth_key: abc12345
    state: present
    serial: ABC-123
    number: 7
    enabled: true
    name: Server port
    tags: server
    type: trunk
    allowed_vlans:
      - 10
      - 15
      - 20
  delegate_to: localhost
- name: Configure access port with sticky MAC allow list and limit.
  meraki_switchport:
    auth_key: abc12345
    state: present
    serial: ABC-123
    number: 5
    sticky_mac_allow_limit: 3
    sticky_mac_allow_list:
      macs:
        - aa:aa:bb:bb:cc:cc
        - bb:bb:aa:aa:cc:cc
        - 11:aa:bb:bb:cc:cc
      state: replaced
    delegate_to: localhost
- name: Delete an existing MAC address from the sticky MAC allow list.
  meraki_switchport:
    auth_key: abc12345
    state: present
    serial: ABC-123
    number: 5
    sticky_mac_allow_list:
      macs:
        - aa:aa:bb:bb:cc:cc
      state: deleted
    delegate_to: localhost
- name: Add a MAC address to sticky MAC allow list.
  meraki_switchport:
    auth_key: abc12345
    state: present
    serial: ABC-123
    number: 5
    sticky_mac_allow_list:
      macs:
        - 22:22:bb:bb:cc:cc
      state: merged
    delegate_to: localhost
"""

RETURN = r"""
data:
    description: Information queried or updated switchports.
    returned: success
    type: complex
    contains:
        access_policy_type:
            description: Type of access policy assigned to port
            returned: success, when assigned
            type: str
            sample: "MAC allow list"
        allowed_vlans:
            description: List of VLANs allowed on an access port
            returned: success, when port is set as access
            type: str
            sample: all
        number:
            description: Number of port.
            returned: success
            type: int
            sample: 1
        name:
            description: Human friendly description of port.
            returned: success
            type: str
            sample: "Jim Phone Port"
        tags:
            description: List of tags assigned to port.
            returned: success
            type: list
            sample: ['phone', 'marketing']
        enabled:
            description: Enabled state of port.
            returned: success
            type: bool
            sample: true
        poe_enabled:
            description: Power Over Ethernet enabled state of port.
            returned: success
            type: bool
            sample: true
        type:
            description: Type of switchport.
            returned: success
            type: str
            sample: trunk
        vlan:
            description: VLAN assigned to port.
            returned: success
            type: int
            sample: 10
        voice_vlan:
            description: VLAN assigned to port with voice VLAN enabled devices.
            returned: success
            type: int
            sample: 20
        isolation_enabled:
            description: Port isolation status of port.
            returned: success
            type: bool
            sample: true
        rstp_enabled:
            description: Enabled or disabled state of Rapid Spanning Tree Protocol (RSTP)
            returned: success
            type: bool
            sample: true
        stp_guard:
            description: State of STP guard
            returned: success
            type: str
            sample: "Root Guard"
        access_policy_number:
            description: Number of assigned access policy. Only applicable to access ports.
            returned: success
            type: int
            sample: 1234
        link_negotiation:
            description: Link speed for the port.
            returned: success
            type: str
            sample: "Auto negotiate"
        sticky_mac_allow_list_limit:
            description: Number of MAC addresses allowed on a sticky port.
            returned: success
            type: int
            sample: 6
        sticky_mac_allow_list:
            description: List of MAC addresses currently allowed on a sticky port. Used with access_policy_type of Sticky MAC allow list.
            returned: success
            type: list
            sample: ["11:aa:bb:bb:cc:cc", "22:aa:bb:bb:cc:cc", "33:aa:bb:bb:cc:cc"]
        mac_allow_list:
            description: List of MAC addresses currently allowed on a non-sticky port. Used with access_policy_type of MAC allow list.
            returned: success
            type: list
            sample: ["11:aa:bb:bb:cc:cc", "22:aa:bb:bb:cc:cc", "33:aa:bb:bb:cc:cc"]
        port_schedule_id:
            description: Unique ID of assigned port schedule
            returned: success
            type: str
            sample: null
        udld:
            description: Alert state of UDLD
            returned: success
            type: str
            sample: "Alert only"
        flexible_stacking_enabled:
            description: Whether flexible stacking capabilities are enabled on the port.
            returned: success
            type: bool
"""

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import (
    MerakiModule,
    meraki_argument_spec,
)

param_map = {
    "access_policy_number": "accessPolicyNumber",
    "access_policy_type": "accessPolicyType",
    "allowed_vlans": "allowedVlans",
    "enabled": "enabled",
    "isolation_enabled": "isolationEnabled",
    "link_negotiation": "linkNegotiation",
    "name": "name",
    "number": "number",
    "poe_enabled": "poeEnabled",
    "rstp_enabled": "rstpEnabled",
    "stp_guard": "stpGuard",
    "tags": "tags",
    "type": "type",
    "vlan": "vlan",
    "voice_vlan": "voiceVlan",
    "mac_allow_list": "macAllowList",
    "sticky_mac_allow_list": "stickyMacAllowList",
    "sticky_mac_allow_list_limit": "stickyMacAllowListLimit",
    "adaptive_policy_group_id": "adaptivePolicyGroupId",
    "peer_sgt_capable": "peerSgtCapable",
    "flexible_stacking_enabled": "flexibleStackingEnabled",
}


def sort_vlans(meraki, vlans):
    converted = set()
    for vlan in vlans:
        converted.add(int(vlan))
    vlans_sorted = sorted(converted)
    vlans_str = []
    for vlan in vlans_sorted:
        vlans_str.append(str(vlan))
    return ",".join(vlans_str)


def assemble_payload(meraki):
    payload = dict()
    # if meraki.params['enabled'] is not None:
    #     payload['enabled'] = meraki.params['enabled']

    for k, v in meraki.params.items():
        try:
            if meraki.params[k] is not None:
                if k == "access_policy_number":
                    if meraki.params["access_policy_type"] is not None:
                        payload[param_map[k]] = v
                else:
                    payload[param_map[k]] = v
        except KeyError:
            pass
    return payload


def get_mac_list(original_allowed, new_mac_list, state):
    if state == "deleted":
        return [entry for entry in original_allowed if entry not in new_mac_list]
    if state == "merged":
        return original_allowed + list(set(new_mac_list) - set(original_allowed))
    return new_mac_list


def clear_vlan(params, payload):
    if params["vlan"] == 0:
        payload["vlan"] = None
    return payload


def main():
    # define the available arguments/parameters that a user can pass to
    # the module
    argument_spec = meraki_argument_spec()

    policy_data_arg_spec = dict(
        macs=dict(type="list", elements="str"),
        state=dict(
            type="str", choices=["merged", "replaced", "deleted"], default="replaced"
        ),
    )

    argument_spec.update(
        state=dict(type="str", choices=["present", "query"], default="query"),
        serial=dict(type="str", required=True),
        number=dict(type="str"),
        name=dict(type="str", aliases=["description"]),
        tags=dict(type="list", elements="str"),
        enabled=dict(type="bool", default=True),
        type=dict(type="str", choices=["access", "trunk"], default="access"),
        vlan=dict(type="int"),
        voice_vlan=dict(type="int"),
        voice_vlan_state=dict(
            type="str", choices=["present", "absent"], default="present"
        ),
        allowed_vlans=dict(type="list", elements="str", default="all"),
        poe_enabled=dict(type="bool", default=True),
        isolation_enabled=dict(type="bool", default=False),
        rstp_enabled=dict(type="bool", default=True),
        stp_guard=dict(
            type="str",
            choices=["disabled", "root guard", "bpdu guard", "loop guard"],
            default="disabled",
        ),
        access_policy_type=dict(
            type="str",
            choices=[
                "Open",
                "Custom access policy",
                "MAC allow list",
                "Sticky MAC allow list",
            ],
        ),
        access_policy_number=dict(type="int"),
        link_negotiation=dict(
            type="str",
            choices=[
                "1 Gigabit full duplex (auto)",
                "1 Gigabit full duplex (forced)",
                "10 Gigabit full duplex (auto)",
                "10 Gigabit full duplex (forced)",
                "100 Megabit (auto)",
                "100 Megabit full duplex (forced)",
                "2.5 Gigabit full duplex (auto)",
                "2.5 Gigabit full duplex (forced)",
                "5 Gigabit full duplex (auto)",
                "5 Gigabit full duplex (forced)",
                "Auto negotiate",
            ],
            default="Auto negotiate",
        ),
        mac_allow_list=dict(type="dict", options=policy_data_arg_spec),
        sticky_mac_allow_list=dict(type="dict", options=policy_data_arg_spec),
        sticky_mac_allow_list_limit=dict(type="int"),
        # adaptive_policy_group_id=dict(type=str),
        # peer_sgt_capable=dict(type=bool),
        flexible_stacking_enabled=dict(type="bool"),
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    meraki = MerakiModule(module, function="switchport")
    if meraki.params.get("voice_vlan_state") == "absent" and meraki.params.get(
        "voice_vlan"
    ):
        meraki.fail_json(
            msg="voice_vlan_state cant be `absent` while voice_vlan is also defined."
        )

    meraki.params["follow_redirects"] = "all"

    if meraki.params["type"] == "trunk":
        if not meraki.params["allowed_vlans"]:
            meraki.params["allowed_vlans"] = [
                "all"
            ]  # Backdoor way to set default without conflicting on access

    query_urls = {"switchport": "/devices/{serial}/switch/ports"}
    query_url = {"switchport": "/devices/{serial}/switch/ports/{number}"}
    update_url = {"switchport": "/devices/{serial}/switch/ports/{number}"}

    meraki.url_catalog["get_all"].update(query_urls)
    meraki.url_catalog["get_one"].update(query_url)
    meraki.url_catalog["update"] = update_url

    # execute checks for argument completeness

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    if meraki.params["state"] == "query":
        if meraki.params["number"]:
            path = meraki.construct_path(
                "get_one",
                custom={
                    "serial": meraki.params["serial"],
                    "number": meraki.params["number"],
                },
            )
            response = meraki.request(path, method="GET")
            meraki.result["data"] = response
        else:
            path = meraki.construct_path(
                "get_all", custom={"serial": meraki.params["serial"]}
            )
            response = meraki.request(path, method="GET")
            meraki.result["data"] = response
    elif meraki.params["state"] == "present":
        payload = assemble_payload(meraki)
        # meraki.fail_json(msg='payload', payload=payload)
        allowed = set()  # Use a set to remove duplicate items
        if meraki.params["allowed_vlans"][0] == "all":
            allowed.add("all")
        else:
            for vlan in meraki.params["allowed_vlans"]:
                allowed.add(str(vlan))
            if meraki.params["vlan"] is not None:
                allowed.add(str(meraki.params["vlan"]))
        if len(allowed) > 1:  # Convert from list to comma separated
            payload["allowedVlans"] = sort_vlans(meraki, allowed)
        else:
            payload["allowedVlans"] = next(iter(allowed))

        # Exceptions need to be made for idempotency check based on how Meraki returns
        if meraki.params["type"] == "access":
            if not meraki.params[
                "vlan"
            ]:  # VLAN needs to be specified in access ports, but can't default to it
                payload["vlan"] = 1
        query_path = meraki.construct_path(
            "get_one",
            custom={
                "serial": meraki.params["serial"],
                "number": meraki.params["number"],
            },
        )
        original = meraki.request(query_path, method="GET")
        # Check voiceVlan to see if state is absent to remove the vlan.
        if meraki.params.get("voice_vlan_state"):
            if meraki.params.get("voice_vlan_state") == "absent":
                payload["voiceVlan"] = None
            else:
                payload["voiceVlan"] = meraki.params.get("voice_vlan")
        if meraki.params.get("mac_allow_list"):
            macs = get_mac_list(
                original.get("macAllowList"),
                meraki.params["mac_allow_list"].get("macs"),
                meraki.params["mac_allow_list"].get("state"),
            )
            payload["macAllowList"] = macs
        # Evaluate Sticky Limit whether it was passed in or what is currently configured and was returned in GET call.
        if meraki.params.get("sticky_mac_allow_list_limit"):
            sticky_mac_limit = meraki.params.get("sticky_mac_allow_list_limit")
        else:
            sticky_mac_limit = original.get("stickyMacAllowListLimit")
        if meraki.params.get("sticky_mac_allow_list"):
            macs = get_mac_list(
                original.get("stickyMacAllowList"),
                meraki.params["sticky_mac_allow_list"].get("macs"),
                meraki.params["sticky_mac_allow_list"].get("state"),
            )
            if int(sticky_mac_limit) < len(macs):
                meraki.fail_json(
                    msg="Stick MAC Allow List Limit must be equal to or greater than length of Sticky MAC Allow List."
                )
            payload["stickyMacAllowList"] = macs
            payload["stickyMacAllowListLimit"] = sticky_mac_limit
        payload = clear_vlan(meraki.params, payload)
        proposed = payload.copy()
        if meraki.params["type"] == "trunk":
            proposed["voiceVlan"] = original[
                "voiceVlan"
            ]  # API shouldn't include voice VLAN on a trunk port
        # meraki.fail_json(msg='Compare', original=original, payload=payload)
        if meraki.is_update_required(original, proposed, optional_ignore=["number"]):
            if meraki.check_mode is True:
                original.update(proposed)
                meraki.result["data"] = original
                meraki.result["changed"] = True
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path(
                "update",
                custom={
                    "serial": meraki.params["serial"],
                    "number": meraki.params["number"],
                },
            )
            response = meraki.request(path, method="PUT", payload=json.dumps(payload))
            meraki.result["data"] = response
            meraki.result["changed"] = True
        else:
            meraki.result["data"] = original

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == "__main__":
    main()
