#!/usr/bin/python
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_vxlans
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_vxlans
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage VxLAN EVPN and its parameters
description: 'Manages interface attributes of Enterprise SONiC interfaces.'
author: Niraimadaiselvam M (@niraimadaiselvamm)
options:
  config:
    description:
      - A list of VxLAN configurations.
    type: list
    elements: dict
    suboptions:
      name:
        type: str
        description: 'The name of the VxLAN.'
        required: true
      evpn_nvo:
        type: str
        description: 'EVPN nvo name'
      source_ip:
        description: 'The source IP address of the VTEP.'
        type: str
      primary_ip:
        description: 'The vtep mclag primary ip address for this node'
        type: str
      external_ip:
        description: 'The vtep mclag external ip address for this node'
        version_added: 2.5.0
        type: str
      vlan_map:
        description: 'The list of VNI map of VLAN.'
        type: list
        elements: dict
        suboptions:
          vni:
            type: int
            description: 'Specifies the VNI ID.'
            required: true
          vlan:
            type: int
            description: 'VLAN ID for VNI VLAN map.'
      vrf_map:
        description: 'list of VNI map of VRF.'
        type: list
        elements: dict
        suboptions:
          vni:
            type: int
            description: 'Specifies the VNI ID.'
            required: true
          vrf:
            type: str
            description: 'VRF name for VNI VRF map.'
      suppress_vlan_neigh:
        description: 'list map of VLAN names with suppress on'
        version_added: 3.1.0
        type: list
        elements: dict
        suboptions:
          vlan_name:
            type: str
            description: 'name of VLAN'
  state:
    description: 'The state of the configuration after module completion.'
    type: str
    choices:
    - merged
    - deleted
    - replaced
    - overridden
    default: merged
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
#
# do show running-configuration
#
# interface vxlan vteptest1
# source-ip 1.1.1.1
# primary-ip 2.2.2.2
# map vni 101 vlan 11
# map vni 102 vlan 12
# map vni 101 vrf Vrfcheck1
# map vni 102 vrf Vrfcheck2
# suppress vlan-neigh vlan_name Vlan11
# suppress vlan-neigh vlan_name Vlan12
# !
#
- name: "Test vxlans deleted state 01"
  dellemc.enterprise_sonic.sonic_vxlans:
    config:
      - name: vteptest1
        source_ip: 1.1.1.1
        vlan_map:
          - vni: 101
            vlan: 11
        vrf_map:
          - vni: 101
            vrf: Vrfcheck1
        suppress_vlan_neigh:
          - vlan_name: Vlan11
          - vlan_name: Vlan12
    state: deleted
#
# After state:
# ------------
#
# do show running-configuration
#
# interface vxlan vteptest1
# source-ip 1.1.1.1
# map vni 102 vlan 12
# map vni 102 vrf Vrfcheck2
# !
#
# Using "deleted" state
#
# Before state:
# -------------
#
# do show running-configuration
#
# interface vxlan vteptest1
# source-ip 1.1.1.1
# map vni 102 vlan 12
# map vni 102 vrf Vrfcheck2
# !
#
- name: "Test vxlans deleted state 02"
  dellemc.enterprise_sonic.sonic_vxlans:
    config:
    state: deleted
#
# After state:
# ------------
#
# do show running-configuration
#
# !
#
# Using "merged" state
#
# Before state:
# -------------
#
# do show running-configuration
#
# !
#
- name: "Test vxlans merged state 01"
  dellemc.enterprise_sonic.sonic_vxlans:
    config:
      - name: vteptest1
        source_ip: 1.1.1.1
        primary_ip: 2.2.2.2
        evpn_nvo: nvo1
        vlan_map:
          - vni: 101
            vlan: 11
          - vni: 102
            vlan: 12
        vrf_map:
          - vni: 101
            vrf: Vrfcheck1
          - vni: 102
            vrf: Vrfcheck2
        suppress_vlan_neigh:
          - vlan_name: Vlan11
          - vlan_name: Vlan12
    state: merged
#
# After state:
# ------------
#
# do show running-configuration
#
# interface vxlan vteptest1
# source-ip 1.1.1.1
# primary-ip 2.2.2.2
# map vni 101 vlan 11
# map vni 102 vlan 12
# map vni 101 vrf Vrfcheck1
# map vni 102 vrf Vrfcheck2
# suppress vlan-neigh vlan-name Vlan11
# suppress vlan-neigh vlan-name Vlan12
# !
#
# Using "overridden" state
#
# Before state:
# -------------
#
# do show running-configuration
#
# interface vxlan vteptest1
# source-ip 1.1.1.1
# primary-ip 2.2.2.2
# map vni 101 vlan 11
# map vni 102 vlan 12
# map vni 101 vrf Vrfcheck1
# map vni 102 vrf Vrfcheck2
# !
#
- name: "Test vxlans overridden state 01"
  dellemc.enterprise_sonic.sonic_vxlans:
    config:
      - name: vteptest2
        source_ip: 3.3.3.3
        primary_ip: 4.4.4.4
        evpn_nvo: nvo2
        vlan_map:
          - vni: 101
            vlan: 11
        vrf_map:
          - vni: 101
            vrf: Vrfcheck1
    state: overridden
#
# After state:
# ------------
#
# do show running-configuration
#
# interface vxlan vteptest2
# source-ip 3.3.3.3
# primary-ip 4.4.4.4
# map vni 101 vlan 11
# map vni 101 vrf Vrfcheck1
# !
#
# Using "replaced" state
#
# Before state:
# -------------
#
# do show running-configuration
#
# interface vxlan vteptest2
# source-ip 3.3.3.3
# primary-ip 4.4.4.4
# map vni 101 vlan 11
# map vni 101 vrf Vrfcheck
# !
#
- name: "Test vxlans replaced state 01"
  dellemc.enterprise_sonic.sonic_vxlans:
    config:
      - name: vteptest2
        source_ip: 5.5.5.5
        vlan_map:
          - vni: 101
            vlan: 12
    state: replaced
#
# After state:
# ------------
#
# do show running-configuration
#
# interface vxlan vteptest2
# source-ip 5.5.5.5
# primary-ip 4.4.4.4
# map vni 101 vlan 12
# map vni 101 vrf Vrfcheck1
# !
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned is always in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned is always in the same format
    as the parameters above.
commands:
  description: The set of commands that are pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.vxlans.vxlans import VxlansArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.vxlans.vxlans import Vxlans


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=VxlansArgs.argument_spec,
                           supports_check_mode=True)

    result = Vxlans(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
