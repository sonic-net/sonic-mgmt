#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_l2_acls
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_l2_acls
version_added: '2.1.0'
notes:
  - Supports C(check_mode).
short_description: Manage Layer 2 access control lists (ACL) configurations on SONiC
description:
  - This module provides configuration management of Layer 2 access control lists (ACL)
    in devices running SONiC.
author: 'Arun Saravanan Balachandran (@ArunSaravananBalachandran)'
options:
  config:
    description:
      - Specifies Layer 2 ACL configurations.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Specifies the ACL name.
        type: str
        required: true
      remark:
        description:
          - Specifies remark for the ACL.
        type: str
      rules:
        description:
          - List of rules with the ACL.
          - I(sequence_num), I(action), I(source) & I(destination) are required for adding a new rule.
          - If I(state=deleted), options other than I(sequence_num) are not considered.
          - I(ethertype) and I(vlan_tag_format) are mutually exclusive.
        type: list
        elements: dict
        suboptions:
          sequence_num:
            description:
              - Specifies the sequence number of the rule.
              - The range is from 1 to 65535.
            type: int
            required: true
          action:
            description:
              - Specifies the action taken on the matched Ethernet frame.
            type: str
            choices:
              - deny
              - discard
              - do-not-nat
              - permit
              - transit
          source:
            description:
              - Specifies the source of the Ethernet frame.
              - I(address) and I(address_mask) are required together.
              - I(any), I(host) and I(address) are mutually exclusive.
            type: dict
            suboptions:
              any:
                description:
                  - Match any source MAC address.
                type: bool
              host:
                description:
                  - MAC address of a single source host.
                type: str
              address:
                description:
                  - Source MAC address.
                type: str
              address_mask:
                description:
                  - Source MAC address mask.
                type: str
          destination:
            description:
              - Specifies the destination of the Ethernet frame.
              - I(address) and I(address_mask) are required together.
              - I(any), I(host) and I(address) are mutually exclusive.
            type: dict
            suboptions:
              any:
                description:
                  - Match any destination MAC address.
                type: bool
              host:
                description:
                  - MAC address of a single destination host.
                type: str
              address:
                description:
                  - Destination MAC address.
                type: str
              address_mask:
                description:
                  - Destination MAC address mask.
                type: str
          ethertype:
            description:
              - Specifies the EtherType of the Ethernet frame.
              - Only one suboption can be specified for ethertype in a rule.
            type: dict
            suboptions:
              value:
                description:
                  - Specifies the EtherType value to match as a hexadecimal string.
                  - The range is from 0x600 to 0xffff.
                type: str
              arp:
                description:
                  - Match Ethernet frame with ARP EtherType (0x806).
                type: bool
              ipv4:
                description:
                  - Match Ethernet frame with IPv4 EtherType (0x800).
                type: bool
              ipv6:
                description:
                  - Match Ethernet frame with IPv6 EtherType (0x86DD).
                type: bool
          vlan_id:
            description:
              - Match Ethernet frame with the given VLAN ID.
            type: int
          vlan_tag_format:
            description:
              - Match Ethernet frame with the given VLAN tag format.
            type: dict
            suboptions:
              multi_tagged:
                description:
                  - Match three of more VLAN tagged Ethernet frame.
                type: bool
          dei:
            description:
              - Match Ethernet frame with the given Drop Eligible Indicator (DEI) value.
            type: int
            choices:
              - 0
              - 1
          pcp:
            description:
              - Match Ethernet frames using Priority Code Point (PCP) value.
              - I(mask) is valid only when I(value) is specified.
              - I(value) and I(traffic_type) are mutually exclusive.
            type: dict
            suboptions:
              value:
                description:
                  - Match Ethernet frame with the given PCP value.
                  - The range is from 0 to 7
                type: int
              mask:
                description:
                  - Match Ethernet frame with given PCP value and mask.
                  - The range is from 0 to 7.
                type: int
              traffic_type:
                description:
                  - Match Ethernet frame with PCP value for the given traffic type.
                  - C(be) - Match Ethernet frame with Best effort PCP (0).
                  - C(bk) - Match Ethernet frame with Background PCP (1).
                  - C(ee) - Match Ethernet frame with Excellent effort PCP (2).
                  - C(ca) - Match Ethernet frame with Critical applications PCP (3).
                  - C(vi) - Match Ethernet frame with Video, < 100 ms latency and jitter PCP (4).
                  - C(vo) - Match Ethernet frame with Voice, < 10 ms latency and jitter PCP (5).
                  - C(ic) - Match Ethernet frame with Internetwork control PCP (6).
                  - C(nc) - Match Ethernet frame with Network control PCP (7).
                type: str
                choices:
                  - be
                  - bk
                  - ee
                  - ca
                  - vi
                  - vo
                  - ic
                  - nc
          remark:
            description:
              - Specifies remark for the ACL rule.
            type: str
  state:
    description:
      - The state of the configuration after module completion.
      - C(merged) - Merges provided L2 ACL configuration with on-device configuration.
      - C(replaced) - Replaces on-device configuration of the specified L2 ACLs with provided configuration.
      - C(overridden) - Overrides all on-device L2 ACL configurations with the provided configuration.
      - C(deleted) - Deletes on-device L2 ACL configuration.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
    default: merged
"""

EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration mac access-list
# !
# mac access-list test
#  seq 1 permit host 22:22:22:22:22:22 any vlan 20
# sonic#

- name: Merge provided Layer 2 ACL configurations
  dellemc.enterprise_sonic.sonic_l2_acls:
    config:
      - name: 'test'
        rules:
          - sequence_num: 2
            action: 'permit'
            source:
              any: true
            destination:
              any: true
            ethertype:
              value: '0x88cc'
            remark: 'LLDP'
          - sequence_num: 3
            action: 'permit'
            source:
              any: true
            destination:
              address: '00:00:10:00:00:00'
              address_mask: '00:00:ff:ff:00:00'
            pcp:
              value: 4
              mask: 6
          - sequence_num: 4
            action: 'deny'
            source:
              any: true
            destination:
              any: true
            vlan_tag_format:
              multi_tagged: true
      - name: 'test1'
        remark: 'test_mac_acl'
        rules:
          - sequence_num: 1
            action: 'permit'
            source:
              host: '11:11:11:11:11:11'
            destination:
              any: true
          - sequence_num: 2
            action: 'permit'
            source:
              any: true
            destination:
              any: true
            ethertype:
              arp: true
            vlan_id: 100
          - sequence_num: 3
            action: 'deny'
            source:
              any: true
            destination:
              any: true
            dei: 0
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration mac access-list
# !
# mac access-list test
#  seq 1 permit host 22:22:22:22:22:22 any vlan 20
#  seq 2 permit any any 0x88cc remark LLDP
#  seq 3 permit any 00:00:10:00:00:00 00:00:ff:ff:00:00 pcp vi pcp-mask 6
#  seq 4 deny any any vlan-tag-format multi-tagged
# !
# mac access-list test1
#  remark test_mac_acl
#  seq 1 permit host 11:11:11:11:11:11 any
#  seq 2 permit any any arp vlan 100
#  seq 3 deny any any dei 0
# sonic#


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration mac access-list
# !
# mac access-list test
#  seq 1 permit host 22:22:22:22:22:22 any vlan 20
#  seq 2 permit any any 0x88cc remark LLDP
#  seq 3 permit any 00:00:10:00:00:00 00:00:ff:ff:00:00 pcp vi pcp-mask 6
# !
# mac access-list test1
#  remark test_mac_acl
#  seq 1 permit host 11:11:11:11:11:11 any
#  seq 2 permit any any arp vlan 100
#  seq 3 deny any any dei 0
# sonic#

- name: Replace device configuration of specified Layer 2 ACLs with provided configuration
  dellemc.enterprise_sonic.sonic_l2_acls:
    config:
      - name: 'test1'
        rules:
          - sequence_num: 1
            action: 'permit'
            source:
              any: true
            destination:
              any: true
            ethertype:
              arp: true
            vlan_id: 200
          - sequence_num: 2
            action: 'discard'
            source:
              any: true
            destination:
              any: true
      - name: 'test2'
        rules:
          - sequence_num: 1
            action: 'permit'
            source:
              host: '33:33:33:33:33:33'
            destination:
              host: '44:44:44:44:44:44'
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration mac access-list
# !
# mac access-list test
#  seq 1 permit host 22:22:22:22:22:22 any vlan 20
#  seq 2 permit any any 0x88cc remark LLDP
#  seq 3 permit any 00:00:10:00:00:00 00:00:ff:ff:00:00 pcp vi pcp-mask 6
# !
# mac access-list test1
#  seq 1 permit any any arp vlan 200
#  seq 2 discard any any
# !
# mac access-list test2
#  seq 1 permit host 33:33:33:33:33:33 host 44:44:44:44:44:44
# sonic#


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration mac access-list
# !
# mac access-list test
#  seq 1 permit host 22:22:22:22:22:22 any vlan 20
#  seq 2 permit any any 0x88cc remark LLDP
#  seq 3 permit any 00:00:10:00:00:00 00:00:ff:ff:00:00 pcp vi pcp-mask 6
# !
# mac access-list test1
#  seq 1 permit any any arp vlan 200
#  seq 2 discard any any
# !
# mac access-list test2
#  seq 1 permit host 33:33:33:33:33:33 host 44:44:44:44:44:44
# sonic#

- name: Override device configuration of all Layer 2 ACLs with provided configuration
  dellemc.enterprise_sonic.sonic_l2_acls:
    config:
      - name: 'test1'
        remark: 'test_mac_acl'
        rules:
          - sequence_num: 1
            action: 'permit'
            source:
              host: '11:11:11:11:11:11'
            destination:
              any: true
            vlan_id: 100
          - sequence_num: 2
            action: 'permit'
            source:
              any: true
            destination:
              any: true
            pcp:
              traffic_type: 'ca'
          - sequence_num: 3
            action: 'deny'
            source:
              any: true
            destination:
              any: true
            ethertype:
              ipv4: true
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration mac access-list
# !
# mac access-list test1
#  remark test_mac_acl
#  seq 1 permit host 11:11:11:11:11:11 any vlan 100
#  seq 2 permit any any pcp ca
#  seq 3 deny any any ip
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration mac access-list
# !
# mac access-list test
#  seq 1 permit host 22:22:22:22:22:22 any vlan 20
#  seq 2 permit any any 0x88cc remark LLDP
#  seq 3 permit any 00:00:10:00:00:00 00:00:ff:ff:00:00 pcp vi pcp-mask 6
# !
# mac access-list test1
#  remark test_mac_acl
#  seq 1 permit host 11:11:11:11:11:11 any vlan 100
#  seq 2 deny any any ip
# !
# mac access-list test2
#  seq 1 permit host 33:33:33:33:33:33 host 44:44:44:44:44:44
# sonic#

- name: Delete specified Layer 2 ACLs, ACL remark and ACL rule entries
  dellemc.enterprise_sonic.sonic_l2_acls:
    config:
      - name: 'test'
        rules:
          - sequence_num: 3
      - name: 'test1'
        remark: 'test_mac_acl'
      - name: 'test2'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration mac access-list
# !
# mac access-list test
#  seq 1 permit host 22:22:22:22:22:22 any vlan 20
#  seq 2 permit any any 0x88cc remark LLDP
# !
# mac access-list test1
#  seq 1 permit host 11:11:11:11:11:11 any vlan 100
#  seq 2 deny any any ip
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration mac access-list
# !
# mac access-list test
#  seq 1 permit host 22:22:22:22:22:22 any vlan 20
#  seq 2 permit any any 0x88cc remark LLDP
#  seq 3 permit any 00:00:10:00:00:00 00:00:ff:ff:00:00 pcp vi pcp-mask 6
# !
# mac access-list test1
#  remark test_mac_acl
#  seq 1 permit host 11:11:11:11:11:11 any vlan 100
#  seq 2 deny any any ip
# !
# mac access-list test2
#  seq 1 permit host 33:33:33:33:33:33 host 44:44:44:44:44:44
# sonic#

- name: Delete all Layer 2 ACL configurations
  dellemc.enterprise_sonic.sonic_l2_acls:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration mac access-list
# sonic#
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after(generated):
  description: The generated configuration module invocation.
  returned: when C(check_mode)
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.l2_acls.l2_acls import L2_aclsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.l2_acls.l2_acls import L2_acls


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=L2_aclsArgs.argument_spec,
                           supports_check_mode=True)

    result = L2_acls(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
