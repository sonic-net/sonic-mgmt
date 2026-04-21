#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_dhcp_snooping
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_dhcp_snooping
version_added: 2.3.0
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: "Manage DHCP Snooping on SONiC"
description: "This module provides configuration management of DHCP snooping for devices running SONiC."
author: Simon Nathans (@simon-nathans), Xiao Han (@Xiao_Han2)
options:
  config:
    description: The DHCP snooping configuration.
    type: dict
    suboptions:
      afis:
        description:
          - List of address families to configure.
          - "There can be up to two items in this list: one where I(afi=ipv4) and one where I(afi=ipv6) to configure DHCPv4 and DHCPv6, respectively."
        type: list
        elements: dict
        suboptions:
          afi:
            description:
              - The address family to configure.
            type: str
            choices: ['ipv4', 'ipv6']
            required: true
          enabled:
            description:
              - Enable DHCP snooping for I(afi).
            type: bool
          vlans:
            description:
              - Enable DHCP snooping on a list of VLANs for I(afi).
              - When I(state=deleted), passing an empty list will disable DHCP snooping in all VLANs
            type: list
            elements: str
          verify_mac:
            description:
              - Enable DHCP snooping MAC verification for I(afi).
            type: bool
          trusted:
            description:
              - Mark interfaces as trusted for DHCP snooping for I(afi).
              - When I(state=deleted), passing an empty list will delete all trusted interfaces.
            type: list
            elements: dict
            suboptions:
              intf_name:
                description:
                  - The interface name.
                type: str
                required: true
          source_bindings:
            description:
              - Create a static entry in the DHCP snooping binding database for I(afi).
              - When I(state=deleted), passing an empty list will delete all source bindings.
            type: list
            elements: dict
            suboptions:
              mac_addr:
                description:
                  - The binding's MAC address.
                type: str
                required: true
              ip_addr:
                description:
                  - The bindings's IP address.
                type: str
              intf_name:
                description:
                  - The binding's interface name.
                  - Can be an Ethernet or a PortChannel interface.
                type: str
              vlan_id:
                description:
                  - The binding's VLAN ID.
                type: int
  state:
    description:
      - The state of the configuration after module completion.
    default: merged
    choices: ['merged', 'deleted', 'overridden', 'replaced']
    type: str
"""

EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show ip dhcp snooping
# !
# DHCP snooping is Disabled
# DHCP snooping source MAC verification is Disabled
# DHCP snooping is enabled on the following VLANs:
# DHCP snooping trusted interfaces:
# !

- name: Configure DHCPv4 snooping global settings
  dellemc.enterprise_sonic.sonic_dhcp_snooping:
    config:
      afis:
        - afi: 'ipv4'
          enabled: true
          verify_mac: true
          vlans: ['1', '2', '3', '5']
          trusted:
            - intf_name: 'Ethernet8'
    state: merged

# After state:
# ------------
#
# sonic# show ip dhcp snooping
# !
# DHCP snooping is Enabled
# DHCP snooping source MAC verification is Enabled
# DHCP snooping is enabled on the following VLANs: 1 2 3 5
# DHCP snooping trusted interfaces: Ethernet8
# !


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show ipv6 dhcp snooping
# !
# DHCPv6 snooping is Disabled
# DHCPv6 snooping source MAC verification is Disabled
# DHCPv6 snooping is enabled on the following VLANs:
# DHCPv6 snooping trusted interfaces:
# !

- name: Configure DHCPv6 snooping global settings
  dellemc.enterprise_sonic.sonic_dhcp_snooping:
    config:
      afis:
        - afi: 'ipv6'
          enabled: true
          vlans:
            - '4'
          trusted:
            - intf_name: 'Ethernet2'
            - intf_name: PortChannel1
    state: merged

# After state:
# ------------
#
# sonic# show ipv6 dhcp snooping
# !
# DHCPv6 snooping is Enabled
# DHCPv6 snooping source MAC verification is Disabled
# DHCPv6 snooping is enabled on the following VLANs: 4
# DHCPv6 snooping trusted interfaces: PortChannel1
# !


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show ip dhcp snooping binding
# !
# Total number of Dynamic bindings: 0
# Total number of Static bindings: 0
# Total number of Tentative bindings: 0
# MAC Address        IP Address       VLAN   Interface    Type     Lease (Secs)
# -----------------  ---------------  ----   -----------  -------  -----------
# !

- name: Add DHCPv4 snooping bindings
  dellemc.enterprise_sonic.sonic_dhcp_snooping:
    config:
      afis:
        - afi: 'ipv4'
          source_bindings:
            - mac_addr: '00:b0:d0:63:c2:26'
              ip_addr: '192.0.2.146'
              intf_name: 'Ethernet4'
              vlan_id: '1'
            - mac_addr: 'aa:f7:67:fc:f4:9a'
              ip_addr: '156.33.90.167'
              intf_name: 'PortChannel1'
              vlan_id: '2'
    state: merged

# After state:
# ------------
#
# sonic# show ip dhcp snooping binding
# !
# Total number of Dynamic bindings: 0
# Total number of Static bindings: 2
# Total number of Tentative bindings: 0
# MAC Address        IP Address       VLAN   Interface    Type     Lease (Secs)
# -----------------  ---------------  ----   -----------  -------  -----------
# 00:b0:d0:63:c2:26  192.0.2.146      1      Ethernet4    static   NA
# aa:f7:67:fc:f4:9a  156.33.90.167    2      PortChannel1  static   NA
# !


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show ip dhcp snooping
# !
# DHCP snooping is Enabled
# DHCP snooping source MAC verification is Enabled
# DHCP snooping is enabled on the following VLANs: 1 2 3 5
# DHCP snooping trusted interfaces: Ethernet8
# !

- name: Disable DHCPv4 snooping on some VLANs
  dellemc.enterprise_sonic.sonic_dhcp_snooping:
    config:
      afis:
        - afi: 'ipv4'
          vlans:
            - '3'
            - '5'
    state: deleted

# After state:
# ------------
#
# sonic# show ip dhcp snooping
# !
# DHCP snooping is Enabled
# DHCP snooping source MAC verification is Enabled
# DHCP snooping is enabled on the following VLANs: 1 2
# DHCP snooping trusted interfaces:
# !


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show ipv6 dhcp snooping
# !
# DHCPv6 snooping is Enabled
# DHCPv6 snooping source MAC verification is Disabled
# DHCPv6 snooping is enabled on the following VLANs: 4
# DHCPv6 snooping trusted interfaces: PortChannel1 PortChannel2 PortChannel3 PortChannel4
# !

- name: Disable DHCPv6 snooping on all VLANs
  dellemc.enterprise_sonic.sonic_dhcp_snooping:
    config:
      afis:
        - afi: 'ipv6'
          vlans: []
    state: deleted

# After state:
# ------------
#
# sonic# show ipv6 dhcp snooping
# !
# DHCPv6 snooping is Enabled
# DHCPv6 snooping source MAC verification is Disabled
# DHCPv6 snooping is enabled on the following VLANs:
# DHCPv6 snooping trusted interfaces: PortChannel1 PortChannel2 PortChannel3 PortChannel4
# !


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show ipv6 dhcp snooping
# !
# DHCPv6 snooping is Enabled
# DHCPv6 snooping source MAC verification is Disabled
# DHCPv6 snooping is enabled on the following VLANs: 4
# DHCPv6 snooping trusted interfaces: PortChannel1 PortChannel2 PortChannel3 PortChannel4
# !

- name: Delete all DHCPv6 configuration
  dellemc.enterprise_sonic.sonic_dhcp_snooping:
    config:
      afis:
        - afi: 'ipv6'
    state: deleted

# After state:
# ------------
#
# sonic# show ipv6 dhcp snooping
# !
# DHCPv6 snooping is Disabled
# DHCPv6 snooping source MAC verification is Disabled
# DHCPv6 snooping is enabled on the following VLANs:
# DHCPv6 snooping trusted interfaces:
# !


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show ip dhcp snooping binding
# !
# Total number of Dynamic bindings: 0
# Total number of Static bindings: 2
# Total number of Tentative bindings: 0
# MAC Address        IP Address       VLAN   Interface    Type     Lease (Secs)
# -----------------  ---------------  ----   -----------  -------  -----------
# 00:b0:d0:63:c2:26  192.0.2.146      1      Ethernet4    static   NA
# aa:f7:67:fc:f4:9a  156.33.90.167    2      PortChannel1  static   NA
# !

- name: Delete a DHCPv4 snooping binding
  dellemc.enterprise_sonic.sonic_dhcp_snooping:
    config:
      afis:
        - afi: 'ipv4'
          source_bindings:
            - mac_addr: '00:b0:d0:63:c2:26'
              ip_addr: '192.0.2.146'
              intf_name: 'Ethernet4'
              vlan_id: '1'
    state: deleted

# After state:
# ------------
#
# sonic# show ip dhcp snooping binding
# !
# Total number of Dynamic bindings: 0
# Total number of Static bindings: 2
# Total number of Tentative bindings: 0
# MAC Address        IP Address       VLAN   Interface    Type     Lease (Secs)
# -----------------  ---------------  ----   -----------  -------  -----------
# aa:f7:67:fc:f4:9a  156.33.90.167    2      PortChannel1  static   NA
# !


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show ipv4 dhcp snooping binding
# !
# MAC Address        IP Address       VLAN   Interface    Type     Lease (Secs)
# -----------------  ---------------  ----   -----------  -------  -----------
# 00:b0:d0:63:c2:26  192.0.2.146      1      Ethernet4    static   NA
# 28:21:28:15:c1:1b  141.202.222.118  1      Ethernet2    static   NA
# aa:f7:67:fc:f4:9a  156.33.90.167    2      PortChannel1  static   NA
# !

- name: Override DHCPv4 snooping bindings
  dellemc.enterprise_sonic.sonic_dhcp_snooping:
    config:
      afis:
        - afi: 'ipv4'
          source_bindings:
            - mac_addr: '00:b0:d0:63:c2:26'
              ip_addr: '192.0.2.146'
              intf_name: 'Ethernet4'
              vlan_id: '3'
    state: overridden

# After state:
# ------------
#
# sonic# show ipv4 dhcp snooping binding
# !
# MAC Address        IP Address       VLAN   Interface    Type     Lease (Secs)
# -----------------  ---------------  ----   -----------  -------  -----------
# 00:b0:d0:63:c2:26  192.0.2.146      3      Ethernet4    static   NA
# !


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show ipv4 dhcp snooping binding
# !
# MAC Address        IP Address       VLAN   Interface    Type     Lease (Secs)
# -----------------  ---------------  ----   -----------  -------  -----------
# 00:b0:d0:63:c2:26  192.0.2.146      1      Ethernet4    static   NA
# 28:21:28:15:c1:1b  141.202.222.118  1      Ethernet2    static   NA
# aa:f7:67:fc:f4:9a  156.33.90.167    2      PortChannel1  static   NA
# !

- name: Replace DHCPv4 snooping bindings
  dellemc.enterprise_sonic.sonic_dhcp_snooping:
    config:
      afis:
        - afi: 'ipv4'
          source_bindings:
            - mac_addr: '00:b0:d0:63:c2:26'
              ip_addr: '192.0.2.146'
              intf_name: 'Ethernet4'
              vlan_id: '3'
    state: replaced

# After state:
# ------------
#
# sonic# show ipv4 dhcp snooping binding
# !
# MAC Address        IP Address       VLAN   Interface    Type     Lease (Secs)
# -----------------  ---------------  ----   -----------  -------  -----------
# 00:b0:d0:63:c2:26  192.0.2.146      3      Ethernet4    static   NA
# 28:21:28:15:c1:1b  141.202.222.118  1      Ethernet2    static   NA
# aa:f7:67:fc:f4:9a  156.33.90.167    2      PortChannel1  static   NA
# !
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: dict
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: dict
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.dhcp_snooping.dhcp_snooping import Dhcp_snoopingArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.dhcp_snooping.dhcp_snooping import Dhcp_snooping


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Dhcp_snoopingArgs.argument_spec,
                           supports_check_mode=True)

    result = Dhcp_snooping(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
