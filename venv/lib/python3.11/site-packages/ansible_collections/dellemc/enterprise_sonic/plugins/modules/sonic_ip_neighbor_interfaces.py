#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ip_neighbor_interfaces
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_ip_neighbor_interfaces
version_added: '3.1.0'
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies
  - Supports C(check_mode)
short_description: Manage interface-specific IP neighbor configurations on SONiC
description:
  - This module provides configuration management of interface-specific
    IP neighbor parameters for devices running SONiC.
author: 'Arun Saravanan Balachandran (@ArunSaravananBalachandran)'
options:
  config:
    description:
      - Specifies interface-specific IP neighbor configurations.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Full name of the interface.
        type: str
        required: true
      ipv4_neighbors:
        description:
          - Specifies the static IPv4 neighbors.
          - I(ip) & I(mac) are required for adding a new neighbor.
        type: list
        elements: dict
        suboptions:
          ip:
            description:
              - IPv4 address of the neighbor.
            type: str
            required: true
          mac:
            description:
              - MAC address of the neighbor.
            type: str
      ipv6_neighbors:
        description:
          - Specifies the static IPv6 neighbors.
          - I(ip) & I(mac) are required for adding a new neighbor.
        type: list
        elements: dict
        suboptions:
          ip:
            description:
              - IPv6 address of the neighbor.
            type: str
            required: true
          mac:
            description:
              - MAC address of the neighbor.
            type: str
  state:
    description:
      - The state of the configuration after module completion.
      - C(merged) - Merges provided interface-specific IP neighbor configuration with on-device configuration.
      - C(replaced) - Replaces on-device IP neighbor configuration of the specified interfaces with provided configuration.
      - C(overridden) - Overrides all on-device interface-specific IP neighbor configurations with the provided configuration.
      - C(deleted) - Deletes on-device interface-specific IP neighbor configuration.
    type: str
    choices:
      - merged
      - deleted
      - replaced
      - overridden
    default: merged
"""
EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface Vlan 10 | grep "arp|neighbor"
#  ip arp 10.1.1.4 00:01:02:03:44:55
# sonic# show running-configuration interface Vlan 20 | grep "arp|neighbor"
# sonic#

- name: Merge provided interface IP neighbor configurations
  dellemc.enterprise_sonic.sonic_ip_neighbor_interfaces:
    config:
      - name: 'Vlan10'
        ipv6_neighbors:
          - ip: '10::2'
            mac: '00:01:02:03:04:22'
      - name: 'Vlan20'
        ipv4_neighbors:
          - ip: '20.1.1.4'
            mac: '00:01:02:03:22:44'
          - ip: '20.1.1.5'
            mac: '00:01:02:03:22:55'
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration interface Vlan 10 | grep "arp|neighbor"
#  ip arp 10.1.1.4 00:01:02:03:44:55
#  ipv6 neighbor 10::2 00:01:02:03:04:22
# sonic# show running-configuration interface Vlan 20 | grep "arp|neighbor"
#  ip arp 20.1.1.4 00:01:02:03:22:44
#  ip arp 20.1.1.5 00:01:02:03:22:55
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface Vlan 10 | grep "arp|neighbor"
#  ip arp 10.1.1.3 00:01:02:03:33:55
#  ip arp 10.1.1.4 00:01:02:03:44:55
#  ipv6 neighbor 10::2 00:01:02:03:04:22
#  ipv6 neighbor 10::3 00:01:02:03:04:33
# sonic# show running-configuration interface Vlan 20 | grep "arp|neighbor"
#  ip arp 20.1.1.4 00:01:02:03:22:44
#  ip arp 20.1.1.5 00:01:02:03:22:55
#  ipv6 neighbor 20::2 00:01:02:03:22:22
#  ipv6 neighbor 20::3 00:01:02:03:22:33
# sonic#

- name: Delete interface IP neighbor configurations
  dellemc.enterprise_sonic.sonic_ip_neighbor_interfaces:
    config:
      - name: 'Vlan10'
        ipv4_neighbors:
          - ip: '10.1.1.4'
        ipv6_neighbors:
          - ip: '10::2'
      - name: 'Vlan20'
        ipv4_neighbors:
          - ip: '20.1.1.4'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface Vlan 10 | grep "arp|neighbor"
#  ip arp 10.1.1.3 00:01:02:03:33:55
#  ipv6 neighbor 10::3 00:01:02:03:04:33
# sonic# show running-configuration interface Vlan 20 | grep "arp|neighbor"
#  ip arp 20.1.1.5 00:01:02:03:22:55
#  ipv6 neighbor 20::2 00:01:02:03:22:22
#  ipv6 neighbor 20::3 00:01:02:03:22:33
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface Vlan 10 | grep "arp|neighbor"
#  ip arp 10.1.1.3 00:01:02:03:33:55
#  ip arp 10.1.1.4 00:01:02:03:44:55
#  ipv6 neighbor 10::2 00:01:02:03:04:22
#  ipv6 neighbor 10::3 00:01:02:03:04:33
# sonic# show running-configuration interface Vlan 20 | grep "arp|neighbor"
#  ip arp 20.1.1.4 00:01:02:03:22:44
#  ip arp 20.1.1.5 00:01:02:03:22:55
#  ipv6 neighbor 20::2 00:01:02:03:22:22
#  ipv6 neighbor 20::3 00:01:02:03:22:33
# sonic#

- name: Delete all interface IP neighbor configurations for interface Vlan 10
  dellemc.enterprise_sonic.sonic_ip_neighbor_interfaces:
    config:
      - name: 'Vlan10'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface Vlan 10 | grep "arp|neighbor"
# sonic# show running-configuration interface Vlan 20 | grep "arp|neighbor"
#  ip arp 20.1.1.4 00:01:02:03:22:44
#  ip arp 20.1.1.5 00:01:02:03:22:55
#  ipv6 neighbor 20::2 00:01:02:03:22:22
#  ipv6 neighbor 20::3 00:01:02:03:22:33
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface Vlan 10 | grep "arp|neighbor"
#  ip arp 10.1.1.3 00:01:02:03:33:55
#  ip arp 10.1.1.4 00:01:02:03:44:55
#  ipv6 neighbor 10::2 00:01:02:03:04:22
#  ipv6 neighbor 10::3 00:01:02:03:04:33
# sonic# show running-configuration interface Vlan 20 | grep "arp|neighbor"
#  ip arp 20.1.1.4 00:01:02:03:22:44
#  ip arp 20.1.1.5 00:01:02:03:22:55
#  ipv6 neighbor 20::2 00:01:02:03:22:22
# sonic#

- name: Delete all interface IP neighbor configurations
  dellemc.enterprise_sonic.sonic_ip_neighbor_interfaces:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface Vlan 10 | grep "arp|neighbor"
# sonic# show running-configuration interface Vlan 20 | grep "arp|neighbor"
# sonic#


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface Vlan 10 | grep "arp|neighbor"
#  ip arp 10.1.1.3 00:01:02:03:33:55
#  ip arp 10.1.1.4 00:01:02:03:44:55
#  ipv6 neighbor 10::2 00:01:02:03:04:22
#  ipv6 neighbor 10::3 00:01:02:03:04:33
# sonic# show running-configuration interface Vlan 20 | grep "arp|neighbor"
#  ip arp 20.1.1.4 00:01:02:03:22:44
#  ip arp 20.1.1.5 00:01:02:03:22:55
#  ipv6 neighbor 20::2 00:01:02:03:22:22
#  ipv6 neighbor 20::3 00:01:02:03:22:33
# sonic#

- name: Replace interface IP neighbor configurations for interface Vlan 10
  dellemc.enterprise_sonic.sonic_ip_neighbor_interfaces:
    config:
      - name: 'Vlan10'
        ipv4_neighbors:
          - ip: '10.1.1.11'
            mac: '00:01:02:03:04:11'
          - ip: '10.1.1.12'
            mac: '00:01:02:03:04:12'
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration interface Vlan 10 | grep "arp|neighbor"
#  ip arp 10.1.1.11 00:01:02:03:04:11
#  ip arp 10.1.1.12 00:01:02:03:04:12
# sonic# show running-configuration interface Vlan 20 | grep "arp|neighbor"
#  ip arp 20.1.1.4 00:01:02:03:22:44
#  ip arp 20.1.1.5 00:01:02:03:22:55
#  ipv6 neighbor 20::2 00:01:02:03:22:22
#  ipv6 neighbor 20::3 00:01:02:03:22:33
# sonic#


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface Vlan 10 | grep "arp|neighbor"
#  ip arp 10.1.1.3 00:01:02:03:33:55
#  ip arp 10.1.1.4 00:01:02:03:44:55
#  ipv6 neighbor 10::2 00:01:02:03:04:22
#  ipv6 neighbor 10::3 00:01:02:03:04:33
# sonic# show running-configuration interface Vlan 20 | grep "arp|neighbor"
#  ip arp 20.1.1.4 00:01:02:03:22:44
#  ip arp 20.1.1.5 00:01:02:03:22:55
#  ipv6 neighbor 20::2 00:01:02:03:22:22
#  ipv6 neighbor 20::3 00:01:02:03:22:33
# sonic# show running-configuration interface Vlan 30 | grep "arp|neighbor"
# sonic#

- name: Override all interface IP neighbor configurations
  dellemc.enterprise_sonic.sonic_ip_neighbor_interfaces:
    config:
      - name: 'Vlan10'
        ipv4_neighbors:
          - ip: '10.1.1.11'
            mac: '00:01:02:03:04:11'
        ipv6_neighbors:
          - ip: '10::11'
            mac: '00:01:02:03:10:11'
      - name: 'Vlan30'
        ipv4_neighbors:
          - ip: '30.1.1.6'
            mac: '00:01:02:03:30:66'
          - ip: '30.1.1.7'
            mac: '00:01:02:03:30:77'
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration interface Vlan 10 | grep "arp|neighbor"
#  ip arp 10.1.1.11 00:01:02:03:04:11
#  ipv6 neighbor 10::11 00:01:02:03:10:11
# sonic# show running-configuration interface Vlan 20 | grep "arp|neighbor"
# sonic# show running-configuration interface Vlan 30 | grep "arp|neighbor"
#  ip arp 30.1.1.6 00:01:02:03:30:66
#  ip arp 30.1.1.7 00:01:02:03:30:77
# sonic#
"""
RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
after:
  description: The configuration resulting from module invocation.
  returned: when changed
  type: list
after(generated):
  description: The generated configuration from module invocation.
  returned: when C(check_mode)
  type: list
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ip_neighbor_interfaces.ip_neighbor_interfaces import (
    Ip_neighbor_interfacesArgs
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ip_neighbor_interfaces.ip_neighbor_interfaces import (
    Ip_neighbor_interfaces
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Ip_neighbor_interfacesArgs.argument_spec,
                           supports_check_mode=True)

    result = Ip_neighbor_interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
