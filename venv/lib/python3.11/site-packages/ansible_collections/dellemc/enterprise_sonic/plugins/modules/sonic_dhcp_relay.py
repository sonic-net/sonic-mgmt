#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_dhcp_relay
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_dhcp_relay
version_added: '2.1.0'
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Manage DHCP and DHCPv6 relay configurations on SONiC
description:
  - This module provides configuration management of DHCP and DHCPv6 relay
    parameters on Layer 3 interfaces of devices running SONiC.
  - Layer 3 interface and VRF name need to be created earlier in the device.
author: 'Arun Saravanan Balachandran (@ArunSaravananBalachandran)'
options:
  config:
    description:
      - Specifies the DHCP and DHCPv6 relay configurations.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Full name of the Layer 3 interface, i.e. Eth1/1.
        type: str
        required: true
      ipv4:
        description:
          - DHCP relay configurations to be set for the interface mentioned in name option.
        type: dict
        suboptions:
          server_addresses:
            description:
              - List of DHCP server IPv4 addresses.
            type: list
            elements: dict
            suboptions:
              address:
                description:
                  - IPv4 address of the DHCP server.
                type: str
          vrf_name:
            description:
              - Specifies name of the VRF in which the DHCP server resides.
              - This option is not used with state I(deleted).
            type: str
          source_interface:
            description:
              - Specifies the DHCP relay source interface.
            type: str
          max_hop_count:
            description:
              - Specifies the maximum hop count for DHCP relay packets.
              - The range is from 1 to 16.
            type: int
          link_select:
            description:
              - Enable link selection suboption.
            type: bool
          vrf_select:
            description:
              - Enable VRF selection suboption.
            type: bool
          circuit_id:
            description:
              - Specifies the DHCP relay circuit-id format.
              - C(%h:%p) - Hostname followed by interface name eg. sonic:Vlan100
              - C(%i) - Name of the physical interface eg. Eth1/2
              - C(%p) - Name of the interface eg. Vlan100
            type: str
            choices:
              - '%h:%p'
              - '%i'
              - '%p'
          policy_action:
            description:
              - Specifies the policy for handling of DHCP relay options.
            type: str
            choices:
              - append
              - discard
              - replace
      ipv6:
        description:
          - DHCPv6 relay configurations to be set for the interface mentioned in name option.
        type: dict
        suboptions:
          server_addresses:
            description:
              - List of DHCPv6 server IPv6 addresses.
            type: list
            elements: dict
            suboptions:
              address:
                description:
                  - IPv6 address of the DHCPv6 server.
                type: str
          vrf_name:
            description:
              - Specifies name of the VRF in which the DHCPv6 server resides.
              - This option is used only with state I(merged).
            type: str
          source_interface:
            description:
              - Specifies the DHCPv6 relay source interface.
            type: str
          max_hop_count:
            description:
              - Specifies the maximum hop count for DHCPv6 relay packets.
              - The range is from 1 to 16.
            type: int
          vrf_select:
            description:
              - Enable VRF selection suboption.
            type: bool
  state:
    description:
      - The state of the configuration after module completion.
      - C(merged) - Merges provided DHCP and DHCPv6 relay configuration with on-device configuration.
      - C(deleted) - Deletes on-device DHCP and DHCPv6 relay configuration.
      - C(replaced) - Replaces on-device DHCP and DHCPv6 relay configuration of the specified interfaces with provided configuration.
      - C(overridden) - Overrides all on-device DHCP and DHCPv6 relay configurations with the provided configuration.
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
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ip dhcp-relay 91.1.1.1 92.1.1.1 vrf VrfReg1
#  ip dhcp-relay max-hop-count 5
#  ip dhcp-relay vrf-select
#  ip dhcp-relay policy-action append
#  ipv6 address 81::1/24
#  ipv6 dhcp-relay 91::1 92::1
#  ipv6 dhcp-relay max-hop-count 5
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  ip dhcp-relay 71.1.1.1 72.1.1.1 73.1.1.1
#  ip dhcp-relay source-interface Vlan100
#  ip dhcp-relay link-select
#  ip dhcp-relay circuit-id %h:%p
# !

- name: Delete DHCP and DHCPv6 relay configurations
  dellemc.enterprise_sonic.sonic_dhcp_relay:
    config:
      - name: 'Eth1/1'
        ipv4:
          server_addresses:
            - address: '92.1.1.1'
          vrf_select: true
          max_hop_count: 5
        ipv6:
          server_addresses:
            - address: '91::1'
            - address: '92::1'
      - name: 'Eth1/2'
        ipv4:
          server_addresses:
            - address: '71.1.1.1'
            - address: '72.1.1.1'
          source_interface: 'Vlan100'
          link_select: true
          circuit_id: '%h:%p'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ip dhcp-relay 91.1.1.1 vrf VrfReg1
#  ip dhcp-relay policy-action append
#  ipv6 address 81::1/24
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  ip dhcp-relay 73.1.1.1
# !


# Using "deleted" state
#
# NOTE: Support is provided in the dhcp_relay resource module for deletion of all attributes for a
# given address family (IPv4 or IPv6) by using a "special" YAML sequence specifying a server address list
# containing a single "blank" IP address under the target address family. The following example shows
# a task using this syntax for deletion of all DHCP (IPv4) configurations for an interface, but the
# equivalent syntax is supported for DHCPv6 (IPv6) as well.
#
# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ip dhcp-relay 91.1.1.1 92.1.1.1 vrf VrfReg1
#  ip dhcp-relay max-hop-count 5
#  ip dhcp-relay vrf-select
#  ip dhcp-relay policy-action append
#  ipv6 address 81::1/24
#  ipv6 dhcp-relay 91::1 92::1
#  ipv6 dhcp-relay max-hop-count 5
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  ip dhcp-relay 71.1.1.1 72.1.1.1 73.1.1.1
#  ip dhcp-relay source-interface Vlan100
#  ip dhcp-relay link-select
#  ip dhcp-relay circuit-id %h:%p
# !

- name: Delete all IPv4 DHCP relay configurations for interface Eth1/1
  dellemc.enterprise_sonic.sonic_dhcp_relay:
    config:
      - name: 'Eth1/1'
        ipv4:
          server_addresses:
            - address:
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ipv6 address 81::1/24
#  ipv6 dhcp-relay 91::1 92::1
#  ipv6 dhcp-relay max-hop-count 5
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  ip dhcp-relay 71.1.1.1 72.1.1.1 73.1.1.1
#  ip dhcp-relay source-interface Vlan100
#  ip dhcp-relay link-select
#  ip dhcp-relay circuit-id %h:%p
# !


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ip dhcp-relay 91.1.1.1 92.1.1.1 vrf VrfReg1
#  ip dhcp-relay max-hop-count 5
#  ip dhcp-relay vrf-select
#  ip dhcp-relay policy-action append
#  ipv6 address 81::1/24
#  ipv6 dhcp-relay 91::1 92::1
#  ipv6 dhcp-relay max-hop-count 5
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  ip dhcp-relay 71.1.1.1 72.1.1.1 73.1.1.1
#  ip dhcp-relay source-interface Vlan100
#  ip dhcp-relay link-select
#  ip dhcp-relay circuit-id %h:%p
# !

- name: Delete all DHCP and DHCPv6 relay configurations for interface Eth1/1
  dellemc.enterprise_sonic.sonic_dhcp_relay:
    config:
      - name: 'Eth1/1'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ipv6 address 81::1/24
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  ip dhcp-relay 71.1.1.1 72.1.1.1 73.1.1.1
#  ip dhcp-relay source-interface Vlan100
#  ip dhcp-relay link-select
#  ip dhcp-relay circuit-id %h:%p
# !


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ip dhcp-relay 91.1.1.1 92.1.1.1 vrf VrfReg1
#  ip dhcp-relay max-hop-count 5
#  ip dhcp-relay vrf-select
#  ip dhcp-relay policy-action append
#  ipv6 address 81::1/24
#  ipv6 dhcp-relay 91::1 92::1
#  ipv6 dhcp-relay max-hop-count 5
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  ip dhcp-relay 71.1.1.1 72.1.1.1 73.1.1.1
#  ip dhcp-relay source-interface Vlan100
#  ip dhcp-relay link-select
#  ip dhcp-relay circuit-id %h:%p
# !

- name: Delete all DHCP and DHCPv6 relay configurations
  dellemc.enterprise_sonic.sonic_dhcp_relay:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ipv6 address 81::1/24
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
# !


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ipv6 address 81::1/24
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  ip dhcp-relay 71.1.1.1 72.1.1.1
# !

- name: Add DHCP and DHCPv6 relay configurations
  dellemc.enterprise_sonic.sonic_dhcp_relay:
    config:
      - name: 'Eth1/1'
        ipv4:
          server_addresses:
            - address: '91.1.1.1'
            - address: '92.1.1.1'
          vrf_name: 'VrfReg1'
          vrf_select: true
          max_hop_count: 5
          policy_action: 'append'
        ipv6:
          server_addresses:
            - address: '91::1'
            - address: '92::1'
          max_hop_count: 5
      - name: 'Eth1/2'
        ipv4:
          server_addresses:
            - address: '73.1.1.1'
          source_interface: 'Vlan100'
          link_select: true
          circuit_id: '%h:%p'
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ip dhcp-relay 91.1.1.1 92.1.1.1 vrf VrfReg1
#  ip dhcp-relay max-hop-count 5
#  ip dhcp-relay vrf-select
#  ip dhcp-relay policy-action append
#  ipv6 address 81::1/24
#  ipv6 dhcp-relay 91::1 92::1
#  ipv6 dhcp-relay max-hop-count 5
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  ip dhcp-relay 71.1.1.1 72.1.1.1 73.1.1.1
#  ip dhcp-relay source-interface Vlan100
#  ip dhcp-relay link-select
#  ip dhcp-relay circuit-id %h:%p
# !


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ip dhcp-relay 91.1.1.1 92.1.1.1 vrf VrfReg1
#  ip dhcp-relay max-hop-count 5
#  ip dhcp-relay vrf-select
#  ip dhcp-relay policy-action append
#  ipv6 address 81::1/24
#  ipv6 dhcp-relay 91::1 92::1
#  ipv6 dhcp-relay max-hop-count 5
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  ip dhcp-relay 71.1.1.1 72.1.1.1 73.1.1.1
#  ip dhcp-relay source-interface Vlan100
#  ip dhcp-relay link-select
#  ip dhcp-relay circuit-id %h:%p
#  ipv6 address 61::1/24
#  ipv6 dhcp-relay 71::1 72::1
# !
# interface Eth1/3
#  mtu 9100
#  speed 400000
#  fec RS
#  shutdown
#  ip address 41.1.1.1/24
#  ip dhcp-relay 51.1.1.1 52.1.1.1
#  ip dhcp-relay circuit-id %h:%p
#  ipv6 address 41::1/24
#  ipv6 dhcp-relay 51::1 52::1
# !

- name: Replace DHCP and DHCPv6 relay configurations of specified interfaces
  dellemc.enterprise_sonic.sonic_dhcp_relay:
    config:
      - name: 'Eth1/1'
        ipv4:
          server_addresses:
            - address: '91.1.1.1'
            - address: '93.1.1.1'
            - address: '95.1.1.1'
          vrf_name: 'VrfReg1'
          vrf_select: true
        ipv6:
          server_addresses:
            - address: '93::1'
            - address: '94::1'
          source_interface: 'Vlan100'
      - name: 'Eth1/2'
        ipv4:
          server_addresses:
            - address: '73.1.1.1'
          circuit_id: '%h:%p'
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ip dhcp-relay 91.1.1.1 93.1.1.1 95.1.1.1 vrf VrfReg1
#  ip dhcp-relay vrf-select
#  ipv6 address 81::1/24
#  ipv6 dhcp-relay 93::1 94::1
#  ipv6 dhcp-relay source-interface Vlan100
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  ip dhcp-relay 73.1.1.1
#  ip dhcp-relay circuit-id %h:%p
#  ipv6 address 61::1/24
# !
# interface Eth1/3
#  mtu 9100
#  speed 400000
#  fec RS
#  shutdown
#  ip address 41.1.1.1/24
#  ip dhcp-relay 51.1.1.1 52.1.1.1
#  ip dhcp-relay circuit-id %h:%p
#  ipv6 address 41::1/24
#  ipv6 dhcp-relay 51::1 52::1
# !


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ip dhcp-relay 91.1.1.1 92.1.1.1 vrf VrfReg1
#  ip dhcp-relay max-hop-count 5
#  ip dhcp-relay vrf-select
#  ip dhcp-relay policy-action append
#  ipv6 address 81::1/24
#  ipv6 dhcp-relay 91::1 92::1
#  ipv6 dhcp-relay max-hop-count 5
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  ip dhcp-relay 71.1.1.1 72.1.1.1 73.1.1.1
#  ip dhcp-relay source-interface Vlan100
#  ip dhcp-relay link-select
#  ip dhcp-relay circuit-id %h:%p
#  ipv6 address 61::1/24
#  ipv6 dhcp-relay 71::1 72::1
# !
# interface Eth1/3
#  mtu 9100
#  speed 400000
#  fec RS
#  shutdown
#  ip address 41.1.1.1/24
#  ip dhcp-relay 51.1.1.1 52.1.1.1
#  ip dhcp-relay circuit-id %h:%p
#  ipv6 address 41::1/24
#  ipv6 dhcp-relay 51::1 52::1
# !

- name: Override DHCP and DHCPv6 relay configurations
  dellemc.enterprise_sonic.sonic_dhcp_relay:
    config:
      - name: 'Eth1/1'
        ipv4:
          server_addresses:
            - address: '91.1.1.1'
            - address: '93.1.1.1'
            - address: '95.1.1.1'
          vrf_name: 'VrfReg1'
          vrf_select: true
        ipv6:
          server_addresses:
            - address: '93::1'
            - address: '94::1'
          source_interface: 'Vlan100'
      - name: 'Eth1/2'
        ipv4:
          server_addresses:
            - address: '73.1.1.1'
          circuit_id: '%h:%p'
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 81.1.1.1/24
#  ip dhcp-relay 91.1.1.1 93.1.1.1 95.1.1.1 vrf VrfReg1
#  ip dhcp-relay vrf-select
#  ipv6 address 81::1/24
#  ipv6 dhcp-relay 93::1 94::1
#  ipv6 dhcp-relay source-interface Vlan100
# !
# interface Eth1/2
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  ip dhcp-relay 73.1.1.1
#  ip dhcp-relay circuit-id %h:%p
#  ipv6 address 61::1/24
# !
# interface Eth1/3
#  mtu 9100
#  speed 400000
#  fec RS
#  shutdown
#  ip address 41.1.1.1/24
#  ipv6 address 41::1/24
# !
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.dhcp_relay.dhcp_relay import Dhcp_relayArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.dhcp_relay.dhcp_relay import Dhcp_relay


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Dhcp_relayArgs.argument_spec,
                           supports_check_mode=True)

    result = Dhcp_relay(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
