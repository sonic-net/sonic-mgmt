#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_br_l2pt
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_br_l2pt
version_added: '3.1.0'
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Manage L2PT configurations on SONiC
description:
  - This module provides configuration management of L2PT parameters
    in devices running SONiC.
author: "Allen Ting (@allenkting)"
options:
  config:
    description: A list of L2PT configurations.
    type: list
    elements: dict
    suboptions:
      name:
        description: Interface name for L2PT configuration.
        type: str
        required: true
      bridge_l2pt_params:
        description: VLAN ID list per supported Layer 2 protocol.
        type: list
        elements: dict
        suboptions:
          protocol:
            description: L2 protocol.
            type: str
            required: true
            choices: ['LLDP', 'LACP', 'STP', 'CDP']
          vlan_ids:
            description:
              - List of VLAN IDs on which the L2 Protocol packets are to be tunneled.
              - Ranges can be specified in the list of VLAN IDs using the delimiter '-'.
            type: list
            elements: str
  state:
    description:
      - The state of the configuration after module completion.
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
# sonic# show running-configuration interface Ethernet 0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lldp Vlan 10

- name: Modify interface L2PT configurations
  dellemc.enterprise_sonic.sonic_br_l2pt:
    config:
      - name: Ethernet0
        bridge_l2pt_params:
          - protocol: 'LACP'
            vlan_ids:
              - 10-12
          - protocol: 'CDP'
            vlan_ids:
              - 20
              - 40-60
          - protocol: 'STP'
            vlan_ids:
              - 25-26
    state: merged

# After state:
# ------------
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel cdp Vlan 20,40-60
#  switchport l2proto-tunnel lacp Vlan 10-12
#  switchport l2proto-tunnel lldp Vlan 10
#  switchport l2proto-tunnel stp Vlan 25-26


# Using "merged" state
#
# Before state:
# -------------
# sonic# show running-configuration interface Ethernet 0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel cdp Vlan 20, 40-50
#  switchport l2proto-tunnel lacp Vlan 10-11
#  switchport l2proto-tunnel lldp Vlan 10
#  switchport l2proto-tunnel stp Vlan 25-26

- name: Modify interface L2PT configurations
  dellemc.enterprise_sonic.sonic_br_l2pt:
    config:
      - name: Ethernet0
        bridge_l2pt_params:
          - protocol: 'LLDP'
            vlan_ids:
              - 12
          - protocol: 'LACP'
            vlan_ids:
              - 12
          - protocol: 'CDP'
            vlan_ids:
              - 20
              - 45-60
          - protocol: 'STP'
            vlan_ids:
              - 20-21
    state: merged

# After state:
# ------------
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel cdp Vlan 20,40-60
#  switchport l2proto-tunnel lacp Vlan 10-12
#  switchport l2proto-tunnel lldp Vlan 10,12
#  switchport l2proto-tunnel stp Vlan 20-21,25-26


# Using "deleted" state
#
# Before state:
# -------------
# sonic# show running-configuration interface Ethernet 0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lacp Vlan 10-12
#  switchport l2proto-tunnel cdp Vlan 20,40-60
#  switchport l2proto-tunnel stp Vlan 25-26

- name: Delete interface L2PT configurations
  dellemc.enterprise_sonic.sonic_br_l2pt:
    config:
      - name: Ethernet0
        bridge_l2pt_params:
          - protocol: 'LACP'
            vlan_ids:
              - 10-12
    state: deleted

# After state:
# ------------
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel cdp Vlan 20,40-60
#  switchport l2proto-tunnel stp Vlan 25-26


# Using "deleted" state
#
# Before state:
# -------------
# sonic# show running-configuration interface Ethernet 0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lacp Vlan 10-12
#  switchport l2proto-tunnel cdp Vlan 20,40-60
#  switchport l2proto-tunnel stp Vlan 25-26
# sonic# show running-configuration interface Ethernet 8
# !
# interface Ethernet8
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lldp Vlan 100
#  switchport l2proto-tunnel stp Vlan 100-150

- name: Delete all interface L2PT configurations
  dellemc.enterprise_sonic.sonic_br_l2pt:
    config:
    state: deleted

# After state:
# ------------
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
# sonic# show running-configuration interface Ethernet 8
# !
# interface Ethernet8
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown


# Using "deleted" state
#
# Before state:
# -------------
# sonic# show running-configuration interface Ethernet 0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lacp Vlan 10-12
#  switchport l2proto-tunnel cdp Vlan 20,40-60
#  switchport l2proto-tunnel stp Vlan 25-26

- name: Delete L2PT configurations for protocol
  dellemc.enterprise_sonic.sonic_br_l2pt:
    config:
      - name: Ethernet0
        bridge_l2pt_params:
          - protocol: 'LACP'
          - protocol: 'CDP'
            vlan_ids: []
    state: deleted

# After state:
# ------------
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel stp Vlan 25-26


# Using "deleted" state
#
# Before state:
# -------------
# sonic# show running-configuration interface Ethernet 0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lacp Vlan 10-12
#  switchport l2proto-tunnel cdp Vlan 20,40-60
#  switchport l2proto-tunnel stp Vlan 25-26

- name: Delete interface L2PT configurations
  dellemc.enterprise_sonic.sonic_br_l2pt:
    config:
      - name: Ethernet0
        bridge_l2pt_params:
          - protocol: 'LACP'
            vlan_ids:
              - 11
          - protocol: 'CDP'
            vlan_ids:
              - 40-50
    state: deleted

# After state:
# ------------
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lacp Vlan 10,12
#  switchport l2proto-tunnel cdp Vlan 20,51-60
#  switchport l2proto-tunnel stp Vlan 25-26


# Using "deleted" state
#
# Before state:
# -------------
# sonic# show running-configuration interface Ethernet 0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lacp Vlan 10-12
#  switchport l2proto-tunnel cdp Vlan 20,40-60
#  switchport l2proto-tunnel stp Vlan 25-26
# sonic# show running-configuration interface Ethernet 8
# !
# interface Ethernet8
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lacp Vlan 10-12
#  switchport l2proto-tunnel cdp Vlan 20,40-60
#  switchport l2proto-tunnel stp Vlan 25-26

- name: Delete L2PT configurations for entire interface
  dellemc.enterprise_sonic.sonic_br_l2pt:
    config:
      - name: Ethernet0
        bridge_l2pt_params: []
      - name: Ethernet8
    state: deleted

# After state:
# ------------
# sonic# show running-configuration interface Ethernet 0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
# sonic# show running-configuration interface Ethernet 8
# !
# interface Ethernet8
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown


# Using "replaced" state
#
# Before state:
# -------------
# sonic# show running-configuration interface Ethernet 0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lacp Vlan 10-12
#  switchport l2proto-tunnel cdp Vlan 20,40-60
#  switchport l2proto-tunnel stp Vlan 25-26
# sonic# show running-configuration interface Ethernet 8
# !
# interface Ethernet8
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lldp Vlan 100
#  switchport l2proto-tunnel stp Vlan 100-150

- name: Replace interface L2PT configurations
  dellemc.enterprise_sonic.sonic_br_l2pt:
    config:
      - name: Ethernet0
        bridge_l2pt_params:
          - protocol: 'LLDP'
            vlan_ids:
              - 10-12
          - protocol: 'LACP'
            vlan_ids:
              - 8
              - 12-14
          - protocol: 'CDP'
            vlan_ids:
              - 20-45
    state: replaced

# After state:
# ------------
# sonic# show running-configuration interface Ethernet 0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lldp Vlan 10-12
#  switchport l2proto-tunnel lacp Vlan 8,12-14
#  switchport l2proto-tunnel cdp Vlan 20-45
# sonic# show running-configuration interface Ethernet 8
# !
# interface Ethernet8
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lldp Vlan 100
#  switchport l2proto-tunnel stp Vlan 100-150


# Using "overridden" state
#
# Before state:
# -------------
# sonic# show running-configuration interface Ethernet 0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lldp Vlan 10
#  switchport l2proto-tunnel lacp Vlan 15-50
#  switchport l2proto-tunnel cdp 20
#  switchport l2proto-tunnel stp 25-26
# sonic# show running-configuration interface Ethernet 8
# !
# interface Ethernet8
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel lldp Vlan 100
#  switchport l2proto-tunnel stp Vlan 100-150

- name: Override interface L2PT configurations
  dellemc.enterprise_sonic.sonic_br_l2pt:
    config:
      - name: Ethernet0
        bridge_l2pt_params:
          - protocol: 'LACP'
            vlan_ids:
              - 10-12
          - protocol: 'CDP'
            vlan_ids:
              - 20
              - 40-60
          - protocol: 'STP'
            vlan_ids:
              - 25-26
    state: overridden

# After state:
# ------------
# sonic# show running-configuration interface Ethernet0
# !
# interface Ethernet0
#  mtu 9100
#  speed 400000
#  fec RS
#  unreliable-los auto
#  no shutdown
#  switchport l2proto-tunnel cdp Vlan 20,40-60
#  switchport l2proto-tunnel lacp Vlan 10-12
#  switchport l2proto-tunnel stp Vlan 25-26
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
  description: The configuration that would result from non-check-mode module invocation.
  returned: when C(check_mode)
  type: list
commands:
  description: The set of commands pushed to the remote device. In C(check_mode) the needed commands are displayed, but not pushed to the device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.br_l2pt.br_l2pt import Br_l2ptArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.br_l2pt.br_l2pt import Br_l2pt


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Br_l2ptArgs.argument_spec,
                           supports_check_mode=True)

    result = Br_l2pt(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
