#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_vrrp
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_vrrp
author: "Santhosh Kumar T(@santhosh-kt)"
version_added: "2.5.0"
short_description: Configure VRRP protocol settings on SONiC.
description:
  - This module provides configuration management of VRRP protocol settings on devices running SONiC
  - Configure interface IP address before configuring VRRP
  - Configure interface VRF forwarding before configuring VRRP in a VRF
options:
  config:
    description:
      - Specifies the VRRP related configuration.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Full name of the Layer 3 interface, i.e. Eth1/1.
        required: true
        type: str
      group:
        description:
          - Defining the VRRP/VRRP6 group
        type: list
        elements: dict
        suboptions:
          virtual_router_id:
            description:
              - VRRP ID (1 to 255)
            type: int
            required: true
          afi:
            description:
              - VRRP configurations to be set for the interface mentioned in types(VRRP/VRRP6).
            type: str
            required: true
            choices:
              - ipv4
              - ipv6
          virtual_address:
            description:
              - Configure virtual IP Address.
            type: list
            elements: dict
            suboptions:
              address:
                description:
                  - List of IP addresses to be set.
                type: str
          advertisement_interval:
            description:
              - Configure advertisement interval (1 to 254)
            type: int
          preempt:
            description:
              - Enable preempt
            type: bool
          priority:
            description:
              - Priority for MASTER election (1 to 254)
            type: int
          track_interface:
            description:
              - Configure track interface for priority change.
              - I(interface) and I(priority_increment) are required together.
            type: list
            elements: dict
            suboptions:
              interface:
                description:
                  - Full name of the Layer 3 interface, i.e. Eth1/1.
                type: str
                required: true
              priority_increment:
                description:
                  - Weight for changing priority (1 to 254)
                type: int
          use_v2_checksum:
            description:
              - Enable checksum compatibility with VRRPv2 (Not supported for IPv6).
            type: bool
          version:
            description:
              - Configure VRRP Version 2 or 3 (Not supported for IPv6).
            type: int
            choices:
              - 2
              - 3
  state:
    description:
      - Specifies the operation to be performed on the VRRP process configured on the device.
      - In case of merged, the input configuration will be merged with the existing VRRP configuration on the device.
      - In case of deleted, the existing VRRP configuration will be removed from the device.
      - In case of overridden, all existing VRRP configuration will be deleted and the specified input configuration will be installed.
      - In case of replaced, the existing VRRP configuration on the device will be replaced by the configuration in the
        playbook for each VRRP interface/group configured by the playbook.
    default: merged
    type: str
    choices: ['merged', 'deleted','replaced', 'overridden']
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
#  ipv6 address 81::1/24
#  !
#  vrrp 1 address-family ipv4
#  preempt
#  vip 81.1.1.3
#  vip 81.1.1.4
#  !
#  vrrp 10 address-family ipv6
#  priority 10
#  advertisement-interval 4
#  vip 81::3
#  vip 81::4
# !
# interface Eth1/3
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  !
#  vrrp 5 address-family ipv4
#  priority 20
#  vip 61.1.1.3
#  !
#  vrrp 15 address-family ipv4
#  priority 20
#  preempt
#  vip 61.1.1.4
# !
- name: Delete VRRP and VRRP6 relay configurations
  sonic_vrrp:
    config:
      - name: 'Eth1/1'
        group:
          - virtual_router_id: 1
            afi: ipv4
            virtual_address:
              - address: 81.1.1.4
            preempt: true
          - virtual_router_id: 10
            afi: ipv6
            advertisement_interval: 4
            priority: 10
      - name: 'Eth1/3'
        group:
          - virtual_router_id: 5
            afi: ipv4
            virtual_address:
              - address: 61.1.1.3
            priority: 20
          - virtual_router_id: 15
            afi: ipv4
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
#  !
#  vrrp 1 address-family ipv4
#  vip 81.1.1.3
#  !
#  vrrp 10 address-family ipv6
#  vip 81::3
#  vip 81::4
# !
# interface Eth1/3
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
# interface Eth1/3
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
# !
- name: Add VRRP and VRRP6 configurations
  sonic_vrrp:
    config:
      - name: 'Eth1/1'
        group:
          - virtual_router_id: 1
            afi: ipv4
            virtual_address:
              - address: 81.1.1.3
              - address: 81.1.1.4
            preempt: true
          - virtual_router_id: 10
            afi: ipv6
            virtual_address:
              - address: 81::3
              - address: 81::4
            advertisement_interval: 4
            priority: 10
      - name: 'Eth1/3'
        group:
          - virtual_router_id: 5
            afi: ipv4
            virtual_address:
              - address: 61.1.1.3
            priority: 20
          - virtual_router_id: 15
            afi: ipv4
            virtual_address:
              - address: 61.1.1.4
            preempt: true
            priority: 20
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
#  ipv6 address 81::1/24
#  !
#  vrrp 1 address-family ipv4
#  preempt
#  vip 81.1.1.3
#  vip 81.1.1.4
#  !
#  vrrp 10 address-family ipv6
#  priority 10
#  advertisement-interval 4
#  vip 81::3
#  vip 81::4
# !
# interface Eth1/3
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  !
#  vrrp 5 address-family ipv4
#  priority 20
#  vip 61.1.1.3
#  !
#  vrrp 15 address-family ipv4
#  priority 20
#  preempt
#  vip 61.1.1.4
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
#  ipv6 address 81::1/24
#  !
#  vrrp 1 address-family ipv4
#  preempt
#  vip 81.1.1.3
#  vip 81.1.1.4
#  !
#  vrrp 10 address-family ipv6
#  priority 10
#  advertisement-interval 4
#  vip 81::3
#  vip 81::4
# !
# interface Eth1/3
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  !
#  vrrp 5 address-family ipv4
#  priority 20
#  vip 61.1.1.3
#  !
#  vrrp 15 address-family ipv4
#  priority 20
#  preempt
#  vip 61.1.1.4
# !
- name: Replace VRRP and VRRP6 relay configurations
  sonic_vrrp:
    config:
      - name: 'Eth1/1'
        group:
          - virtual_router_id: 10
            afi: ipv6
            priority: 20
      - name: 'Eth1/3'
        group:
          - virtual_router_id: 5
            afi: ipv4
            virtual_address:
              - address: 61.1.1.5
            preempt: false
            track_interface:
              - interface: Eth1/1
                priority_increment: 10
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
#  ipv6 address 81::1/24
#  !
#  vrrp 1 address-family ipv4
#  vip 81.1.1.3
#  vip 81.1.1.4
#  !
#  vrrp 10 address-family ipv6
#  priority 20
# !
# interface Eth1/3
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  !
#  vrrp 5 address-family ipv4
#  no preempt
#  vip 61.1.1.5
#  track-interface Eth1/1 weight 10
#  !
#  vrrp 15 address-family ipv4
#  priority 20
#  preempt
#  vip 61.1.1.4
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
#  ipv6 address 81::1/24
#  !
#  vrrp 1 address-family ipv4
#  preempt
#  vip 81.1.1.3
#  vip 81.1.1.4
#  !
#  vrrp 10 address-family ipv6
#  priority 10
#  advertisement-interval 4
#  vip 81::3
#  vip 81::4
# !
# interface Eth1/3
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  !
#  vrrp 5 address-family ipv4
#  priority 20
#  vip 61.1.1.3
#  !
#  vrrp 15 address-family ipv4
#  priority 20
#  preempt
#  vip 61.1.1.4
# !
- name: Overwrite the VRRP and VRRP6 relay configurations
  sonic_vrrp:
    config:
      - name: 'Eth1/1'
        group:
          - virtual_router_id: 15
            afi: ipv4
            virtual_address:
              - address: 81.1.1.15
            preempt: false
      - name: 'Eth1/3'
        group:
          - virtual_router_id: 5
            afi: ipv4
          - virtual_router_id: 15
            afi: ipv4
            virtual_address:
              - address: 61.1.1.5
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
#  ipv6 address 81::1/24
#  !
#  vrrp 15 address-family ipv4
#  no preempt
#  vip 81.1.1.15
# !
# interface Eth1/3
#  mtu 9100
#  speed 400000
#  fec RS
#  no shutdown
#  ip address 61.1.1.1/24
#  !
#  vrrp 5 address-family ipv4
#  !
#  vrrp 15 address-family ipv4
#  vip 61.1.1.5
# !
"""

RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after(generated):
  description: The generated configuration model invocation.
  returned: when C(check_mode)
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.vrrp.vrrp import VrrpArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.vrrp.vrrp import Vrrp


def main():
    """
    Main entry point for module execution
    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=VrrpArgs.argument_spec,
                           supports_check_mode=True)

    result = Vrrp(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
