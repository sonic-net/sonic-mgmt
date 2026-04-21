#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_static_routes
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_static_routes
version_added: 2.0.0
notes:
  - Supports C(check_mode).
short_description: Manage static routes configuration on SONiC
description:
  - This module provides configuration management of static routes for devices running SONiC
author: "S. Talabi (@stalabi1)"
options:
  config:
    type: list
    elements: dict
    description:
      - Manages 'static_routes' configurations
    suboptions:
      vrf_name:
        required: True
        type: str
        description:
          - Name of the configured VRF on the device.
      static_list:
        type: list
        elements: dict
        description:
          - A list of 'static_routes' configurations.
        suboptions:
          prefix:
            required: True
            type: str
            description:
              - Destination prefix for the static route, either IPv4 or IPv6.
          next_hops:
            type: list
            elements: dict
            description:
              - A list of next-hops to be utilised for the static route being specified.
            suboptions:
              index:
                required: True
                type: dict
                description:
                  - An identifier utilised to uniquely reference the next-hop.
                suboptions:
                  blackhole:
                    type: bool
                    default: False
                    description:
                      - Indicates that packets matching this route should be discarded.
                  interface:
                    type: str
                    description:
                      - The reference to a base interface.
                  nexthop_vrf:
                    type: str
                    description:
                      - Name of the next-hop network instance for leaked routes.
                  next_hop:
                    type: str
                    description:
                      - The next-hop that is to be used for the static route.
              metric:
                type: int
                description:
                  - Specifies the preference of the next-hop entry when it is injected into the RIB.
              track:
                type: int
                description:
                  - The IP SLA track ID for static route.
              tag:
                type: int
                description:
                  - The tag value for the static route.
  state:
    description:
      - The state of the configuration after module completion.
    type: str
    choices:
    - merged
    - deleted
    - overridden
    - replaced
    default: merged
"""

EXAMPLES = """

# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep "ip route"
# (No "ip route" configuration present)

- name: Merge static routes configurations
  dellemc.enterprise_sonic.sonic_static_routes:
    config:
      - vrf_name: 'default'
        static_list:
          - prefix: '2.0.0.0/8'
            next_hops:
              - index:
                  interface: 'Ethernet4'
                metric: 1
                tag: 2
                track: 3
              - index:
                next_hop: '3.0.0.0'
                metric: 2
                tag: 4
                track: 8
      - vrf_name: 'VrfReg1'
        static_list:
          - prefix: '3.0.0.0/8'
            next_hops:
              - index:
                  interface: 'eth0'
                  nexthop_vrf: 'VrfReg2'
                  next_hop: '4.0.0.0'
                metric: 4
                tag: 5
                track: 6
              - index:
                  blackhole: true
                metric: 10
                tag: 20
                track: 30
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip route"
# ip route 2.0.0.0/8 3.0.0.0 tag 4 track 8 2
# ip route 2.0.0.0/8 interface Ethernet4 tag 2 track 3 1
# ip route vrf VrfReg1 3.0.0.0/8 4.0.0.0 interface Management 0 nexthop-vrf VrfReg2 tag 5 track 6 4
# ip route vrf VrfReg1 3.0.0.0/8 blackhole tag 20 track 30 10
#
#
# Modifying previous merge

- name: Modify static routes configurations
  dellemc.enterprise_sonic.sonic_static_routes:
    config:
      - vrf_name: 'VrfReg1'
        static_list:
          - prefix: '3.0.0.0/8'
            next_hops:
              - index:
                  blackhole: true
                metric: 11
                tag: 22
                track: 33
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip route"
# ip route 2.0.0.0/8 3.0.0.0 tag 4 track 8 2
# ip route 2.0.0.0/8 interface Ethernet4 tag 2 track 3 1
# ip route vrf VrfReg1 3.0.0.0/8 4.0.0.0 interface Management 0 nexthop-vrf VrfReg2 tag 5 track 6 4
# ip route vrf VrfReg1 3.0.0.0/8 blackhole tag 22 track 33 11


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep "ip route"
# ip route 4.0.0.0/8 2.0.0.0 tag 4 track 8 2

- name: Override static routes configurations
  dellemc.enterprise_sonic.sonic_static_routes:
    config:
      - vrf_name: 'VrfReg2'
        static_list:
          - prefix: '3.0.0.0/8'
            next_hops:
              - index:
                  blackhole: true
                metric: 10
                tag: 20
                track: 30
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip route"
# ip route vrf VrfReg2 3.0.0.0/8 blackhole tag 20 track 30 10


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep "ip route"
# ip route 4.0.0.0/8 2.0.0.0 tag 4 track 8 2

- name: Replace static routes configurations
  dellemc.enterprise_sonic.sonic_static_routes:
    config:
      - vrf_name: 'default'
        static_list:
          - prefix: '4.0.0.0/8'
            next_hops:
              - index:
                  blackhole: true
                metric: 5
                tag: 10
                track: 15
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip route"
# ip route 4.0.0.0/8 blackhole tag 10 track 15 5


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep "ip route"
# ip route 2.0.0.0/8 3.0.0.0 tag 4 track 8 2
# ip route 2.0.0.0/8 interface Ethernet4 tag 2 track 3 1
# ip route vrf VrfReg1 3.0.0.0/8 4.0.0.0 interface Management 0 nexthop-vrf VrfReg2 tag 5 track 6 4
# ip route vrf VrfReg1 3.0.0.0/8 blackhole tag 22 track 33 11

- name: Delete static routes configurations
  dellemc.enterprise_sonic.sonic_static_routes:
    config:
      - vrf_name: 'default'
        static_list:
          - prefix: '2.0.0.0/8'
            next_hops:
              - index:
                  interface: 'Ethernet4'
      - vrf_name: 'VrfReg1'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip route"
# ip route 2.0.0.0/8 3.0.0.0 tag 4 track 8 2
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.static_routes.static_routes import Static_routesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.static_routes.static_routes import Static_routes


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Static_routesArgs.argument_spec,
                           supports_check_mode=True)

    result = Static_routes(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
