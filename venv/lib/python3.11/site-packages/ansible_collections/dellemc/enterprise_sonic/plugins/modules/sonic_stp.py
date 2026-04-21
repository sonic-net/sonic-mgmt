#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_stp
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_stp
version_added: "2.3.0"
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Manage STP configuration on SONiC
description:
  - This module provides configuration management of STP for devices running SONiC
author: "S. Talabi (@stalabi1)"
options:
  config:
    description:
      - Specifies STP configurations
      - I(mstp), I(pvst) and I(rapid_pvst) are mutually exclusive.
    type: dict
    suboptions:
      global:
        description:
          - Global STP configuration
        type: dict
        suboptions:
          enabled_protocol:
            description:
              - Specifies the type of STP enabled on the device
            type: str
            choices: ['mst', 'pvst', 'rapid_pvst']
          loop_guard:
            description:
              - The loop guard default setting for the bridge
            type: bool
          bpdu_filter:
            description:
              - Enables edge port BPDU filter
            type: bool
          disabled_vlans:
            description:
              - List of disabled STP VLANs. The value of a list item can be a single VLAN ID or a range of VLAN IDs
              - separated by '-' or '..'; for example 70-100 or 70..100.
            type: list
            elements: str
          root_guard_timeout:
            description:
              - Specifies root guard recovery timeout in seconds before the port is moved back to forwarding state
              - Range 5-600
            type: int
          portfast:
            description:
              - Enables PortFast globally on all access ports
              - Configurable for pvst protocol
            type: bool
          hello_time:
            description:
              - Interval in seconds between periodic transmissions of configuration messages by designated ports
              - Range 1-10
            type: int
          max_age:
            description:
              - Maximum age in seconds of the information transmitted by the bridge when it is the root bridge
              - Range 6-40
            type: int
          fwd_delay:
            description:
              - Delay in seconds used by STP bridges to transition root and designated ports to forwarding
              - Range 4-30
            type: int
          bridge_priority:
            description:
              - The manageable component of the bridge identifier
              - Value must be a multiple of 4096 in the range of 0-61440
            type: int
      interfaces:
        description:
          - Interfaces STP configuration
        type: list
        elements: dict
        suboptions:
          intf_name:
            description:
              - Name of interface
            type: str
            required: True
          edge_port:
            description:
              - Configure interface as an STP edge port
            type: bool
          link_type:
            description:
              - Specifies the interface's link type
            type: str
            choices: ['point-to-point', 'shared']
          guard:
            description:
              - Enables root guard or loop guard
            type: str
            choices: ['loop', 'root', 'none']
          bpdu_guard:
            description:
              - Enable edge port BPDU guard
            type: bool
          bpdu_filter:
            description:
              - Enables edge port BPDU filter
            type: bool
          portfast:
            description:
              - Enable/Disable portfast on specified interface
              - Configurable for pvst protocol
            type: bool
          uplink_fast:
            description:
              - Enables uplink fast
            type: bool
          shutdown:
            description:
              - Port to be shutdown when it receives a BPDU
            type: bool
          cost:
            description:
              - The port's contribution, when it is the root port, to the root path cost for the bridge
              - Range 1-200000000
            type: int
          port_priority:
            description:
              - The manageable component of the port identifier
              - Range 0-240
            type: int
          stp_enable:
            description:
              - Enables STP on the interface
            type: bool
      mstp:
        description:
          - Multi STP configuration
        type: dict
        suboptions:
          mst_name:
            description:
              - Name of the MST configuration identifier
            type: str
          revision:
            description:
              - Revision level of the MST configuration identifier, range 0-65535
            type: int
          max_hop:
            description:
              - Number of bridges in an MST region that a BPDU can traverse before it is discarded
              - Range 1-40
            type: int
          hello_time:
            description:
              - Interval in seconds between periodic transmissions of configuration messages by designated ports
              - Range 1-10
            type: int
          max_age:
            description:
              - Maximum age in seconds of the information transmitted by the bridge when it is the root bridge
              - Range 6-40
            type: int
          fwd_delay:
            description:
              - Delay in seconds used by STP bridges to transition root and designated ports to forwarding
              - Range 4-30
            type: int
          mst_instances:
            description:
              - Configuration for MST instances
            type: list
            elements: dict
            suboptions:
              mst_id:
                description:
                  - Value used to identify MST instance, range 0-4094
                type: int
                required: True
              bridge_priority:
                description:
                  - The manageable component of the bridge identifier
                  - Value must be a multiple of 4096 in the range of 0-61440
                type: int
              vlans:
                description:
                  - List of VLANs mapped to the MST instance. The value of a list item can be a single VLAN ID or a range of VLAN IDs
                  - separated by '-' or '..'; for example 70-100 or 70..100.
                type: list
                elements: str
              interfaces:
                description:
                  - List of STP enabled interfaces
                type: list
                elements: dict
                suboptions:
                  intf_name:
                    description:
                      - Reference to the STP interface
                    type: str
                    required: True
                  cost:
                    description:
                      - The port's contribution, when it is the root port, to the root path cost for the bridge
                      - Range 1-200000000
                    type: int
                  port_priority:
                    description:
                      - The manageable component of the port identifier, range 0-240
                    type: int
      pvst:
        description:
          - Per VLAN STP configuration
        type: list
        elements: dict
        suboptions:
          vlan_id:
            description:
              - VLAN identifier, range 1-4094
            type: int
            required: True
          hello_time:
            description:
              - Interval in seconds between periodic transmissions of configuration messages by designated ports
              - Range 1-10
            type: int
          max_age:
            description:
              - Maximum age in seconds of the information transmitted by the bridge when it is the root bridge
              - Range 6-40
            type: int
          fwd_delay:
            description:
              - Delay in seconds used by STP bridges to transition root and designated ports to forwarding
              - Range 4-30
            type: int
          bridge_priority:
            description:
              - The manageable component of the bridge identifier
              - Value must be a multiple of 4096 in the range of 0-61440
            type: int
          interfaces:
            description:
              - List of STP enabled interfaces
            type: list
            elements: dict
            suboptions:
              intf_name:
                description:
                  - Reference to the STP interface
                type: str
                required: True
              cost:
                description:
                  - The port's contribution, when it is the root port, to the root path cost for the bridge
                  - Range 1-200000000
                type: int
              port_priority:
                description:
                  - The manageable component of the port identifier, range 0-240
                type: int
      rapid_pvst:
        description:
          - Rapid per VLAN STP configuration
        type: list
        elements: dict
        suboptions:
          vlan_id:
            description:
              - VLAN identifier, range 1-4094
            type: int
            required: True
          hello_time:
            description:
              - Interval in seconds between periodic transmissions of configuration messages by designated ports
              - Range 1-10
            type: int
          max_age:
            description:
              - Maximum age in seconds of the information transmitted by the bridge when it is the root bridge
              - Range 6-40
            type: int
          fwd_delay:
            description:
              - Delay in seconds used by STP bridges to transition root and designated ports to forwarding
              - Range 4-30
            type: int
          bridge_priority:
            description:
              - The manageable component of the bridge identifier
              - Value must be a multiple of 4096 in the range of 0-61440
            type: int
          interfaces:
            description:
              - List of STP enabled interfaces
            type: list
            elements: dict
            suboptions:
              intf_name:
                description:
                  - Reference to the STP interface
                type: str
                required: True
              cost:
                description:
                  - The port's contribution, when it is the root port, to the root path cost for the bridge
                  - Range 1-200000000
                type: int
              port_priority:
                description:
                  - The manageable component of the port identifier, range 0-240
                type: int
  state:
    description:
      - The state of the configuration after module completion
    type: str
    choices: ['merged', 'deleted', 'replaced', 'overridden']
    default: merged
"""

EXAMPLES = """

# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration spanning-tree
# (No spanning-tree configuration present)

- name: Merge STP configurations
  dellemc.enterprise_sonic.sonic_stp:
    config:
      global:
        enabled_protocol: mst
        loop_guard: true
        bpdu_filter: true
        disabled_vlans:
          - 4-6
        hello_time: 5
        max_age: 10
        fwd_delay: 20
        bridge_priority: 4096
      interfaces:
        - intf_name: Ethernet20
          edge_port: true
          link_type: shared
          guard: loop
          bpdu_guard: true
          bpdu_filter: true
          uplink_fast: true
          shutdown: true
          cost: 20
          port_priority: 30
          stp_enable: true
      mstp:
        mst_name: mst1
        revision: 1
        max_hop: 3
        hello_time: 6
        max_age: 9
        fwd_delay: 12
        mst_instances:
          - mst_id: 1
            bridge_priority: 2048
            vlans:
              - 1
            interfaces:
              - intf_name: Ethernet20
                cost: 60
                port_priority: 65
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration spanning-tree
#  no spanning-tree vlan 4-6
#  spanning-tree mode mst
#  spanning-tree edge-port bpdufilter default
#  spanning-tree forward-time 20
#  spanning-tree hello-time 5
#  spanning-tree max-age 10
#  spanning-tree loopguard default
#  spanning-tree mst hello-time 6
#  spanning-tree mst forward-time 12
#  spanning-tree mst max-age 9
#  spanning-tree mst max-hops 3
#  spanning-tree mst 1 priority 2048
#  !
#  spanning-tree mst configuration
#   name mst1
#   revision 1
#   instance 1 vlan 1
#   activate
#  !
#  interface Ethernet20
#   spanning-tree bpdufilter enable
#   spanning-tree guard loop
#   spanning-tree bpduguard port-shutdown
#   spanning-tree cost 20
#   spanning-tree link-type shared
#   spanning-tree port-priority 30
#   spanning-tree port type edge
#   spanning-tree uplinkfast
#   spanning-tree mst 1 cost 60
#   spanning-tree mst 1 port-priority 65


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration spanning-tree
#  no spanning-tree vlan 4-6
#  spanning-tree mode mst
#  spanning-tree edge-port bpdufilter default
#  spanning-tree loopguard default
#  spanning-tree mst hello-time 6
#  spanning-tree mst forward-time 12
#  spanning-tree mst max-age 9
#  spanning-tree mst max-hops 3
#  spanning-tree mst 1 priority 2048
#  !
#  spanning-tree mst configuration
#   name mst1
#   revision 1
#   instance 1 vlan 1
#   activate
#  !
#  interface Ethernet20
#   spanning-tree bpdufilter enable
#   spanning-tree guard loop
#   spanning-tree bpduguard port-shutdown
#   spanning-tree cost 20
#   spanning-tree link-type shared
#   spanning-tree port-priority 30
#   spanning-tree port type edge
#   spanning-tree uplinkfast
#   spanning-tree mst 1 cost 60
#   spanning-tree mst 1 port-priority 65

- name: Replace STP configurations
  dellemc.enterprise_sonic.sonic_stp:
    config:
      interfaces:
        - intf_name: Ethernet20
          cost: 25
          port_priority: 35
      mstp:
        mst_name: mst2
        revision: 2
        max_hop: 4
        hello_time: 7
        max_age: 10
        fwd_delay: 13
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration spanning-tree
#  no spanning-tree vlan 4-6
#  spanning-tree mode mst
#  spanning-tree edge-port bpdufilter default
#  spanning-tree loopguard default
#  spanning-tree mst hello-time 7
#  spanning-tree mst forward-time 13
#  spanning-tree mst max-age 10
#  spanning-tree mst max-hops 4
#  !
#  spanning-tree mst configuration
#   name mst2
#   revision 2
#   activate
#  !
#  interface Ethernet20
#   spanning-tree cost 25
#   spanning-tree port-priority 35


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration spanning-tree
#  no spanning-tree vlan 4-6
#  spanning-tree mode mst
#  spanning-tree edge-port bpdufilter default
#  spanning-tree loopguard default
#  spanning-tree mst hello-time 7
#  spanning-tree mst forward-time 13
#  spanning-tree mst max-age 10
#  spanning-tree mst max-hops 4
#  !
#  spanning-tree mst configuration
#   name mst2
#   revision 2
#   activate
#  !
#  interface Ethernet20
#   spanning-tree cost 25
#   spanning-tree port-priority 35

- name: Override STP configurations
  dellemc.enterprise_sonic.sonic_stp:
    config:
      global:
        enabled_protocol: pvst
        bpdu_filter: true
        root_guard_timeout: 25
        portfast: true
        hello_time: 5
        max_age: 10
        fwd_delay: 20
        bridge_priority: 4096
      pvst:
        - vlan_id: 1
          hello_time: 4
          max_age: 6
          fwd_delay: 8
          bridge_priority: 4096
          interfaces:
            - intf_name: Ethernet20
              cost: 10
              port_priority: 50
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration spanning-tree
#  spanning-tree mode pvst
#  spanning-tree edge-port bpdufilter default
#  spanning-tree forward-time 20
#  spanning-tree guard root timeout 25
#  spanning-tree hello-time 5
#  spanning-tree max-age 10
#  spanning-tree priority 4096
#  spanning-tree portfast default
#  spanning-tree vlan 1 hello-time 4
#  spanning-tree vlan 1 forward-time 8
#  spanning-tree vlan 1 max-age 6
# sonic# show running-configuration interface Ethernet 20 | grep spanning-tree
#  spanning-tree vlan 1 cost 10
#  spanning-tree vlan 1 port-priority 50


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration spanning-tree
#  spanning-tree mode pvst
#  spanning-tree edge-port bpdufilter default
#  spanning-tree forward-time 20
#  spanning-tree guard root timeout 25
#  spanning-tree hello-time 5
#  spanning-tree max-age 10
#  spanning-tree priority 4096
#  spanning-tree portfast default
#  spanning-tree vlan 1 hello-time 4
#  spanning-tree vlan 1 forward-time 8
#  spanning-tree vlan 1 max-age 6
# sonic# show running-configuration interface Ethernet 20 | grep spanning-tree
#  spanning-tree vlan 1 cost 10
#  spanning-tree vlan 1 port-priority 50

- name: Delete STP configurations
  dellemc.enterprise_sonic.sonic_stp:
    config:
      global:
        bpdu_filter: true
        root_guard_timeout: 25
      pvst:
        - vlan_id: 1
          interfaces:
            - intf_name: Ethernet20
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration spanning-tree
# spanning-tree mode pvst
# spanning-tree forward-time 20
# spanning-tree hello-time 5
# spanning-tree max-age 10
# spanning-tree priority 4096
# spanning-tree portfast default
# spanning-tree vlan 1 hello-time 4
# spanning-tree vlan 1 forward-time 8
# spanning-tree vlan 1 max-age 6
# sonic# show running-configuration interface Ethernet 20 | grep spanning-tree
# (No spanning-tree configuration present)
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.stp.stp import StpArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.stp.stp import Stp


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=StpArgs.argument_spec,
                           supports_check_mode=True)

    result = Stp(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
