#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
The module file for sonic_ospfv3_interfaces
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_ospfv3_interfaces
version_added: '3.1.0'
notes:
  - Supports C(check_mode).
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
short_description: Configure OSPFv3 interface mode protocol settings on SONiC.
description:
  - This module provides configuration management of OSPFv3 interface mode parameters on devices running SONiC.
  - Configure VRF instance before configuring OSPFv3 in a VRF.
  - Configure global/VRF OSPFv3 instance before configuring OSPFv3 in interfaces.
author: "Mansi Jharia (@Mansi062001)"
options:
      config:
        description:
          - Specifies the OSPFv3 interface mode related configuration.
        type: list
        elements: dict
        suboptions:
          name:
            required: True
            type: str
            description:
              - Full name of the interface, i.e. Ethernet1.
          advertise:
            description:
              - Enable OSPFv3 interface advertise.
              - expects name of a prefix list.
            type: str
          area_id:
            description:
              - OSPFv3 Area ID of the network (A.B.C.D or 0 to 4294967295).
            type: str
          bfd:
            description:
              - Configure OSPFv3 interface BFD.
            type: dict
            suboptions:
              enable:
                description:
                  - Enable BFD support for OSPFv3.
                type: bool
                required: true
              bfd_profile:
                description:
                  - Configure BFD profile.
                type: str
          cost:
            description:
              - Configure OSPFv3 interface cost (1 to 65535).
            type: int
          dead_interval:
            description:
              - Configure OSPFv3 adjacency dead interval (1 to 65535).
            type: int
          hello_interval:
            description:
              - Configure OSPFv3 neighbour hello interval (1 to 65535).
            type: int
          mtu_ignore:
            description:
              - Disable OSPFv3 MTU mismatch detection.
            type: bool
          network:
            description:
              - Configure OSPFv3 interface network type
            type: str
            choices:
              - broadcast
              - point_to_point
          passive:
            description:
              - Configure ospfv3 interface as passive.
            type: bool
          priority:
            description:
              - Configure OSPFv3 adjacency router priority (0 to 255).
            type: int
          retransmit_interval:
            description:
              - Configure OSPFv3 retransmit interval (2 to 65535).
            type: int
          transmit_delay:
            description:
              - Configure OSPFv3 transmit delay (1 to 65535).
            type: int
      state:
        description:
          - Specifies the operation to be performed on the OSPFv3 interfaces configured on the device.
          - In case of merged, the input configuration will be merged with the existing OSPFv3 interfaces configuration on the device.
          - In case of deleted, the specified existing OSPFv3 interfaces configuration will be removed from the device.
          - In case of overridden, all the existing OSPFv3 interfaces configuration will be deleted and the specified input
            configuration will be installed.
          - In case of replaced, the existing OSPFv3 interface configuration on the device will be replaced by the configuration in the
            playbook for each interface group configured by the playbook.
        type: str
        default: merged
        choices: ['merged', 'deleted', 'replaced', 'overridden']
"""
EXAMPLES = """
# Using deleted

# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ipv6 ospfv3 advertise prefix-list test1
# ipv6 ospfv3 area 2.2.2.2
# ipv6 ospfv3 bfd
# ipv6 ospfv3 bfd profile profile2
# ipv6 ospfv3 cost 30
# ipv6 ospfv3 dead-interval 40
# ipv6 ospfv3 hello-interval 10
# ipv6 ospfv3 mtu-ignore
# ipv6 ospfv3 network point-to-point
# ipv6 ospfv3 priority 20
# ipv6 ospfv3 passive
# !
# interface Eth1/2
# ipv6 ospfv3 bfd
# ipv6 ospfv3 network point-to-point
# !
# interface Eth1/3
# ipv6 ospfv3 bfd
# ipv6 ospfv3 network point-to-point
# ipv6 ospfv3 area 3.3.3.3
# !
# sonic#

- name: Delete the specified OSPFv3_interface configurations
  sonic_ospfv3_interfaces:
    config:
      - name: 'Eth1/1'
        area_id: '2.2.2.2'
        cost: 30
        priority: 20
        hello_interval: 10
        dead_interval: 40
        mtu_ignore: true
        bfd:
          enable: true
          bfd_profile: 'profile2'
        network: point_to_point
      - name: 'Eth1/2'
        bfd:
          enable: true
      - name: 'Eth1/3'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ipv6 ospfv3 advertise prefix-list test1
# ipv6 ospfv3 passive
# !
# interface Eth1/2
# ipv6 ospfv3 network point-to-point
# !
# interface Eth1/3
# !
# sonic#


# Using deleted

# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ipv6 ospfv3 advertise prefix-list test1
# ipv6 ospfv3 area 2.2.2.2
# ipv6 ospfv3 bfd
# ipv6 ospfv3 bfd profile profile2
# ipv6 ospfv3 cost 30
# ipv6 ospfv3 dead-interval 40
# ipv6 ospfv3 hello-interval 10
# ipv6 ospfv3 mtu-ignore
# ipv6 ospfv3 network point-to-point
# ipv6 ospfv3 priority 20
# ipv6 ospfv3 passive
# !
# interface Eth1/2
# ipv6 ospfv3 bfd
# ipv6 ospfv3 network point-to-point
# !
# interface Eth1/3
# ipv6 ospfv3 bfd
# ipv6 ospfv3 network point-to-point
# ipv6 ospfv3 area 3.3.3.3
# !
# sonic#

- name: Delete the specified OSPFv3_interface configurations
  sonic_ospfv3_interfaces:
    config:
      - name: 'Eth1/1'
      - name: 'Eth1/2'
        bfd:
          enable: true
      - name: 'Eth1/3'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# !
# interface Eth1/2
# ipv6 ospfv3 network point-to-point
# !
# interface Eth1/3
# !
# sonic#


# Using merged

# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# !
# interface Eth1/2
# !
# interface Eth1/3
# !
# sonic#

- name: Add the OSPFv3_interface configurations
  sonic_ospfv3_interfaces:
    config:
      - name: 'Eth1/1'
        advertise: 'test1'
        area_id: '2.2.2.2'
        cost: 20
        passive: true
        priority: 20
        hello_interval: 10
        dead_interval: 40
        mtu_ignore: true
        hello_multiplier: 5
        bfd:
          enable: true
          bfd_profile: 'profile1'
        network: broadcast
      - name: 'Eth1/3'
        area_id: '3.3.3.3'
        hello_multiplier: 5
        bfd:
          enable: true
        network: point_to_point
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ipv6 ospfv3 advertise prefix-list test1
# ipv6 ospfv3 area 2.2.2.2
# ipv6 ospfv3 bfd
# ipv6 ospfv3 bfd profile profile1
# ipv6 ospfv3 cost 20
# ipv6 ospfv3 dead-interval 40
# ipv6 ospfv3 hello-interval 10
# ipv6 ospfv3 mtu-ignore
# ipv6 ospfv3 network broadcast
# ipv6 ospfv3 passive
# ipv6 ospfv3 priority 20
# !
# interface Eth1/2
# !
# interface Eth1/3
# ipv6 ospfv3 bfd
# ipv6 ospfv3 network point-to-point
# ipv6 ospfv3 area 3.3.3.3
# !
# sonic#

# Using merged

# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ipv6 ospfv3 advertise prefix-list test1
# ipv6 ospfv3 area 2.2.2.2
# ipv6 ospfv3 bfd
# ipv6 ospfv3 bfd profile profile1
# ipv6 ospfv3 cost 20
# ipv6 ospfv3 dead-interval 40
# ipv6 ospfv3 hello-interval 10
# ipv6 ospfv3 mtu-ignore
# ipv6 ospfv3 network broadcast
# ipv6 ospfv3 priority 20
# !
# interface Eth1/2
# !
# interface Eth1/3
# ipv6 ospfv3 bfd
# ipv6 ospfv3 network point-to-point
# ipv6 ospfv3 area 3.3.3.3
# !
# sonic#

- name: Add the OSPFv3_interface configurations
  sonic_ospfv3_interfaces:
    config:
      - name: 'Eth1/1'
        area_id: '2.2.2.2'
        cost: 30
        passive: true
        priority: 20
        hello_interval: 10
        dead_interval: 40
        mtu_ignore: true
        bfd:
          enable: true
          bfd_profile: 'profile2'
        network: point_to_point
      - name: 'Eth1/2'
        bfd:
          enable: true
        network: point_to_point
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ipv6 ospfv3 advertise prefix-list test1
# ipv6 ospfv3 area 2.2.2.2
# ipv6 ospfv3 bfd
# ipv6 ospfv3 bfd profile profile2
# ipv6 ospfv3 cost 30
# ipv6 ospfv3 dead-interval 40
# ipv6 ospfv3 hello-interval 10
# ipv6 ospfv3 mtu-ignore
# ipv6 ospfv3 network point-to-point
# ipv6 ospfv3 passive
# ipv6 ospfv3 priority 20
# !
# interface Eth1/2
# ipv6 ospfv3 bfd
# ipv6 ospfv3 network point-to-point
# !
# interface Eth1/3
# ipv6 ospfv3 bfd
# ipv6 ospfv3 network point-to-point
# ipv6 ospfv3 area 3.3.3.3
# !
# sonic#


# Using replaced

# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ipv6 ospfv3 advertise prefix-list test1
# ipv6 ospfv3 area 2.2.2.2
# ipv6 ospfv3 bfd
# ipv6 ospfv3 bfd profile profile1
# ipv6 ospfv3 cost 20
# ipv6 ospfv3 dead-interval 40
# ipv6 ospfv3 hello-interval 10
# ipv6 ospfv3 mtu-ignore
# ipv6 ospfv3 network broadcast
# ipv6 ospfv3 passive
# ipv6 ospfv3 priority 20
# !
# interface Eth1/2
# !
# interface Eth1/3
# ipv6 ospfv3 bfd
# ipv6 ospfv3 network point-to-point
# ipv6 ospfv3 area 3.3.3.3
# !
# sonic#


- name: Replace the OSPFv3_interface configurations
  sonic_ospfv3_interfaces:
    config:
      - name: 'Eth1/3'
        area_id: '2.2.2.2'
        cost: 30
        passive: true
        priority: 20
        hello_interval: 10
        dead_interval: 40
        mtu_ignore: true
        bfd:
          enable: true
          bfd_profile: 'profile2'
        network: broadcast
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ipv6 ospfv3 advertise prefix-list test1
# ipv6 ospfv3 area 2.2.2.2
# ipv6 ospfv3 bfd
# ipv6 ospfv3 bfd profile profile1
# ipv6 ospfv3 cost 20
# ipv6 ospfv3 dead-interval 40
# ipv6 ospfv3 hello-interval 10
# ipv6 ospfv3 mtu-ignore
# ipv6 ospfv3 network broadcast
# ipv6 ospfv3 passive
# ipv6 ospfv3 priority 20
# !
# interface Eth1/2
# !
# interface Eth1/3
# ipv6 ospfv3 area 2.2.2.2
# ipv6 ospfv3 bfd
# ipv6 ospfv3 bfd profile profile2
# ipv6 ospfv3 cost 30
# ipv6 ospfv3 dead-interval 40
# ipv6 ospfv3 hello-interval 10
# ipv6 ospfv3 mtu-ignore
# ipv6 ospfv3 network broadcast
# ipv6 ospfv3 passive
# ipv6 ospfv3 priority 20
# !
# sonic#


# Using overridden

# Before state:
# -------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# ipv6 ospfv3 area 2.2.2.2
# ipv6 ospfv3 bfd
# ipv6 ospfv3 bfd profile profile1
# ipv6 ospfv3 cost 20
# ipv6 ospfv3 dead-interval 40
# ipv6 ospfv3 hello-interval 10
# ipv6 ospfv3 mtu-ignore
# ipv6 ospfv3 network broadcast
# ipv6 ospfv3 priority 20
# !
# interface Eth1/2
# !
# interface Eth1/3
# ipv6 ospfv3 bfd
# ipv6 ospfv3 network point-to-point
# ipv6 ospfv3 area 3.3.3.3
# !
# sonic#

- name: Override the OSPFv3_interface configurations
  sonic_ospfv3_interfaces:
    config:
      - name: 'Eth1/3'
        advertise: 'test1'
        area_id: '2.2.2.2'
        cost: 30
        passive: true
        priority: 20
        hello_interval: 10
        dead_interval: 40
        mtu_ignore: true
        bfd:
          enable: true
          bfd_profile: 'profile2'
        network: broadcast
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration interface
# !
# interface Eth1/1
# !
# interface Eth1/2
# !
# interface Eth1/3
# ipv6 ospfv3 advertise prefix-list test1
# ipv6 ospfv3 area 2.2.2.2
# ipv6 ospfv3 bfd
# ipv6 ospfv3 bfd profile profile2
# ipv6 ospfv3 cost 30
# ipv6 ospfv3 dead-interval 40
# ipv6 ospfv3 hello-interval 10
# ipv6 ospfv3 mtu-ignore
# ipv6 ospfv3 network broadcast
# ipv6 ospfv3 passive
# ipv6 ospfv3 priority 20
# !
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
  description: The configuration resulting from  module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after(generated):
  description: The generated(calculated) configuration that would be applied by module invocation.
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ospfv3_interfaces.ospfv3_interfaces import Ospfv3_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ospfv3_interfaces.ospfv3_interfaces import Ospfv3_interfaces


def main():
    """
    Main entry point for module execution
    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Ospfv3_interfacesArgs.argument_spec,
                           supports_check_mode=True)

    result = Ospfv3_interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
