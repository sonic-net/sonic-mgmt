#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_mac
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_mac
version_added: "2.1.0"
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Manage MAC configuration on SONiC
description:
  - This module provides configuration management of MAC for devices running SONiC
author: "S. Talabi (@stalabi1)"
options:
  config:
    description:
      - A list of MAC configurations.
    type: list
    elements: dict
    suboptions:
      vrf_name:
        description:
          - Specifies the VRF name.
        type: str
        default: 'default'
      mac:
        description:
          - Configuration attributes for MAC.
        type: dict
        suboptions:
          aging_time:
            description:
              - Time in seconds of inactivity before the MAC entry is timed out.
            type: int
            default: 600
          dampening_interval:
            description:
              - Interval for which mac movements are observed before disabling MAC learning on a port.
            type: int
            default: 5
          dampening_threshold:
            description:
              - Number of MAC movements allowed per second before disabling MAC learning on a port.
            type: int
            default: 5
          mac_table_entries:
            description:
              - Configuration attributes for MAC table entries.
            type: list
            elements: dict
            suboptions:
              mac_address:
                description:
                  - MAC address for the dynamic or static MAC table entry.
                type: str
                required: True
              vlan_id:
                description:
                  - ID number of VLAN on which the MAC address is present.
                type: int
                required: True
              interface:
                description:
                  - Specifies the interface for the MAC table entry.
                type: str
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
# sonic# show mac dampening
# MAC Move Dampening Threshold : 5
# MAC Move Dampening Interval  : 5
# sonic# show running-configuration | grep mac
# (No mac configuration pressent)

- name: Merge MAC configurations
  dellemc.enterprise_sonic.sonic_mac:
  config:
    - vrf_name: 'default'
      mac:
        aging_time: 50
        dampening_interval: 20
        dampening_threshold: 30
        mac_table_entries:
          - mac_address: '00:00:5e:00:53:af'
            vlan_id: 1
            interface: 'Ethernet20'
          - mac_address: '00:33:33:33:33:33'
            vlan_id: 2
            interface: 'Ethernet24'
          - mac_address: '00:00:4e:00:24:af'
            vlan_id: 3
            interface: 'Ethernet28'
  state: merged

# After state:
# ------------
#
# sonic# show mac dampening
# MAC Move Dampening Threshold : 30
# MAC Move Dampening Interval  : 20
# sonic# show running-configuration | grep mac
# mac address-table 00:00:5e:00:53:af Vlan1 Ethernet20
# mac address-table 00:33:33:33:33:33 Vlan2 Ethernet24
# mac address-table 00:00:4e:00:24:af Vlan3 Ethernet28
# mac address-table aging-time 50
#
#
# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show mac dampening
# MAC Move Dampening Threshold : 30
# MAC Move Dampening Interval  : 20
# sonic# show running-configuration | grep mac
# mac address-table 00:00:5e:00:53:af Vlan1 Ethernet20
# mac address-table 00:33:33:33:33:33 Vlan2 Ethernet24
# mac address-table 00:00:4e:00:24:af Vlan3 Ethernet28
# mac address-table aging-time 50

- name: Replace MAC configurations
  dellemc.enterprise_sonic.sonic_mac:
  config:
    - vrf_name: 'default'
      mac:
        aging_time: 45
        dampening_interval: 30
        dampening_threshold: 60
        mac_table_entries:
          - mac_address: '00:00:5e:00:53:af'
            vlan_id: 3
            interface: 'Ethernet24'
          - mac_address: '00:44:44:44:44:44'
            vlan_id: 2
            interface: 'Ethernet20'
  state: replaced

# sonic# show mac dampening
# MAC Move Dampening Threshold : 60
# MAC Move Dampening Interval  : 30
# sonic# show running-configuration | grep mac
# mac address-table 00:00:5e:00:53:af Vlan3 Ethernet24
# mac address-table 00:33:33:33:33:33 Vlan2 Ethernet24
# mac address-table 00:00:4e:00:24:af Vlan3 Ethernet28
# mac address-table 00:44:44:44:44:44 Vlan2 Ethernet20
# mac address-table aging-time 45
#
#
# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show mac dampening
# MAC Move Dampening Threshold : 60
# MAC Move Dampening Interval  : 30
# sonic# show running-configuration | grep mac
# mac address-table 00:00:5e:00:53:af Vlan3 Ethernet24
# mac address-table 00:33:33:33:33:33 Vlan2 Ethernet24
# mac address-table 00:00:4e:00:24:af Vlan3 Ethernet28
# mac address-table 00:44:44:44:44:44 Vlan2 Ethernet20
# mac address-table aging-time 45

- name: Override MAC cofigurations
  dellemc.enterprise_sonic.sonic_mac:
  config:
    - vrf_name: 'default'
      mac:
        aging_time: 10
        dampening_interval: 20
        dampening_threshold: 30
        mac_table_entries:
          - mac_address: '00:11:11:11:11:11'
            vlan_id: 1
            interface: 'Ethernet20'
          - mac_address: '00:22:22:22:22:22'
            vlan_id: 2
            interface: 'Ethernet24'
  state: overridden

# After state:
# ------------
#
# sonic# show mac dampening
# MAC Move Dampening Threshold : 30
# MAC Move Dampening Interval  : 20
# sonic# show running-configuration | grep mac
# mac address-table 00:11:11:11:11:11 Vlan1 Ethernet20
# mac address-table 00:22:22:22:22:22 Vlan2 Ethernet24
# mac address-table aging-time 10
#
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show mac dampening
# MAC Move Dampening Threshold : 30
# MAC Move Dampening Interval  : 20
# sonic# show running-configuration | grep mac
# mac address-table 00:11:11:11:11:11 Vlan1 Ethernet20
# mac address-table 00:22:22:22:22:22 Vlan2 Ethernet24
# mac address-table aging-time 10

- name: Delete MAC cofigurations
  dellemc.enterprise_sonic.sonic_mac:
  config:
    - vrf_name: 'default'
      mac:
        aging_time: 10
        dampening_interval: 20
        dampening_threshold: 30
        mac_table_entries:
          - mac_address: '00:11:11:11:11:11'
            vlan_id: 1
            interface: 'Ethernet20'
          - mac_address: '00:22:22:22:22:22'
            vlan_id: 2
            interface: 'Ethernet24'
  state: deleted

# After state:
# ------------
#
# sonic# show mac dampening
# MAC Move Dampening Threshold : 5
# MAC Move Dampening Interval  : 5
# sonic# show running-configuration | grep mac
# (No mac configuration present)
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.mac.mac import MacArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.mac.mac import Mac


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=MacArgs.argument_spec,
                           supports_check_mode=True)

    result = Mac(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
