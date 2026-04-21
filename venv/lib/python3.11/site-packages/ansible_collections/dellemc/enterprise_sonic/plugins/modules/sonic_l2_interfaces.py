#!/usr/bin/python
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_l2_interfaces
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_l2_interfaces
version_added: 1.0.0
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Configure interface-to-VLAN association that is based on access or trunk mode
description: Manages Layer 2 interface attributes of Enterprise SONiC Distribution by Dell Technologies.
author: Niraimadaiselvam M(@niraimadaiselvamm)
options:
  config:
    description: A list of Layer 2 interface configurations.
    type: list
    elements: dict
    suboptions:
      name:
        type: str
        description: Full name of the interface, for example, 'Eth1/26'.
        required: true
      trunk:
        type: dict
        description: Configures trunking parameters on an interface.
        suboptions:
          allowed_vlans:
            description: Specifies a list of allowed trunk mode VLANs and VLAN ranges for the interface.
            type: list
            elements: dict
            suboptions:
              vlan:
                type: str
                description: Configures the specified trunk mode VLAN or VLAN range.
      access:
        type: dict
        description: Configures access mode characteristics of the interface.
        suboptions:
          vlan:
            type: int
            description: Configures the specified VLAN in access mode.
  state:
    type: str
    description: The state that the configuration should be left in.
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
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 10         Inactive    A  Eth1/3
# 11         Inactive    T  Eth1/3
# 12         Inactive    A  Eth1/4
# 13         Inactive    T  Eth1/4
# 14         Inactive    A  Eth1/5
# 15         Inactive    T  Eth1/5
#
- name: Configures switch port of interfaces
  dellemc.enterprise_sonic.sonic_l2_interfaces:
    config:
      - name: Eth1/3
      - name: Eth1/4
    state: deleted
#
# After state:
# ------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 10         Inactive
# 11         Inactive
# 12         Inactive
# 13         Inactive
# 14         Inactive    A  Eth1/5
# 15         Inactive    T  Eth1/5
#
#
# Using "deleted" state
#
# Before state:
# -------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 10         Inactive    A  Eth1/3
# 11         Inactive    T  Eth1/3
# 12         Inactive    A  Eth1/4
# 13         Inactive    T  Eth1/4
# 14         Inactive    A  Eth1/5
# 15         Inactive    T  Eth1/5
#
- name: Configures switch port of interfaces
  dellemc.enterprise_sonic.sonic_l2_interfaces:
    config:
    state: deleted
#
# After state:
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 10         Inactive
# 11         Inactive
# 12         Inactive
# 13         Inactive
# 14         Inactive
# 15         Inactive
#
#
# Using "deleted" state
#
# Before state:
# -------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 11         Inactive    T  Ethernet12
# 12         Inactive    A  Ethernet12
# 13         Inactive    T  Ethernet12
# 14         Inactive    T  Ethernet12
# 15         Inactive    T  Ethernet12
# 16         Inactive    T  Ethernet12

- name: Delete the access vlan and a range of trunk vlans for an interface
  sonic_l2_interfaces:
    config:
      - name: Ethernet12
        access:
          vlan: 12
        trunk:
          allowed_vlans:
            - vlan: 13-16
    state: deleted

# After state:
# ------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 11         Inactive    T  Ethernet12
# 12         Inactive
# 13         Inactive
# 14         Inactive
# 15         Inactive
# 16         Inactive
#
#
#
# Using "merged" state
#
# Before state:
# -------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 10         Inactive
# 11         Inactive    T  Eth1/7
# 12         Inactive    T  Eth1/7
#
- name: Configures an access vlan for an interface
  dellemc.enterprise_sonic.sonic_l2_interfaces:
    config:
      - name: Eth1/3
        access:
          vlan: 10
    state: merged
#
# After state:
# ------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 10         Inactive    A  Eth1/3
# 11         Inactive    T  Eth1/7
# 12         Inactive    T  Eth1/7
#
#
# Using "merged" state
#
# Before state:
# -------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 10         Inactive    A  Eth1/3
# 12         Inactive
# 13         Inactive
# 14         Inactive
# 15         Inactive
# 16         Inactive
# 18         Inactive
#
- name: Modify the access vlan, add a range of trunk vlans and a single trunk vlan for an interface
  dellemc.enterprise_sonic.sonic_l2_interfaces:
    config:
      - name: Eth1/3
        access:
          vlan: 12
        trunk:
          allowed_vlans:
            - vlan: 13-16
            - vlan: 18
    state: merged
#
# After state:
# ------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 10         Inactive
# 12         Inactive    A  Eth1/3
# 13         Inactive    T  Eth1/3
# 14         Inactive    T  Eth1/3
# 15         Inactive    T  Eth1/3
# 16         Inactive    T  Eth1/3
# 18         Inactive    T  Eth1/3
#
#
# Using "merged" state
#
# Before state:
# -------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 10         Inactive
# 11         Inactive
# 12         Inactive    A  Eth1/4
# 13         Inactive    T  Eth1/4
# 14         Inactive    A  Eth1/5
# 15         Inactive    T  Eth1/5
#
- name: Configures switch port of interfaces
  dellemc.enterprise_sonic.sonic_l2_interfaces:
    config:
      - name: Eth1/3
        access:
          vlan: 12
        trunk:
          allowed_vlans:
            - vlan: 13
            - vlan: 14
    state: merged
#
# After state:
# ------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 10         Inactive
# 11         Inactive
# 12         Inactive    A  Eth1/3
#                        A  Eth1/4
# 13         Inactive    T  Eth1/3
#                        T  Eth1/4
# 14         Inactive    A  Eth1/3
#                        A  Eth1/5
# 15         Inactive    T  Eth1/5
#
#
# Using "replaced" state
#
# Before state:
# -------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 10         Inactive    A  Ethernet12
#                        A  Ethernet13
# 11         Inactive    T  Ethernet12
#                        T  Ethernet13

- name: Replace access vlan and trunk vlans for specified interfaces
  sonic_l2_interfaces:
    config:
      - name: Ethernet12
        access:
          vlan: 12
        trunk:
          allowed_vlans:
            - vlan: 13-14
      - name: Ethernet14
        access:
          vlan: 10
        trunk:
          allowed_vlans:
            - vlan: 11
            - vlan: 13-14
    state: replaced

# After state:
# ------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 10         Inactive    A  Ethernet13
#                        A  Ethernet14
# 11         Inactive    T  Ethernet13
#                        T  Ethernet14
# 12         Inactive    A  Ethernet12
# 13         Inactive    T  Ethernet12
#                        T  Ethernet14
# 14         Inactive    T  Ethernet12
#                        T  Ethernet14
#
#
# Using "overridden" state
#
# Before state:
# -------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 10         Inactive    A  Ethernet11
# 11         Inactive    T  Ethernet11
# 12         Inactive    A  Ethernet12
# 13         Inactive    T  Ethernet12

- name: Override L2 interfaces configuration in device with provided configuration
  sonic_l2_interfaces:
    config:
      - name: Ethernet13
        access:
          vlan: 12
        trunk:
          allowed_vlans:
            - vlan: 13-14
    state: overridden

# After state:
# ------------
#
# do show Vlan
# Q: A - Access (Untagged), T - Tagged
# NUM        Status      Q Ports
# 12         Inactive    A  Ethernet13
# 13         Inactive    T  Ethernet13
# 14         Inactive    T  Ethernet13
#
#
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned always in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned is always in the same format
    as the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.l2_interfaces.l2_interfaces import L2_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.l2_interfaces.l2_interfaces import L2_interfaces


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=L2_interfacesArgs.argument_spec,
                           supports_check_mode=True)

    result = L2_interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
