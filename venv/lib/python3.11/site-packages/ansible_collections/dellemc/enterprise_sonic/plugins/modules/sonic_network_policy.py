#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_network_policy
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_network_policy
version_added: 3.1.0
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Manage network policy configuration on SONiC
description:
  - This module provides configuration management of network policy for devices running SONiC
author: S. Talabi (@stalabi1)
options:
  config:
    description:
      - List of network policy configurations
    type: list
    elements: dict
    suboptions:
      number:
        description:
          - Network policy number, range 1-128
        type: int
        required: true
      applications:
        description:
          - List of network policy application configurations
          - I(dot1p) and I(vlan_id) are mutually exclusive
          - I(dot1p) cannot be configured when I(untagged=True)
        type: list
        elements: dict
        suboptions:
          app_type:
            description:
              - Media type of the application
            type: str
            choices: ['voice', 'voice-signaling']
            required: true
          dot1p:
            description:
              - Enable dot1p priority tagging
            type: str
            choices: ['enabled']
          vlan_id:
            description:
              - VLAN identifier, range 1-4094
            type: int
          untagged:
            description:
              - Indicates that the application is using an untagged VLAN
            type: bool
          priority:
            description:
              - Priority of VLAN, range 0-7
            type: int
          dscp:
            description:
              - DSCP value of VLAN, range 0-63
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
# sonic# show running-configuration
# (No network policy configuration present)

- name: Merge network policy configuration
  dellemc.enterprise_sonic.sonic_network_policy:
    config:
      - number: 1
        applications:
          - app_type: voice
            vlan_id: 2
            priority: 1
            dscp: 1
          - app_type: voice-signaling
            dot1p: enabled
            dscp: 50
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration
# !
# network-policy profile 1
#  voice vlan 2 cos 1 dscp 1
#  voice-signaling vlan dot1p dscp 50
# !


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration
# !
# network-policy profile 1
#  voice vlan 2 cos 1 dscp 1
#  voice-signaling vlan 3 untagged dscp 50
# !
# network-policy profile 2
#  voice vlan 100 cos 7 dscp 12
#  voice-signaling vlan 400 cos 7 dscp 45
# !

- name: Replace network policy configuration
  dellemc.enterprise_sonic.sonic_network_policy:
    config:
      - number: 1
        applications:
          - app_type: voice
            vlan_id: 1
            untagged: false
            priority: 0
            dscp: 0
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration
# !
# network-policy profile 1
#  voice vlan 1 cos 0 dscp 0
# !
# network-policy profile 2
#  voice vlan 100 cos 7 dscp 12
#  voice-signaling vlan 400 cos 7 dscp 45
# !


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration
# !
# network-policy profile 1
#  voice vlan 2 cos 1 dscp 1
#  voice-signaling vlan 3 untagged dscp 50
# !
# network-policy profile 2
#  voice vlan 100 cos 7 dscp 12
#  voice-signaling vlan 400 cos 7 dscp 45
# !

- name: Override network policy configuration
  dellemc.enterprise_sonic.sonic_network_policy:
    config:
      - number: 1
        applications:
          - app_type: voice
            vlan_id: 1
            untagged: false
            priority: 0
            dscp: 0
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration
# !
# network-policy profile 1
#  voice vlan 1 cos 0 dscp 0
# !


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration
# !
# network-policy profile 1
#  voice vlan 2 cos 1 dscp 1
#  voice-signaling vlan 3 untagged dscp 50
# !
# network-policy profile 2
#  voice vlan 100 cos 7 dscp 12
#  voice-signaling vlan 400 cos 7 dscp 45
# !
# network-policy profile 3
#  voice-signaling vlan 80 cos 6 dscp 32
# !

- name: Delete network policy configuration
  dellemc.enterprise_sonic.sonic_network_policy:
    config:
      - number: 1
        applications:
          - app_type: voice
            dscp: 1
      - number: 2
        applications:
          - app_type: voice
      - number: 3
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration
# !
# network-policy profile 1
#  voice vlan 2 cos 1
#  voice-signaling vlan 3 untagged dscp 50
# !
# network-policy profile 2
#  voice-signaling vlan 400 cos 7 dscp 45
# !


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration
# !
# network-policy profile 1
#  voice vlan 2 cos 1 dscp 1
#  voice-signaling vlan 3 untagged dscp 50
# !
# network-policy profile 2
#  voice vlan 100 cos 7 dscp 12
#  voice-signaling vlan 400 cos 7 dscp 45
# !
# network-policy profile 3
#  voice-signaling vlan 80 cos 6 dscp 32
# !

- name: Delete all network policy configuration
  dellemc.enterprise_sonic.sonic_network_policy:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration
# (No network policy configuration present)
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
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.network_policy.network_policy import Network_policyArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.network_policy.network_policy import Network_policy


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Network_policyArgs.argument_spec,
                           supports_check_mode=True)

    result = Network_policy(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
