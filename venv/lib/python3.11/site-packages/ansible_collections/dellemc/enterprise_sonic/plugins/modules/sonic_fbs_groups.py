#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_fbs_groups
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_fbs_groups
version_added: 3.1.0
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies.
  - Supports C(check_mode).
short_description: Manage flow based services (FBS) groups configuration on SONiC
description:
  - This module provides configuration management of FBS groups for devices running SONiC
author: S. Talabi (@stalabi1)
options:
  config:
    description:
      - FBS groups configuration
    type: dict
    suboptions:
      next_hop_groups:
        description:
          - Next-hop groups configuration
        type: list
        elements: dict
        suboptions:
          group_name:
            description:
              - Name of next-hop group
            type: str
            required: true
          group_description:
            description:
              - Description of next-hop group
            type: str
          group_type:
            description:
              - Type of next-hop group
              - The group type is required for merged, replaced, and overridden states.
            type: str
            choices: ['ipv4', 'ipv6']
          threshold_type:
            description:
              - Type of threshold
              - Deletion of I(threshold_type) will delete I(threshold_up) and I(threshold_down).
            type: str
            choices: ['count', 'percentage']
          threshold_up:
            description:
              - Specifies the minimum threshold value for a next-hop group to be considered forwardable
              - Range 1-128
              - I(threshold_type) must be configured.
            type: int
          threshold_down:
            description:
              - Specifies the threshold value equal to or below for a next-hop to not be considered forwardable
              - Range 0-127
              - I(threshold_type) must be configured.
            type: int
          next_hops:
            description:
              - Next-hops configuration for forwarding
            type: list
            elements: dict
            suboptions:
              entry_id:
                description:
                  - Entry ID, range 1-65535
                type: int
                required: true
              ip_address:
                description:
                  - Forwarding IP address
                  - The IP address is required for merged, replaced, and overridden states.
                type: str
              vrf:
                description:
                  - Forwarding network instance
                type: str
              next_hop_type:
                description:
                  - Type of next-hop
                type: str
                choices: ['non_recursive', 'overlay', 'recursive']
      replication_groups:
        description:
          - Replication groups configuration
        type: list
        elements: dict
        suboptions:
          group_name:
            description:
              - Name of replication group
            type: str
            required: true
          group_description:
            description:
              - Description of replication group
            type: str
          group_type:
            description:
              - Type of replication group
              - The group type is required for merged, replaced, and overridden states.
            type: str
            choices: ['ipv4', 'ipv6']
          next_hops:
            description:
              - Next-hops configuration for forwarding
            type: list
            elements: dict
            suboptions:
              entry_id:
                description:
                  - Entry ID, range 1-65535
                type: int
                required: true
              ip_address:
                description:
                  - Forwarding IP address
                  - The IP address is required for merged, replaced, and overridden states.
                type: str
              vrf:
                description:
                  - Forwarding network instance
                type: str
              next_hop_type:
                description:
                  - Type of next-hop
                type: str
                choices: ['non_recursive', 'overlay', 'recursive']
              single_copy:
                description:
                  - Enable/disable single path to create copy
                type: bool
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
# sonic# show running-configuration pbf next-hop-group
# (No 'pbf next-hop-group' configuration present)
# sonic# show running-configuration pbf replication-group
# (No 'pbf replication-group' configuration present)

- name: Merge FBS groups configuration
  dellemc.enterprise_sonic.sonic_fbs_groups:
    config:
      next_hop_groups:
        - group_name: hop1
          group_description: abc
          group_type: ipv4
          threshold_type: count
          threshold_up: 15
          threshold_down: 5
          next_hops:
            - entry_id: 1
              ip_address: 1.1.1.1
              vrf: VrfReg1
              next_hop_type: non_recursive
      replication_groups:
        - group_name: rep1
          group_description: xyz
          group_type: ipv6
          next_hops:
            - entry_id: 2
              ip_address: 1::1
              vrf: VrfReg2
              next_hop_type: overlay
              single_copy: true
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration pbf next-hop-group
# !
# pbf next-hop-group hop1 type ip
#   description abc
#   threshold type count up 15 down 5
#   entry 1 next-hop 1.1.1.1 vrf VrfReg1 non-recursive
# !
# sonic# show running-configuration pbf replication-group
# !
# pbf replication-group rep1 type ipv6
#   description xyz
#   entry 2 next-hop 1::1 vrf VrfReg2 overlay single-copy
# !


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration pbf next-hop-group
# !
# pbf next-hop-group hop1 type ip
#   description abc
#   threshold type count up 15 down 5
#   entry 1 next-hop 1.1.1.1 vrf VrfReg1 non-recursive
# !
# pbf next-hop-group hop2 type ipv6
#   description abc
#   entry 5 next-hop 3::3 vrf default non-recursive
# !
# sonic# show running-configuration pbf replication-group
# !
# pbf replication-group rep1 type ipv6
#   description xyz
#   entry 2 next-hop 1::1 vrf VrfReg2 overlay single-copy
# !

- name: Replace FBS groups configuration
  dellemc.enterprise_sonic.sonic_fbs_groups:
    config:
      next_hop_groups:
        - group_name: hop2
          group_description: xyz
          group_type: ipv4
          next_hops:
            - entry_id: 1
              ip_address: 1.1.1.1
              vrf: VrfReg1
              next_hop_type: recursive
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration pbf next-hop-group
# !
# pbf next-hop-group hop1 type ip
#   description abc
#   threshold type count up 15 down 5
#   entry 1 next-hop 1.1.1.1 vrf VrfReg1 non-recursive
# !
# pbf next-hop-group hop2 type ipv4
#   description xyz
#   entry 1 next-hop 1.1.1.1 vrf VrfReg1 recursive
# !
# sonic# show running-configuration pbf replication-group
# !
# pbf replication-group rep1 type ipv6
#   description xyz
#   entry 2 next-hop 1::1 vrf VrfReg2 overlay single-copy
# !


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration pbf next-hop-group
# !
# pbf next-hop-group hop1 type ip
#   description abc
#   entry 1 next-hop 1.1.1.1 vrf VrfReg1 non-recursive
# !
# sonic# show running-configuration pbf replication-group
# !
# pbf replication-group rep1 type ipv6
#   description xyz
#   entry 2 next-hop 1::1 vrf VrfReg2 overlay single-copy
# !

- name: Override FBS groups configuration
  dellemc.enterprise_sonic.sonic_fbs_groups:
    config:
      next_hop_groups:
        - group_name: hop1
          group_description: abc
          group_type: ipv4
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration pbf next-hop-group
# !
# pbf next-hop-group hop1 type ip
#   description abc
# !
# sonic# show running-configuration pbf replication-group
# (No 'pbf replication-group' configuration present)


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration pbf next-hop-group
# !
# pbf next-hop-group hop1 type ip
#   description abc
#   entry 1 next-hop 1.1.1.1 vrf VrfReg1 non-recursive
# !
# sonic# show running-configuration pbf replication-group
# !
# pbf replication-group rep1 type ipv6
#   description xyz
#   entry 2 next-hop 1::1 vrf VrfReg2 overlay single-copy
# !

- name: Delete FBS groups configuration
  dellemc.enterprise_sonic.sonic_fbs_groups:
    config:
      next_hop_groups:
        - group_name: hop1
          group_description: abc
      replication_groups:
        - group_name: rep1
          next_hops:
            - entry_id: 2
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration pbf next-hop-group
# !
# pbf next-hop-group hop1 type ip
#   entry 1 next-hop 1.1.1.1 vrf VrfReg1 non-recursive
# !
# sonic# show running-configuration pbf replication-group
# !
# pbf replication-group rep1 type ipv6
#   description xyz
# !


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration pbf next-hop-group
# !
# pbf next-hop-group hop1 type ip
#   entry 1 next-hop 1.1.1.1 vrf VrfReg1 non-recursive
# !
# sonic# show running-configuration pbf replication-group
# !
# pbf replication-group rep1 type ipv6
#   description xyz
# !

- name: Delete FBS groups configuration
  dellemc.enterprise_sonic.sonic_fbs_groups:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration pbf next-hop-group
# (No 'pbf next-hop-group' configuration present)
# sonic# show running-configuration pbf replication-group
# (No 'pbf replication-group' configuration present)
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: dict
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: dict
after(generated):
  description: The generated configuration from module invocation.
  returned: when C(check_mode)
  type: dict
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.fbs_groups.fbs_groups import Fbs_groupsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.fbs_groups.fbs_groups import Fbs_groups


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Fbs_groupsArgs.argument_spec,
                           supports_check_mode=True)

    result = Fbs_groups(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
