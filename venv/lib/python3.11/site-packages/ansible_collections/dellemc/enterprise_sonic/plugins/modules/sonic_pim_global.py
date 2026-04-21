#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_pim_global
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_pim_global
version_added: 2.5.0
notes:
  - Supports C(check_mode).
short_description: Manage global PIM configurations on SONiC
description:
  - This module provides configuration management of global PIM
    parameters for devices running SONiC.
  - VRF and prefix-list need to be created earlier in the device.
author: 'Arun Saravanan Balachandran (@ArunSaravananBalachandran)'
options:
  config:
    description:
      - Specifies global PIM configurations.
    type: list
    elements: dict
    suboptions:
      vrf_name:
        description:
          - Name of the VRF to which the PIM configurations belong.
        type: str
        default: 'default'
      join_prune_interval:
        description:
          - Specifies the PIM Join Prune Interval in seconds.
          - The range is from 60 to 600.
        type: int
      keepalive_timer:
        description:
          - Specifies the PIM Keepalive timer in seconds.
          - The range is from 31 to 60000.
        type: int
      ssm_prefix_list:
        description:
          - Specifies the SSM prefix-list.
        type: str
      ecmp_enable:
        description:
          - Enable PIM ECMP.
        type: bool
      ecmp_rebalance_enable:
        description:
          - Enable PIM ECMP rebalance.
          - ECMP has to be enabled for configuring ECMP rebalance.
        type: bool
  state:
    description:
      - The state of the configuration after module completion.
      - C(merged) - Merges provided global PIM configuration with on-device configuration.
      - C(replaced) - Replaces on-device PIM configuration of the specified VRFs with provided configuration.
      - C(overridden) - Overrides all on-device global PIM configurations with the provided configuration.
      - C(deleted) - Deletes on-device global PIM configuration.
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
# sonic# show running-configuration | grep "ip pim"
# ip pim vrf VrfReg1 join-prune-interval 60
# ip pim vrf VrfReg1 keep-alive-timer 180
# ip pim vrf VrfReg1 ssm prefix-list prefix-list-1
# ip pim vrf VrfReg2 ecmp
# ip pim vrf VrfReg2 ssm prefix-list prefix-list-2
# ip pim vrf default ecmp
# ip pim vrf default ecmp rebalance
# sonic#

- name: Delete specified global PIM configurations
  dellemc.enterprise_sonic.sonic_pim_global:
    config:
      - vrf_name: 'VrfReg1'
        join_prune_interval: 60
        keepalive_timer: 180
      - vrf_name: 'VrfReg2'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip pim"
# ip pim vrf VrfReg1 ssm prefix-list prefix-list-1
# ip pim vrf default ecmp
# ip pim vrf default ecmp rebalance
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep "ip pim"
# ip pim vrf VrfReg1 join-prune-interval 60
# ip pim vrf VrfReg1 keep-alive-timer 180
# ip pim vrf VrfReg1 ssm prefix-list prefix-list-1
# ip pim vrf VrfReg2 ecmp
# ip pim vrf VrfReg2 ssm prefix-list prefix-list-2
# ip pim vrf default ecmp
# ip pim vrf default ecmp rebalance
# sonic#

- name: Delete all global PIM configurations
  dellemc.enterprise_sonic.sonic_pim_global:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip pim"
# sonic#


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep "ip pim"
# ip pim vrf default join-prune-interval 120
# ip pim vrf default keep-alive-timer 360
# ip pim vrf default ssm prefix-list prefix-list-1
# sonic#

- name: Merge provided global PIM configurations
  dellemc.enterprise_sonic.sonic_pim_global:
    config:
      - vrf_name: 'default'
        ecmp_enable: true
        ecmp_rebalance_enable: true
        join_prune_interval: 60
        keepalive_timer: 180
        ssm_prefix_list: 'prefix-list-def'
      - vrf_name: 'VrfReg1'
        join_prune_interval: 60
        keepalive_timer: 180
      - vrf_name: 'VrfReg2'
        ssm_prefix_list: 'prefix-list-2'
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip pim"
# ip pim vrf VrfReg1 join-prune-interval 60
# ip pim vrf VrfReg1 keep-alive-timer 180
# ip pim vrf VrfReg2 ssm prefix-list prefix-list-2
# ip pim vrf default ecmp
# ip pim vrf default ecmp rebalance
# ip pim vrf default join-prune-interval 60
# ip pim vrf default keep-alive-timer 180
# ip pim vrf default ssm prefix-list prefix-list-def
# sonic#


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep "ip pim"
# ip pim vrf VrfReg1 join-prune-interval 60
# ip pim vrf VrfReg1 keep-alive-timer 180
# ip pim vrf VrfReg1 ssm prefix-list prefix-list-1
# ip pim vrf VrfReg2 ecmp
# ip pim vrf VrfReg2 ssm prefix-list prefix-list-2
# ip pim vrf default ecmp
# ip pim vrf default ecmp rebalance
# sonic#

- name: Replace global PIM configurations of specified VRFs
  dellemc.enterprise_sonic.sonic_pim_global:
    config:
      - vrf_name: 'default'
        ecmp_enable: true
      - vrf_name: 'VrfReg1'
        join_prune_interval: 120
        keepalive_timer: 360
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip pim"
# ip pim vrf VrfReg1 join-prune-interval 120
# ip pim vrf VrfReg1 keep-alive-timer 360
# ip pim vrf VrfReg2 ecmp
# ip pim vrf VrfReg2 ssm prefix-list prefix-list-2
# ip pim vrf default ecmp
# sonic#


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep "ip pim"
# ip pim vrf VrfReg1 join-prune-interval 60
# ip pim vrf VrfReg1 keep-alive-timer 180
# ip pim vrf VrfReg1 ssm prefix-list prefix-list-1
# ip pim vrf VrfReg2 ecmp
# ip pim vrf VrfReg2 ssm prefix-list prefix-list-2
# ip pim vrf default ecmp
# ip pim vrf default ecmp rebalance
# sonic#

- name: Override global PIM configurations
  dellemc.enterprise_sonic.sonic_pim_global:
    config:
      - vrf_name: 'default'
        ecmp_enable: true
      - vrf_name: 'VrfReg1'
        join_prune_interval: 120
        keepalive_timer: 360
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip pim"
# ip pim vrf VrfReg1 join-prune-interval 120
# ip pim vrf VrfReg1 keep-alive-timer 360
# ip pim vrf default ecmp
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
  description: The resulting configuration on module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     as the parameters above.
after(generated):
  description: The generated configuration on module invocation.
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.pim_global.pim_global import Pim_globalArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.pim_global.pim_global import Pim_global


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Pim_globalArgs.argument_spec,
                           supports_check_mode=True)

    result = Pim_global(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
