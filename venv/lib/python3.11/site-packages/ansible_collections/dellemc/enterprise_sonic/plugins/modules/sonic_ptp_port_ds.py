#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#############################################

"""
The module file for sonic_ptp_port_ds
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_ptp_port_ds
version_added: '3.1.0'
notes:
  - Supports C(check_mode).
short_description: Manage port specific PTP configurations on SONiC
description:
  - This module provides configuration management of port-specific
    PTP parameters for devices running SONiC.
author: 'Vidya Chidambaram (@vidyac86)'
options:
  config:
    description:
      - Specifies port-specific PTP configurations.
    type: list
    elements: dict
    suboptions:
      interface:
        description:
          - Specifies the name of the interface.
        required: true
        type: str
      role:
        description:
          - Specifies the role of interface.
        type: str
        choices: ['dynamic', 'master', 'slave']
      local_priority:
        description:
          - Specifies the local-priority attribute used for the profile G8275-1 and G8275-2.
          - The range is from 1 to 255.
        type: int
        default:
      unicast_table:
        description:
          - List of ip addresses to use for PTP master.
        type: list
        elements: str
  state:
    description:
      - The state of the configuration after module completion.
      - C(merged) - Merges provided interface-specific PTP configuration with on-device configuration.
      - C(replaced) - Replaces on-device PTP configuration of the specified interfaces with provided configuration.
      - C(overridden) - Overrides all on-device interface-specific PTP configurations with the provided configuration.
      - C(deleted) - Deletes on-device interface-specific PTP configuration.
    type: str
    choices:
      - merged
      - deleted
      - replaced
      - overridden
    default: merged
"""
EXAMPLES = """
# Using deleted
#
# Before State:
# -------------
#
# sonic# show running-configuration ptp | grep "ptp port"
# ptp port add Ethernet0 role slave local-priority 100
# ptp port add Ethernet4 role master local-priority 90
# ptp port master-table Ethernet0 add 1.1.1.1
# ptp port master-table Ethernet0 add 1.1.1.2
# sonic#

- name: Delete specified PTP port configurations
  dellemc.enterprise_sonic.sonic_ptp_port_ds:
    config:
      - interface: 'Ethernet4'
        role: 'master'
        local_priority: 90
      - interface: 'Ethernet0'
        role: 'slave'
        local_priority: 100
        unicast_table:
          - '1.1.1.1'
          - '1.1.1.2'
    state: deleted

# After State:
# ------------
#
# sonic# show running-configuration ptp
# ptp port add Ethernet4 role master local-priority 90
# sonic#


# Using deleted
#
# Before State:
# -------------
#
# sonic# show running-configuration ptp | grep "ptp port"
# ptp port add Ethernet0 role slave local-priority 100
# ptp port add Ethernet4 role master local-priority 90
# ptp port master-table Ethernet0 add 1.1.1.1
# ptp port master-table Ethernet0 add 1.1.1.2
# sonic#

- name: Delete all PTP configurations in the specified port
  dellemc.enterprise_sonic.sonic_ptp_port_ds:
    config:
      - interface: 'Ethernet0'
    state: deleted

# After State:
# ------------
#
# sonic# show running-configuration ptp
# ptp port add Ethernet4 role master local-priority 90
# sonic#


# Using deleted
#
# Before State:
# -------------
#
# sonic# show running-configuration ptp | grep "ptp port"
# ptp port add Ethernet0 role slave local-priority 100
# ptp port add Ethernet4 role master local-priority 90
# ptp port master-table Ethernet0 add 1.1.1.1
# ptp port master-table Ethernet0 add 1.1.1.2
# sonic#

- name: Delete all PTP port configurations
  dellemc.enterprise_sonic.sonic_ptp_port_ds:
    config:
    state: deleted

# After State:
# ------------
#
# sonic# show running-configuration ptp
# sonic#

# Using merged
#
# Before State:
# -------------
#
# sonic# show running-configuration ptp | grep "ptp port"
# ptp port add Ethernet0
# sonic#

- name: Merge provided PTP port configurations
  dellemc.enterprise_sonic.sonic_ptp_port_ds:
    config:
      - interface: 'Ethernet0'
        role: 'slave'
        local_priority: 100
    state: merged

# After State:
# ------------
#
# sonic# show running-configuration ptp | grep "ptp port"
# ptp port add Ethernet0 role slave local-priority 100
# sonic#


# Using replaced
#
# Before State:
# -------------
#
# sonic# do show running-configuration | grep "ptp port"
# ptp port add Ethernet0 role master local-priority 10
# ptp port add Ethernet1 local-priority 100
# ptp port add Ethernet2 role slave
# ptp port master-table Ethernet1 add 1.1.1.1
# sonic#

- name: Replace PTP configurations for specified port
  dellemc.enterprise_sonic.sonic_ptp_port_ds:
    config:
      - interface: 'Ethernet0'
        role: 'slave'
        unicast_table:
          - '2.2.2.2'
    state: replaced

# After State:
# ------------
#
# sonic# do show running-configuration | grep "ptp port"
# ptp port add Ethernet0 role slave
# ptp port add Ethernet1 local-priority 100
# ptp port add Ethernet2 role slave
# ptp port master-table Ethernet0 add 2.2.2.2
# ptp port master-table Ethernet1 add 1.1.1.1
# sonic#


# Using overridden
#
# Before State:
# -------------
#
# sonic# show running-configuration ptp | grep "ptp port"
# ptp port add Ethernet0 role slave local-priority 100
# ptp port master-table Ethernet0 add 1.1.1.1
# sonic#

- name: Override device PTP port configuration with provided configuration
  dellemc.enterprise_sonic.sonic_ptp_port_ds:
    config:
      - interface: 'Ethernet4'
        role: 'master'
        local_priority: 90
    state: overridden

# After State:
# ------------
#
# sonic# show running-configuration ptp | grep "ptp port"
# ptp port add Ethernet4 role master local-priority 90
# sonic#
"""
RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
  type: dict
after:
  description: The resulting configuration model invocation.
  returned: when changed
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
  type: dict
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ptp_port_ds.ptp_port_ds import Ptp_port_dsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ptp_port_ds.ptp_port_ds import Ptp_port_ds


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Ptp_port_dsArgs.argument_spec,
                           supports_check_mode=True)

    result = Ptp_port_ds(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
