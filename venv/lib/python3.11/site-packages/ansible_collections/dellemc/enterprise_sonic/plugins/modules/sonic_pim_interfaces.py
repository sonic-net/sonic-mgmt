#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_pim_interfaces
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_pim_interfaces
version_added: 2.5.0
notes:
  - Supports C(check_mode).
short_description: Manage interface-specific PIM configurations on SONiC
description:
  - This module provides configuration management of interface-specific
    PIM parameters for devices running SONiC.
  - BFD profiles need to be created earlier in the device.
author: 'Arun Saravanan Balachandran (@ArunSaravananBalachandran)'
options:
  config:
    description:
      - Specifies interface-specific PIM configurations.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Full name of the interface.
        type: str
        required: true
      sparse_mode:
        description:
          - Enable PIM sparse-mode.
        type: bool
      drpriority:
        description:
          - Specifies the Designated Router Priority.
          - The range is from 1 to 4294967295.
        type: int
      hello_interval:
        description:
          - Specifies the Hello interval in seconds.
          - The range is from 1 to 255.
        type: int
      bfd_enable:
        description:
          - Enable BFD support for PIM.
        type: bool
      bfd_profile:
        description:
          - Specifies the BFD profile to be enabled.
          - BFD support for PIM has to be enabled for configuring BFD profile.
        type: str
  state:
    description:
      - The state of the configuration after module completion.
      - C(merged) - Merges provided interface-specific PIM configuration with on-device configuration.
      - C(replaced) - Replaces on-device PIM configuration of the specified interfaces with provided configuration.
      - C(overridden) - Overrides all on-device interface-specific PIM configurations with the provided configuration.
      - C(deleted) - Deletes on-device interface-specific PIM configuration.
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
# sonic# show running-configuration interface Eth 1/1 | grep "ip pim"
#  ip pim sparse-mode
#  ip pim drpriority 10
#  ip pim hello 60
#  ip pim bfd
#  ip pim bfd profile profile_1
# sonic# show running-configuration interface Eth 1/2 | grep "ip pim"
#  ip pim hello 60
#  ip pim bfd
# sonic#

- name: Delete specified interface PIM configurations
  dellemc.enterprise_sonic.sonic_pim_interfaces:
    config:
      - name: 'Eth1/1'
        hello_interval: 60
        bfd_profile: profile_1
      - name: 'Eth1/2'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface Eth 1/1 | grep "ip pim"
#  ip pim sparse-mode
#  ip pim drpriority 10
#  ip pim bfd
# sonic# show running-configuration interface Eth 1/2 | grep "ip pim"
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface Eth 1/1 | grep "ip pim"
#  ip pim sparse-mode
#  ip pim drpriority 10
#  ip pim hello 60
#  ip pim bfd
#  ip pim bfd profile profile_1
# sonic# show running-configuration interface Eth 1/2 | grep "ip pim"
#  ip pim hello 60
#  ip pim bfd
# sonic#

- name: Delete all interface-specific PIM configurations
  dellemc.enterprise_sonic.sonic_pim_interfaces:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration interface Eth 1/1 | grep "ip pim"
# sonic# show running-configuration interface Eth 1/2 | grep "ip pim"
# sonic#


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface Eth 1/1 | grep "ip pim"
#  ip pim sparse-mode
#  ip pim hello 45
# sonic# show running-configuration interface Eth 1/2 | grep "ip pim"
# sonic#

- name: Merge provided interface PIM configurations
  dellemc.enterprise_sonic.sonic_pim_interfaces:
    config:
      - name: 'Eth1/1'
        drpriority: 10
        hello_interval: 60
        bfd_enable: true
        bfd_profile: profile_1
      - name: 'Eth1/2'
        hello_interval: 60
        bfd_enable: true
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration interface Eth 1/1 | grep "ip pim"
#  ip pim sparse-mode
#  ip pim drpriority 10
#  ip pim hello 60
#  ip pim bfd
#  ip pim bfd profile profile_1
# sonic# show running-configuration interface Eth 1/2 | grep "ip pim"
#  ip pim hello 60
#  ip pim bfd
# sonic#


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface Eth 1/1 | grep "ip pim"
#  ip pim sparse-mode
#  ip pim drpriority 10
#  ip pim hello 45
#  ip pim bfd
#  ip pim bfd profile profile_1
# sonic# show running-configuration interface Eth 1/2 | grep "ip pim"
#  ip pim hello 60
#  ip pim bfd
# sonic#

- name: Replace PIM configurations for specified interfaces
  dellemc.enterprise_sonic.sonic_pim_interfaces:
    config:
      - name: 'Eth1/1'
        hello_interval: 60
        bfd_enable: true
        bfd_profile: profile_1
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration interface Eth 1/1 | grep "ip pim"
#  ip pim hello 60
#  ip pim bfd
#  ip pim bfd profile profile_1
# sonic# show running-configuration interface Eth 1/2 | grep "ip pim"
#  ip pim hello 60
#  ip pim bfd
# sonic#


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration interface Eth 1/1 | grep "ip pim"
#  ip pim sparse-mode
#  ip pim drpriority 10
#  ip pim hello 45
#  ip pim bfd
#  ip pim bfd profile profile_1
# sonic# show running-configuration interface Eth 1/2 | grep "ip pim"
#  ip pim hello 60
#  ip pim bfd
# sonic#

- name: Override interface-specific PIM configurations
  dellemc.enterprise_sonic.sonic_pim_interfaces:
    config:
      - name: 'Eth1/1'
        hello_interval: 60
        bfd_enable: true
        bfd_profile: profile_1
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration interface Eth 1/1 | grep "ip pim"
#  ip pim hello 60
#  ip pim bfd
#  ip pim bfd profile profile_1
# sonic# show running-configuration interface Eth 1/2 | grep "ip pim"
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.pim_interfaces.pim_interfaces import Pim_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.pim_interfaces.pim_interfaces import Pim_interfaces


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Pim_interfacesArgs.argument_spec,
                           supports_check_mode=True)

    result = Pim_interfaces(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
