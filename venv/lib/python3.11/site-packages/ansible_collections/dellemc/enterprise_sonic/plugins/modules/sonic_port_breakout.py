#!/usr/bin/python
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_port_breakout
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_port_breakout
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
author: Niraimadaiselvam M (@niraimadaiselvamm)
short_description: Configure port breakout settings on physical interfaces
description:
  - This module provides configuration management of port breakout parameters on devices running Enterprise SONiC.
options:
  config:
    description:
      - Specifies the port breakout related configuration.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Specifies the name of the port breakout.
        type: str
        required: true
      mode:
        description:
          - Specifies the mode of the port breakout.
        type: str
        choices:
          - 1x10G
          - 1x25G
          - 1x40G
          - 1x50G
          - 1x100G
          - 1x200G
          - 1x400G
          - 1x800G
          - 2x10G
          - 2x25G
          - 2x40G
          - 2x50G
          - 2x100G
          - 2x200G
          - 2x400G
          - 4x10G
          - 4x25G
          - 4x50G
          - 4x100G
          - 4x200G
          - 8x10G
          - 8x25G
          - 8x50G
          - 8x100G
  state:
    description:
      - Specifies the operation to be performed on the port breakout configured on the device.
      - In case of merged, the input mode configuration will be merged with the existing port breakout configuration on the device.
      - In case of deleted, the existing port breakout mode configuration will be removed from the device.
      - In case of replaced, on-device port breakout configuration of the specified interfaces is replaced with provided configuration.
      - In case of overridden, all on-device port breakout configurations are overridden with the provided configuration.
    default: merged
    choices: ['merged', 'deleted', 'replaced', 'overridden']
    type: str
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show interface breakout
# -----------------------------------------------
# Port  Breakout Mode  Status        Interfaces
# -----------------------------------------------
# 1/1   4x10G          Completed     Eth1/1/1
#                                    Eth1/1/2
#                                    Eth1/1/3
#                                    Eth1/1/4
# 1/11  1x100G         Completed     Eth1/11/1
#

- name: Delete interface port breakout configuration
  dellemc.enterprise_sonic.sonic_port_breakout:
    config:
      - name: 1/11
        mode: 1x100G
    state: deleted

# After state:
# ------------
#
# sonic# show interface breakout
# -----------------------------------------------
# Port  Breakout Mode  Status        Interfaces
# -----------------------------------------------
# 1/1   4x10G          Completed     Eth1/1/1
#                                    Eth1/1/2
#                                    Eth1/1/3
#                                    Eth1/1/4
# 1/11  Default        Completed     Eth1/11
#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show interface breakout
# -----------------------------------------------
# Port  Breakout Mode  Status        Interfaces
# -----------------------------------------------
# 1/1   4x10G          Completed     Eth1/1/1
#                                    Eth1/1/2
#                                    Eth1/1/3
#                                    Eth1/1/4
# 1/11  1x100G         Completed     Eth1/11/1
#

- name: Delete all port breakout configurations
  dellemc.enterprise_sonic.sonic_port_breakout:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show interface breakout
# -----------------------------------------------
# Port  Breakout Mode  Status        Interfaces
# -----------------------------------------------
# 1/1   Default        Completed     Eth1/1
# 1/11  Default        Completed     Eth1/11


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show interface breakout
# -----------------------------------------------
# Port  Breakout Mode  Status        Interfaces
# -----------------------------------------------
# 1/1   4x10G          Completed     Eth1/1/1
#                                    Eth1/1/2
#                                    Eth1/1/3
#                                    Eth1/1/4
#

- name: Merge port breakout configurations
  dellemc.enterprise_sonic.sonic_port_breakout:
    config:
      - name: 1/11
        mode: 1x100G
    state: merged

# After state:
# ------------
#
# sonic# show interface breakout
# -----------------------------------------------
# Port  Breakout Mode  Status        Interfaces
# -----------------------------------------------
# 1/1   4x10G          Completed     Eth1/1/1
#                                    Eth1/1/2
#                                    Eth1/1/3
#                                    Eth1/1/4
# 1/11  1x100G         Completed     Eth1/11/1


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show interface breakout
# -----------------------------------------------
# Port  Breakout Mode  Status        Interfaces
# -----------------------------------------------
# 1/49   4x25G         Completed     Eth1/49/1
#                                    Eth1/49/2
#                                    Eth1/49/3
#                                    Eth1/49/4
#

- name: Replace port breakout configurations
  dellemc.enterprise_sonic.sonic_port_breakout:
    config:
      - name: 1/49
        mode: 4x10G
    state: replaced

# After state:
# ------------
#
# sonic# show interface breakout
# -----------------------------------------------
# Port  Breakout Mode  Status        Interfaces
# -----------------------------------------------
# 1/49   4x10G         Completed     Eth1/49/1
#                                    Eth1/49/2
#                                    Eth1/49/3
#                                    Eth1/49/4


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show interface breakout
# ----------------------------------------------
# Port  Breakout Mode  Status        Interfaces
# -----------------------------------------------
# 1/49  4x10G          Completed     Eth1/49/1
#                                    Eth1/49/2
#                                    Eth1/49/3
#                                    Eth1/49/4
# 1/50  2x50G          Completed     Eth1/50/1
#                                    Eth1/50/2
# 1/51  1x100G         Completed     Eth1/51/1
#

- name: Override port breakout configurations
  dellemc.enterprise_sonic.sonic_port_breakout:
    config:
      - name: 1/52
        mode: 4x10G
    state: overridden

# After state:
# ------------
#
# sonic# show interface breakout
# -----------------------------------------------
# Port  Breakout Mode  Status        Interfaces
# -----------------------------------------------
# 1/49  Default        Completed     Eth1/49
# 1/50  Default        Completed     Eth1/50
# 1/51  Default        Completed     Eth1/51
# 1/52  4x10G          Completed     Eth1/52/1
#                                    Eth1/52/2
#                                    Eth1/52/3
#                                    Eth1/52/4
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
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.port_breakout.port_breakout import Port_breakoutArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.port_breakout.port_breakout import Port_breakout


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Port_breakoutArgs.argument_spec,
                           supports_check_mode=True)

    result = Port_breakout(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
