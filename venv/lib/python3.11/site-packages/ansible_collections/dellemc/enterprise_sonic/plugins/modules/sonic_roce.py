#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_roce
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_roce
version_added: 2.5.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage RoCE QoS configuration on SONiC
description:
  - This module provides configuration management of RoCE(v2) QoS for devices running SONiC
author: "S. Talabi (@stalabi1)"
options:
  config:
    description:
      - RoCE QoS configuration
    type: dict
    suboptions:
      roce_enable:
        description:
          - Enable or disable RoCEv2 default buffer configuration
        type: bool
      pfc_priority:
        description:
          - Specifies the PFC priorities to enable RoCEv2 buffer default configuration on
          - Range 0-7, two priority values separated by comma
          - Ex. '3,4'
          - Only configurable when RoCE is enabled
        type: str
  state:
    description:
      - The state of the configuration after module completion.
    type: str
    choices:
      - merged
    default: merged
"""

EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep roce
# (No RoCE configuration present)

- name: Enable RoCE for PFC priorities
  dellemc.enterprise_sonic.sonic_roce:
    config:
      roce_enable: true
      pfc_priorities: '3,4'
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration | grep roce
# roce enable pfc-priority 3,4
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
  description: The configuration from module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after(generated):
  description: The generated (simulated) configuration expected from module invocation.
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.roce.roce import RoceArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.roce.roce import Roce


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=RoceArgs.argument_spec,
                           supports_check_mode=True)

    result = Roce(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
