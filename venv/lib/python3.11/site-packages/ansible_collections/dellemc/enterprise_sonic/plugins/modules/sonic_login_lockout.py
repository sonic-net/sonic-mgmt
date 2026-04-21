#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_login_lockout
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_login_lockout
version_added: 2.5.0
short_description: Manage Global Login Lockout configurations on SONiC
description:
  - This module provides configuration management of login lockout parameters.
  - Login Lockout feature is to lock out the user account for user-lockout-period
    after the max-retry failed attempts. Console exempt option can be enabled
    to skip the login lockout validations for console users.
author: 'Arul Kumar Shankara Narayanan(@arulkumar9690)'
options:
  config:
    description: The set of login lockout attribute configurations
    type: dict
    suboptions:
      console_exempt:
        description:
          - Exempt console logins from account lockout.
        type: bool
      period:
        description:
          - Account lockout period in minutes
          - The range is from 0 to 43200
        type: int
      max_retries:
        description:
          - The number of maximum password retries.
          - The range is from 0 to 16
        type: int
  state:
    description:
      - Specifies the operation to be performed on the login attributes configured on the device.
      - If the state is "merged", merge specified attributes with existing configured login attributes.
      - For "deleted", delete the specified login attributes from existing configuration.
      - For "overridden", Overrides all on-device login lockout configurations with the provided configuration.
      - For "replaced", Replaces on-device login lockout configurations with the provided configuration.
    type: str
    choices:
      - merged
      - deleted
      - overridden
      - replaced
    default: merged
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep lockout
# !
# login lockout period 12
# login lockout max-retries 5
# login lockout console-exempt
# !

- name: Delete Login Lockout configurations
  dellemc.enterprise_sonic.sonic_login_lockout:
    config:
      period: 12
      max_retries: 5
    state: deleted

# After state:
# ------------
# sonic# show running-configuration | grep lockout
# !
# login lockout console-exempt
# !
# sonic#


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep lockout
# sonic#

- name: Modify Login Lockout configurations
  dellemc.enterprise_sonic.sonic_login_lockout:
    config:
      console_exempt: true
      period: 12
      max_retries: 5
    state: merged

# After state:
# ------------
# sonic# show running-configuration | grep lockout
# !
# login lockout period 12
# login lockout max-retries 5
# login lockout console-exempt
# !

# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep lockout
# !
# login lockout period 10
# login lockout max-retries 2
# !
# sonic#

- name: Override Login Lockout configurations
  dellemc.enterprise_sonic.sonic_login_lockout:
    config:
      console_exempt: true
      period: 11
      max_retries: 3
    state: overridden

# After state:
# ------------
# sonic# show running-configuration | grep lockout
# !
# login lockout period 11
# login lockout max-retries 3
# login lockout console-exempt
# !

# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep lockout
# !
# login lockout period 10
# login lockout max-retries 2
# !
# sonic#

- name: Replace Login Lockout configurations
  dellemc.enterprise_sonic.sonic_login_lockout:
    config:
      period: 15
    state: replaced

# After state:
# ------------
# sonic# show running-configuration | grep lockout
# !
# login lockout period 15
# !
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: dict
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: dict
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.login_lockout.login_lockout import Login_lockoutArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.login_lockout.login_lockout import Login_lockout


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Login_lockoutArgs.argument_spec,
                           supports_check_mode=True)

    result = Login_lockout(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
