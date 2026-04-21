#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_fips
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_fips
version_added: '2.1.0'
short_description: Manage FIPS configurations on SONiC
description:
  - This module provides FIPS configuration management to specify the
    security requirements for cryptographic modules in devices running
    SONiC.
author: 'Balasubramaniam Koundappa(@balasubramaniam-k)'
options:
  config:
    description: The mode of FIPS configuration with specifications of security requirements for cryptographic modules.
    type: dict
    suboptions:
      enable:
        description:
          - This argument is a boolean value to enable or disable FIPS mode.
        type: bool
  state:
    description:
      - The state specifies the type of configuration update to be performed on the device.
        If the state is "merged", merge specified attributes with existing configured attributes.
        For "deleted", delete the specified attributes from existing configuration.
    type: str
    choices:
      - merged
      - deleted
    default: merged
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep fips
# !
# crypto fips enable
# !

- name: Delete FIPS mode configuration
  dellemc.enterprise_sonic.sonic_fips:
    config:
      enable: false
    state: deleted

# After state:
# ------------
# sonic# show running-configuration | grep fips
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show fips status
# !
# FIPS Mode           : Enabled
# Crypto Library      : OpenSSL 1.1.1n-fips  15 Mar 2022
# FIPS Object Module  : DELL OpenSSL FIPS Crypto Module v2.6 July 2021
# !

- name: Disable FIPS mode
  dellemc.enterprise_sonic.sonic_fips:
    config:
      enable: false
    state: deleted

# After state:
# ------------
#
# sonic# show fips status
# !
# FIPS Mode           : Disabled
# Crypto Library      : OpenSSL 1.1.1n-fips  15 Mar 2022
# FIPS Object Module  : DELL OpenSSL FIPS Crypto Module v2.6 July 2021
# !


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep fips
# sonic#

- name: Modify FIPS configurations
  dellemc.enterprise_sonic.sonic_fips:
    config:
      enable: true
    state: merged

# After state:
# ------------
# sonic# show running-configuration | grep fips
# !
# crypto fips enable
# !


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show fips status
# !
# FIPS Mode           : Disabled
# Crypto Library      : OpenSSL 1.1.1n-fips  15 Mar 2022
# FIPS Object Module  : DELL OpenSSL FIPS Crypto Module v2.6 July 2021
# !

- name: Enable FIPS mode
  dellemc.enterprise_sonic.sonic_fips:
    config:
      enable: true
    state: merged

# After state:
# ------------
#
# sonic# show fips status
# !
# FIPS Mode           : Enabled
# Crypto Library      : OpenSSL 1.1.1n-fips  15 Mar 2022
# FIPS Object Module  : DELL OpenSSL FIPS Crypto Module v2.6 July 2021
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.fips.fips import FipsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.fips.fips import Fips


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=FipsArgs.argument_spec,
                           supports_check_mode=True)

    result = Fips(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
