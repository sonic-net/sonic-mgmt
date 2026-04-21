#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_lldp_global
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_lldp_global
version_added: '2.1.0'
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage Global LLDP configurations on SONiC
description:
  - This module provides configuration management of global LLDP parameters
    for use on LLDP enabled Layer 2 interfaces of devices running SONiC.
  - It is intended for use in conjunction with LLDP Layer 2 interface
    configuration applied on participating interfaces.
author: 'Divya Balasubramanian(@divya-balasubramania)'
options:
  config:
    description: The set of link layer discovery protocol global attribute configurations
    type: dict
    suboptions:
      enable:
        description:
          - This argument is a boolean value to enable or disable LLDP.
        type: bool
      multiplier:
        description:
          - Multiplier value is used to determine the timeout interval (i.e. hello-time x multiplier value)
          - The range is from 1 to 10
        type: int
      system_description:
        description:
          -  Description of this system to be sent in LLDP advertisements.
          -  When configured, this value is used in the advertisements
             instead of the default system description.
        type: str
      system_name:
        description:
          - Specifying a descriptive system name using this command, user may find it easier to distinguish the device with LLDP.
          - By default, the host name is used.
        type: str
      mode:
        description:
          - By default both transmit and receive of LLDP frames is enabled.
          - This command can be used to configure either in receive only or transmit only mode.
        type: str
        choices:
           - receive
           - transmit
      hello_time:
        description:
          - Frequency at which LLDP advertisements are sent (in seconds).
          - The range is from 5 to 254 sec
        type: int
      tlv_select:
        description:
          - By default, management address and system capabilities TLV are advertised in LLDP frames.
          - This configuration option can be used to selectively suppress sending of these TLVs
            to the Peer.
        type: dict
        suboptions:
          management_address:
            description:
              - Enable or disable management address TLV.
            type: bool
          system_capabilities:
            description:
              - Enable or disable system capabilities TLV.
            type: bool
  state:
    description:
      - The state specifies the type of configuration update to be performed on the device.
      - If the state is "merged", merge specified attributes with existing configured attributes.
      - For "deleted", delete the specified attributes from existing configuration.
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
# sonic# show running-configuration
# !
# lldp receive
# lldp timer 200
# lldp multiplier 1
# lldp system-name 8999_System
# lldp system-description sonic_system
# !

- name: Delete LLDP configurations
  dellemc.enterprise_sonic.sonic_lldp_global:
    config:
      hello_time: 200
      system_description: sonic_system
      mode: receive
      multiplier: 1
    state: deleted

# After state:
# ------------
# sonic# show running-configuration | grep lldp
# !
# lldp system-name 8999_System
# !
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep lldp
# sonic#

- name: Delete default LLDP configurations
  dellemc.enterprise_sonic.sonic_lldp_global:
    config:
      tlv_select:
        system_capabilities: true
    state: deleted

# After state:
# ------------
# sonic# show running-configuration
# !
# no lldp tlv-select system-capabilities
# !


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep lldp
# !
# lldp receive
# lldp timer 200
# lldp multiplier 1
# lldp system-name 8999_System
# lldp system-description sonic_system
# !

- name: Delete all LLDP configuration
  dellemc.enterprise_sonic.sonic_lldp_global:
    config:
    state: deleted

# After state:  (No LLDP global configuration present.)
# ------------
# sonic# show running-configuration | grep lldp
# sonic#


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep lldp
# sonic#

- name: Modify LLDP configurations
  dellemc.enterprise_sonic.sonic_lldp_global:
    config:
      enable: false
      multiplier: 9
      system_name: CR_sonic
      hello_time: 18
      mode: receive
      system_description: Sonic_System
      tlv_select:
        management_address: true
        system_capabilities: false
    state: merged

# After state:
# ------------
# sonic# show running-configuration | grep lldp
# !
# no lldp enable
# no lldp tlv-select system_capabilities
# lldp receive
# lldp timer 18
# lldp multiplier 9
# lldp system-name CR_sonic
# lldp system-description Sonic_System
# !


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep lldp
# !
# lldp receive
# lldp timer 200
# lldp multiplier 1
# lldp system-name 8999_System
# lldp system-description sonic_system
# !

- name: Modify LLDP configurations
  dellemc.enterprise_sonic.sonic_lldp_global:
    config:
      multiplier: 9
      system_name: CR_sonic
    state: merged

# After state:
# ------------
# sonic# show running-configuration | grep lldp
# !
# lldp receive
# lldp timer 200
# lldp multiplier 9
# lldp system-name CR_sonic
# lldp system-description sonic_system
# !
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
  type: list
after:
  description: The resulting configuration module invocation.
  returned: when changed
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
  type: list
after(generated):
  description: The generated configuration module invocation.
  returned: when C(check_mode)
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
  type: list
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.lldp_global.lldp_global import Lldp_globalArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.lldp_global.lldp_global import Lldp_global


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Lldp_globalArgs.argument_spec,
                           supports_check_mode=True)

    result = Lldp_global(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
