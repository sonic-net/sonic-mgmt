#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_system
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_system
version_added: 1.0.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
author: Abirami N (@abirami-n)
short_description: Configure system parameters
description:
  - This module is used for configuration management of global system parameters on devices running Enterprise SONiC.
options:
  config:
    description:
      - Specifies the system related configurations
    type: dict
    suboptions:
      hostname:
        description:
          - Specifies the hostname of the SONiC device
        type: str
      interface_naming:
        description:
          - Specifies the type of interface-naming in device
        type: str
        choices:
          - standard
          - standard_extended
          - native
      anycast_address:
        description:
          - Specifies different types of anycast address that can be configured on the device
        type: dict
        suboptions:
          ipv4:
            description:
              - Enable or disable ipv4 anycast-address
            type: bool
          ipv6:
            description:
              - Enable or disable ipv6 anycast-address
            type: bool
          mac_address:
            description:
              - Specifies the mac anycast-address
            type: str
      auto_breakout:
        description:
          - Specifies auto-breakout status in the device
        version_added: 2.5.0
        type: str
        choices:
          - ENABLE
          - DISABLE
      load_share_hash_algo:
        description:
          - Specifies different types of ECMP Load share hash algorithm
        version_added: 2.5.0
        type: str
        choices:
          - CRC
          - XOR
          - CRC_32LO
          - CRC_32HI
          - CRC_CCITT
          - CRC_XOR
          - JENKINS_HASH_LO
          - JENKINS_HASH_HI
      audit_rules:
        description:
          - Specifies audit rule profile type.
          - Can be used on SONiC release versions 4.4.0 and above.
        version_added: 2.5.0
        type: str
        choices:
          - BASIC
          - DETAIL
          - CUSTOM
          - NONE
      switching_mode:
        description:
          - Specifies switching mode in the device.
          - Operational default value is STORE_AND_FORWARD.
        version_added: 3.1.0
        type: str
        choices:
          - CUT_THROUGH
          - STORE_AND_FORWARD
      adjust_txrx_clock_freq:
        description:
          - Adjust TX/RX clock frequency to platform specific value.
          - Operational default value is C(false).
        version_added: 3.1.0
        type: bool
      concurrent_session_limit:
        version_added: 3.1.0
        description:
          - Specifies limit on number of concurrent sessions
          - Range 1-12
        type: int
      password_complexity:
        description:
          - The set of login password attribute configurations
        type: dict
        suboptions:
          min_length:
            description:
              - Minimum number of required alphanumeric characters
              - The range is from 6 to 32
              - Default is 8
            type: int
          min_upper_case:
            description:
              - Minimum number of uppercase characters required
              - The range is from 0 to 31
            type: int
          min_lower_case:
            description:
              - Minimum number of lowercase characters required
              - The range is from 0 to 31
            type: int
          min_numerals:
            description:
              - Minimum number of numeric characters required
              - The range is from 0 to 31
            type: int
          min_spl_char:
            description:
              - Minimum number of special characters required
              - The range is from 0 to 31
            type: int
  state:
    description:
      - Specifies the operation to be performed on the system parameters configured on the device.
      - In case of merged, the input configuration will be merged with the existing system configuration on the device.
      - In case of deleted the existing system configuration will be removed from the device.
    default: merged
    choices: ['merged', 'replaced', 'overridden', 'deleted']
    type: str
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
# !
# SONIC(config)#do show running-configuration
# !
# ip anycast-mac-address aa:bb:cc:dd:ee:ff
# ip anycast-address enable
# ipv6 anycast-address enable
# interface-naming standard
# ip load-share hash algorithm JENKINS_HASH_HI
# login concurrent-session limit 4
# system adjust-txrx-clock-freq
# login password-attribute character-restriction lower 2

- name: Delete System configuration
  dellemc.enterprise_sonic.sonic_system:
    config:
      hostname: SONIC
      interface_naming: standard
      anycast_address:
        ipv6: true
      load_share_hash_algo: JENKINS_HASH_HI
      concurrent_session_limit: 4
      adjust_txrx_clock_freq: true
      password_complexity:
        min_lower_case: 2
    state: deleted

# After state:
# ------------
# !
# sonic(config)#do show running-configuration
# !
# ip anycast-mac-address aa:bb:cc:dd:ee:ff
# ip anycast-address enable


# Using "deleted" state
#
# Before state:
# -------------
# !
# SONIC(config)#do show running-configuration
# !
# ip anycast-mac-address aa:bb:cc:dd:ee:ff
# ip anycast-address enable
# ipv6 anycast-address enable
# interface-naming standard
# ip load-share hash algorithm JENKINS_HASH_HI
# login concurrent-session limit 4

- name: Delete all system related configs in device configuration
  dellemc.enterprise_sonic.sonic_system:
    config:
    state: deleted

# After state:
# ------------
# !
# sonic(config)#do show running-configuration
# !


# Using "merged" state
#
# Before state:
# -------------
# !
# sonic(config)#do show running-configuration
# !

- name: Merge provided configuration with device configuration
  dellemc.enterprise_sonic.sonic_system:
    config:
      hostname: SONIC
      interface_naming: standard
      anycast_address:
        ipv6: true
        ipv4: true
        mac_address: aa:bb:cc:dd:ee:ff
      load_share_hash_algo: JENKINS_HASH_HI
      concurrent_session_limit: 4
      adjust_txrx_clock_freq: true
      password_complexity:
        min_upper_case: 2
        min_spl_char: 2
    state: merged

# After state:
# ------------
# !
# SONIC(config)#do show running-configuration
# !
# hostname SONIC
# ip anycast-mac-address aa:bb:cc:dd:ee:ff
# ip anycast-address enable
# ipv6 anycast-address enable
# interface-naming standard
# ip load-share hash algorithm JENKINS_HASH_HI
# login concurrent-session limit 4
# system adjust-txrx-clock-freq
# login password-attribute character-restriction upper 2
# login password-attribute character-restriction special-char 2

# Using "replaced" state
#
# Before state:
# -------------
# !
# sonic(config)#do show running-configuration
# !
# ip anycast-mac-address aa:bb:cc:dd:ee:ff
# ip anycast-address enable
# ipv6 anycast-address enable
# interface-naming standard
# login concurrent-session limit 4
# login password-attribute character-restriction upper 2
# login password-attribute character-restriction special-char 2

- name: Replace system configuration.
  sonic_system:
    config:
      hostname: SONIC
      anycast_address:
        ipv6: true
      concurrent_session_limit: 5
      password_complexity:
        min_lower_case: 2
    state: replaced

# After state:
# ------------
# !
# SONIC(config)#do show running-configuration
# !
# hostname SONIC
# ipv6 anycast-address enable
# login concurrent-session limit 5
# login password-attribute character-restriction lower 2

# Using "replaced" state
#
# Before state:
# -------------
# !
# sonic(config)#do show running-configuration
# !
# ip anycast-mac-address aa:bb:cc:dd:ee:ff
# interface-naming standard
# login concurrent-session limit 5
# login password-attribute character-restriction lower 2

- name: Replace system device configuration.
  sonic_system:
    config:
      hostname: sonic
      interface_naming: standard
      anycast_address:
        ipv6: true
        ipv4: true
      load_share_hash_algo: JENKINS_HASH_HI
      password_complexity:
        min_numerals: 2
    state: replaced

# After state:
# ------------
# !
# sonic(config)#do show running-configuration
# !
# ip anycast-address enable
# ipv6 anycast-address enable
# interface-naming standard
# ip load-share hash algorithm JENKINS_HASH_HI
# login password-attribute character-restriction numeric 2

# Using "overridden" state
#
# Before state:
# -------------
# !
# sonic(config)#do show running-configuration
# !
# ipv6 anycast-address enable
# ip load-share hash algorithm JENKINS_HASH_HI
# login concurrent-session limit 5
# login password-attribute character-restriction numeric 2

- name: Override system configuration.
  sonic_system:
    config:
      hostname: SONIC
      interface_naming: standard
      anycast_address:
        ipv4: true
        mac_address: bb:aa:cc:dd:ee:ff
      load_share_hash_algo: CRC_XOR
      concurrent_session_limit: 4
      password_complexity:
        min_upper_case: 1
    state: overridden

# After state:
# ------------
# !
# SONIC(config)#do show running-configuration
# !
# hostname SONIC
# ip anycast-mac-address bb:aa:cc:dd:ee:ff
# ip anycast-address enable
# interface-naming standard
# ip load-share hash algorithm CRC_XOR
# login concurrent-session limit 4
# login password-attribute character-restriction upper 1

# Using "merged" state
#
# Before state:
# -------------
# !
# sonic(config)#do show running-configuration
# !

- name: Merge provided configuration with device configuration
  dellemc.enterprise_sonic.sonic_system:
    config:
      hostname: SONIC
      interface_naming: standard
      auto_breakout: ENABLE
      load_share_hash_algo: JENKINS_HASH_HI
      audit_rules: BASIC
    state: merged

# After state:
# ------------
# !
# SONIC(config)#do show running-configuration
# !
# hostname SONIC
# interface-naming standard
# auto-breakout
# ip load-share hash algorithm JENKINS_HASH_HI
# auditd-system rules basic

# Using "deleted" state
#
# Before state:
# -------------
# !
# SONIC(config)#do show running-configuration
# !
# hostname SONIC
# interface-naming standard
# auto-breakout
# ip load-share hash algorithm JENKINS_HASH_HI
# auditd-system rules basic

- name: Delete auto-breakout configuration on the device
  dellemc.enterprise_sonic.sonic_system:
    config:
      hostname: SONIC
      auto_breakout: ENABLE
      load_share_hash_algo: JENKINS_HASH_HI
      audit_rules: BASIC
    state: deleted

# After state:
# ------------
# !
# sonic(config)#do show running-configuration
# !
# interface-naming standard
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.system.system import SystemArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.system.system import System


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=SystemArgs.argument_spec,
                           supports_check_mode=True)

    result = System(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
