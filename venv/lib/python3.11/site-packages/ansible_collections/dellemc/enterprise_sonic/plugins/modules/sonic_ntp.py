#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ntp
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_ntp
version_added: 2.0.0
notes:
  - Supports C(check_mode).
short_description: Manage NTP configuration on SONiC.
description:
  - This module provides configuration management of NTP for devices running SONiC.
author: "M. Zhang (@mingjunzhang2019)"
options:
  config:
    description:
      - Specifies NTP related configurations.
    type: dict
    suboptions:
      source_interfaces:
        type: list
        elements: str
        description:
          - List of names of NTP source interfaces.
      enable_ntp_auth:
        type: bool
        description:
          - Enable or disable NTP authentication.
      trusted_keys:
        type: list
        elements: int
        description:
          - List of trusted NTP authentication keys.
      vrf:
        type: str
        description:
          - VRF name on which NTP is enabled.
      servers:
        type: list
        elements: dict
        description:
          - List of NTP servers.
          - minpoll and maxpoll are required to be configured together.
        suboptions:
          address:
            type: str
            description:
              - IPv4/IPv6 address or host name of NTP server.
            required: true
          key_id:
            type: int
            description:
              - NTP authentication key used by server.
              - Key_id can not be deleted.
          minpoll:
            type: int
            description:
              - Minimum poll interval to poll NTP server.
              - minpoll can not be deleted.
          maxpoll:
            type: int
            description:
              - Maximum poll interval to poll NTP server.
              - maxpoll can not be deleted.
          prefer:
            type: bool
            description:
              - Indicates whether this server should be preferred.
              - prefer can not be deleted.
      ntp_keys:
        type: list
        elements: dict
        description:
          - List of NTP authentication keys.
        suboptions:
          key_id:
            type: int
            description:
              - NTP authentication key identifier.
            required: true
          key_type:
            type: str
            description:
              - NTP authentication key type.
              - key_type can not be deleted.
              - When "state" is "merged", "key_type" is required.
            choices:
              - NTP_AUTH_SHA1
              - NTP_AUTH_MD5
              - NTP_AUTH_SHA2_256
          key_value:
            type: str
            description:
              - NTP authentication key value.
              - key_value can not be deleted.
              - When "state" is "merged", "key_value" is required.
          encrypted:
            type: bool
            description:
              - NTP authentication key_value is encrypted.
              - encrypted can not be deleted.
              - When "state" is "merged", "encrypted" is required.

  state:
    description:
      - The state of the configuration after module completion.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
    default: merged
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show ntp server
# ----------------------------------------------------------------------------
# NTP Servers                     minpoll maxpoll Prefer Authentication key ID
# ----------------------------------------------------------------------------
# 10.11.0.1                       6       10      False
# 10.11.0.2                       5       9       False
# dell.com                        6       9       False
# dell.org                        7       10      True
#
- name: Delete NTP server configuration
  sonic_ntp:
    config:
      servers:
        - address: 10.11.0.2
        - address: dell.org
    state: deleted

# After state:
# ------------
#
# sonic# show ntp server
# ----------------------------------------------------------------------------
# NTP Servers                     minpoll maxpoll Prefer Authentication key ID
# ----------------------------------------------------------------------------
# 10.11.0.1                       6       10      False
# dell.com                        6       9       False
#
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show ntp global
# ----------------------------------------------
# NTP Global Configuration
# ----------------------------------------------
# NTP source-interfaces:  Ethernet0, Ethernet4, Ethernet8, Ethernet16
#
- name: Delete NTP source-interface configuration
  sonic_ntp:
    config:
      source_interfaces:
        - Ethernet8
        - Ethernet16
    state: deleted

# After state:
# ------------
#
# sonic# show ntp global
# ----------------------------------------------
# NTP Global Configuration
# ----------------------------------------------
# NTP source-interfaces:  Ethernet0, Ethernet4
#
#
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep ntp
# ntp authentication-key 8 sha1 U2FsdGVkX1/NpJrdOeyMeUHEkSohY6azY9VwbAqXRTY= encrypted
# ntp authentication-key 10 md5 U2FsdGVkX1/Gxds/5pscCvIKbVngGaKka4SQineS51Y= encrypted
# ntp authentication-key 20 sha2-256 U2FsdGVkX1/eAzKj1teKhYWD7tnzOsYOijGeFAT0rKM= encrypted
#
- name: Delete NTP key configuration
  sonic_ntp:
    config:
      ntp_keys:
        - key_id: 10
        - key_id: 20
    state: deleted
#
# After state:
# ------------
#
# sonic# show running-configuration | grep ntp
# ntp authentication-key 8 sha1 U2FsdGVkX1/NpJrdOeyMeUHEkSohY6azY9VwbAqXRTY= encrypted
#
#
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show ntp server
# ----------------------------------------------------------------------------
# NTP Servers                     minpoll maxpoll Prefer Authentication key ID
# ----------------------------------------------------------------------------
# 10.11.0.1                       6       10      False
# dell.com                        6       9       False
#
- name: Merge NTP server configuration
  sonic_ntp:
    config:
      servers:
        - address: 10.11.0.2
          minpoll: 5
        - address: dell.org
          minpoll: 7
          maxpoll: 10
          prefer: true
    state: merged

# After state:
# ------------
#
# sonic# show ntp server
# ----------------------------------------------------------------------------
# NTP Servers                     minpoll maxpoll Prefer Authentication key ID
# ----------------------------------------------------------------------------
# 10.11.0.1                       6       10      Flase
# 10.11.0.2                       5       10      Flase
# dell.com                        6       9       Flase
# dell.org                        7       10      True
#
#
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show ntp global
# ----------------------------------------------
# NTP Global Configuration
# ----------------------------------------------
# NTP source-interfaces:  Ethernet0, Ethernet4
#
- name: Merge NTP source-interface configuration
  sonic_ntp:
    config:
      source_interfaces:
        - Ethernet8
        - Ethernet16
    state: merged

# After state:
# ------------
#
# sonic# show ntp global
# ----------------------------------------------
# NTP Global Configuration
# ----------------------------------------------
# NTP source-interfaces:  Ethernet0, Ethernet4, Ethernet8, Ethernet16
#
#
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep ntp
# ntp authentication-key 8 sha1 U2FsdGVkX1/NpJrdOeyMeUHEkSohY6azY9VwbAqXRTY= encrypted
#
- name: Merge NTP key configuration
  sonic_ntp:
    config:
      ntp_keys:
        - key_id: 10
          key_type: NTP_AUTH_MD5
          key_value: dellemc10
          encrypted: false
        - key_id: 20
          key_type: NTP_AUTH_SHA2_256
          key_value: dellemc20
          encrypted: false
    state: merged
#
# After state:
# ------------
#
# sonic# show running-configuration | grep ntp
# ntp authentication-key 8 sha1 U2FsdGVkX1/NpJrdOeyMeUHEkSohY6azY9VwbAqXRTY= encrypted
# ntp authentication-key 10 md5 U2FsdGVkX1/Gxds/5pscCvIKbVngGaKka4SQineS51Y= encrypted
# ntp authentication-key 20 sha2-256 U2FsdGVkX1/eAzKj1teKhYWD7tnzOsYOijGeFAT0rKM= encrypted
#
# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show ntp server
# ----------------------------------------------------------------------------
# NTP Servers                     minpoll maxpoll Prefer Authentication key ID
# ----------------------------------------------------------------------------
# 10.11.0.1                       6       10      False
# dell.com                        6       9       False
#
- name: Replace NTP server configuration
  sonic_ntp:
    config:
      servers:
        - address: 10.11.0.2
          minpoll: 5
          maxpoll: 9
        - address: dell.com
          minpoll: 7
          maxpoll: 10
          prefer: true
    state: replaced
#
# After state:
# ------------
#
# sonic# show ntp server
# ----------------------------------------------------------------------------
# NTP Servers                     minpoll maxpoll Prefer Authentication key ID
# ----------------------------------------------------------------------------
# 10.11.0.1                       6       10      False
# 10.11.0.2                       5       9       False
# dell.com                        7       10      True
#
# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show ntp server
# ----------------------------------------------------------------------------
# NTP Servers                     minpoll maxpoll Prefer Authentication key ID
# ----------------------------------------------------------------------------
# 10.11.0.1                       6       10      False
# dell.com                        6       9       False
#
# sonic# show ntp global
# ----------------------------------------------
# NTP Global Configuration
# ----------------------------------------------
# NTP source-interfaces:  Ethernet0, Ethernet4
#
- name: Overridden NTP configuration
  sonic_ntp:
    config:
      servers:
        - address: 10.11.0.2
          minpoll: 5
        - address: dell.com
          minpoll: 7
          maxpoll: 10
          prefer: true
    state: overridden
#
# After state:
# ------------
#
# After state:
# ------------
#
# sonic# show ntp server
# ----------------------------------------------------------------------------
# NTP Servers                     minpoll maxpoll Prefer Authentication key ID
# ----------------------------------------------------------------------------
# 10.11.0.2                       5       10      False
# dell.com                        7       10      True
#
# sonic# show ntp global
#
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
after(generated):
  description: The generated configuration module invocation.
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ntp.ntp import NtpArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ntp.ntp import Ntp


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=NtpArgs.argument_spec,
                           supports_check_mode=True)

    result = Ntp(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
