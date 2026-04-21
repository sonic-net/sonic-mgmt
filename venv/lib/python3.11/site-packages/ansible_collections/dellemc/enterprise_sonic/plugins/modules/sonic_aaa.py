#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_aaa
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_aaa
version_added: 1.1.0
notes:
  - Tested against Enterprise SONiC Distribution by Dell Technologies
  - Supports C(check_mode)
author: S. Talabi (@stalabi1)
short_description: Manage AAA configuration on SONiC
description:
  - This module provides configuration management of AAA for devices running SONiC.
options:
  config:
    description:
      - AAA configuration
      - For all lists in the module, the list items should be specified in order of desired priority.
      - List items specified first have the highest priority.
    type: dict
    suboptions:
      authentication:
        description:
          - AAA authentication configuration
        type: dict
        version_added: 3.0.0
        suboptions:
          auth_method:
            description:
              - Specifies the order of the methods in which to authenticate login
              - Any 1 choice may be specified or 2 choices consisting of local and another group may be specified
              - C(cac-piv) option is only available in devices running sonic 4.5.0 and above.
              - MFA is not applicable when C(cac-piv) is configured as first factor for authentication.
            type: list
            elements: str
            choices: ['ldap', 'local', 'radius', 'tacacs+', 'cac-piv']
          console_auth_local :
            description:
              Enable/disable local authentication on console
            type: bool
          failthrough:
            description:
              - Enable/disable failthrough
            type: bool
          mfa_auth_method:
            version_added: 3.1.0
            description:
              - Specifies RSA SecurID as multi-factor authentication method.
            type: str
            choices: ['rsa-securid']
          login_mfa_console:
            version_added: 3.1.0
            description:
              - Enable/disable MFA method for console access.
            type: bool
      authorization:
        description:
          - AAA authorization configuration
        type: dict
        version_added: 3.0.0
        suboptions:
          commands_auth_method:
            description:
              - Specifies the order of the methods in which to authorize commands
            type: list
            elements: str
            choices: ['local', 'tacacs+']
          login_auth_method:
            description:
              - Specifies the order of the methods in which to authorize login
            type: list
            elements: str
            choices: ['ldap', 'local']
      name_service:
        description:
          - AAA name-service configuration
        type: dict
        version_added: 3.0.0
        suboptions:
          group:
            description:
              - Name-service source for group method
            type: list
            elements: str
            choices: ['ldap', 'local', 'login']
          netgroup:
            description:
              - Name-service source for netgroup method
            type: list
            elements: str
            choices: ['ldap', 'local']
          passwd:
            description:
              - Name-service source for passwd method
            type: list
            elements: str
            choices: ['ldap', 'local', 'login']
          shadow:
            description:
              - Name-service source for shadow method
            type: list
            elements: str
            choices: ['ldap', 'local', 'login']
          sudoers:
            description:
              - Name-service source for sudoers method
            type: list
            elements: str
            choices: ['ldap', 'local']
  state:
    description:
      - The state of the configuration after module completion
    choices: ['merged', 'deleted', 'overridden', 'replaced']
    default: merged
    type: str
"""

EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show aaa
# (No AAA configuration present)
#
# sonic# show mfa
# ---------------------------------------------------------
# Multi-factor Authentication Information
# ---------------------------------------------------------
# MFA Authentication             : None
# Console Exempted               : None
# MFA Service Security Profile   : None
# RSA SecurID Security Profile   : None

- name: Merge AAA configuration
  dellemc.enterprise_sonic.sonic_aaa:
    config:
      authentication:
        auth_method:
          - local
          - ldap
        console_auth_local: true
        failthrough: true
        mfa_auth_method: 'rsa-securid'
        login_mfa_console: true
      authorization:
        commands_auth_method:
          - local
          - tacacs+
        login_auth_method:
          - local
          - ldap
      name_service:
        group:
          - ldap
        netgroup:
          - local
        passwd:
          - login
        shadow:
          - ldap
        sudoers:
          - local
    state: merged

# After state:
# ------------
#
# sonic# show aaa
# ---------------------------------------------------------
# AAA Authentication Information
# ---------------------------------------------------------
# failthrough  : True
# login-method : local, ldap
# login-mfa    : rsa-securid
# console authentication  : local
# ---------------------------------------------------------
# AAA Authorization Information
# ---------------------------------------------------------
# login        : local, ldap
# commands     : local, tacacs+
# ---------------------------------------------------------
# AAA Name-Service Information
# ---------------------------------------------------------
# group-method    : ldap
# netgroup-method : local
# passwd-method   : login
# shadow-method   : ldap
# sudoers-method  : local
#
# sonic# show mfa
# ---------------------------------------------------------
# Multi-factor Authentication Information
# ---------------------------------------------------------
# MFA Authentication             : rsa-securid
# Console Exempted               : No
# MFA Service Security Profile   : None
# RSA SecurID Security Profile   : None


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show aaa
# ---------------------------------------------------------
# AAA Authentication Information
# ---------------------------------------------------------
# failthrough  : True
# login-method : local, ldap
# login-mfa    : rsa-securid
# console authentication  : local
# ---------------------------------------------------------
# AAA Authorization Information
# ---------------------------------------------------------
# login        : local, ldap
# commands     : local, tacacs+
# ---------------------------------------------------------
# AAA Name-Service Information
# ---------------------------------------------------------
# group-method    : ldap
# netgroup-method : local
# passwd-method   : login
# shadow-method   : ldap
# sudoers-method  : local
#
# sonic# show mfa
# ---------------------------------------------------------
# Multi-factor Authentication Information
# ---------------------------------------------------------
# MFA Authentication             : rsa-securid
# Console Exempted               : No
# MFA Service Security Profile   : None
# RSA SecurID Security Profile   : None

- name: Replace AAA configuration
  dellemc.enterprise_sonic.sonic_aaa:
    config:
      authentication:
        auth_method:
          - cac-piv
          - local
        console_auth_local: true
        failthrough: false
      authorization:
        commands_auth_method:
          - local
      name_service:
        group:
          - ldap
    state: replaced

# After state:
# ------------
#
# sonic# show aaa
# ---------------------------------------------------------
# AAA Authentication Information
# ---------------------------------------------------------
# failthrough  : False
# login-method : cac-piv, local
# login-mfa    : None
# console authentication  : local
# ---------------------------------------------------------
# AAA Authorization Information
# ---------------------------------------------------------
# login        : local
# ---------------------------------------------------------
# AAA Name-Service Information
# ---------------------------------------------------------
# group-method    : ldap
#
# sonic# show mfa
# ---------------------------------------------------------
# Multi-factor Authentication Information
# ---------------------------------------------------------
# MFA Authentication             : None
# Console Exempted               : None
# MFA Service Security Profile   : None
# RSA SecurID Security Profile   : None


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show aaa
# ---------------------------------------------------------
# AAA Authentication Information
# ---------------------------------------------------------
# failthrough  : True
# login-method : local, ldap
# login-mfa    : rsa-securid
# console authentication  : local
# ---------------------------------------------------------
# AAA Authorization Information
# ---------------------------------------------------------
# login        : local, ldap
# commands     : local, tacacs+
# ---------------------------------------------------------
# AAA Name-Service Information
# ---------------------------------------------------------
# group-method    : ldap
# netgroup-method : local
# passwd-method   : login
# shadow-method   : ldap
# sudoers-method  : local
#
# sonic# show mfa
# ---------------------------------------------------------
# Multi-factor Authentication Information
# ---------------------------------------------------------
# MFA Authentication             : rsa-securid
# Console Exempted               : Yes
# MFA Service Security Profile   : None
# RSA SecurID Security Profile   : None

- name: Override AAA configuration
  dellemc.enterprise_sonic.sonic_aaa:
    config:
      authentication:
        auth_method:
          - tacacs+
        console_auth_local: true
        failthrough: true
        mfa_auth_method: 'rsa-securid'
        login_mfa_console: true
    state: overridden

# After state:
# ------------
#
# sonic# show aaa
# ---------------------------------------------------------
# AAA Authentication Information
# ---------------------------------------------------------
# failthrough  : True
# login-method : tacacs+
# login-mfa    : rsa-securid
# console authentication  : local
#
# sonic# show mfa
# ---------------------------------------------------------
# Multi-factor Authentication Information
# ---------------------------------------------------------
# MFA Authentication             : rsa-securid
# Console Exempted               : No
# MFA Service Security Profile   : None
# RSA SecurID Security Profile   : None


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show aaa
# ---------------------------------------------------------
# AAA Authentication Information
# ---------------------------------------------------------
# failthrough  : True
# login-method : local, ldap
# login-mfa    : rsa-securid
# console authentication  : local
# ---------------------------------------------------------
# AAA Authorization Information
# ---------------------------------------------------------
# login        : local, ldap
# commands     : local, tacacs+
# ---------------------------------------------------------
# AAA Name-Service Information
# ---------------------------------------------------------
# group-method    : ldap
# netgroup-method : local
# passwd-method   : login
# shadow-method   : ldap
# sudoers-method  : local
#
# sonic# show mfa
# ---------------------------------------------------------
# Multi-factor Authentication Information
# ---------------------------------------------------------
# MFA Authentication             : rsa-securid
# Console Exempted               : No
# MFA Service Security Profile   : None
# RSA SecurID Security Profile   : None

- name: Delete AAA individual attributes
  dellemc.enterprise_sonic.sonic_aaa:
    config:
      authentication:
        auth_method:
          - local
          - ldap
        console_auth_local: true
        failthrough: true
        mfa_auth_method: 'rsa-securid'
        login_mfa_console: true
      authorization:
        commands_auth_method:
          - local
          - tacacs+
        login_auth_method:
          - local
          - ldap
      name_service:
        group:
          - ldap
        netgroup:
          - local
        passwd:
          - login
        shadow:
          - ldap
        sudoers:
          - local
    state: deleted

# After state:
# ------------
#
# sonic# show aaa
# (No AAA configuration present)
#
# sonic# show mfa
# ---------------------------------------------------------
# Multi-factor Authentication Information
# ---------------------------------------------------------
# MFA Authentication             : None
# Console Exempted               : None
# MFA Service Security Profile   : None
# RSA SecurID Security Profile   : None


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show aaa
# ---------------------------------------------------------
# AAA Authentication Information
# ---------------------------------------------------------
# failthrough  : True
# login-method : local, ldap
# login-mfa    : rsa-securid
# console authentication  : local
# ---------------------------------------------------------
# AAA Authorization Information
# ---------------------------------------------------------
# login        : local, ldap
# commands     : local, tacacs+
# ---------------------------------------------------------
# AAA Name-Service Information
# ---------------------------------------------------------
# group-method    : ldap
# netgroup-method : local
# passwd-method   : login
# shadow-method   : ldap
# sudoers-method  : local
#
# sonic# show mfa
# ---------------------------------------------------------
# Multi-factor Authentication Information
# ---------------------------------------------------------
# MFA Authentication             : rsa-securid
# Console Exempted               : Yes
# MFA Service Security Profile   : None
# RSA SecurID Security Profile   : None

- name: Delete all AAA configuration
  dellemc.enterprise_sonic.sonic_aaa:
    config: {}
    state: deleted

# After state:
# ------------
#
# sonic# show aaa
# (No AAA configuration present)
#
# sonic# show mfa
# ---------------------------------------------------------
# Multi-factor Authentication Information
# ---------------------------------------------------------
# MFA Authentication             : None
# Console Exempted               : None
# MFA Service Security Profile   : None
# RSA SecurID Security Profile   : None
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: dict
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: dict
after(generated):
  description: The generated configuration module invocation.
  returned: when C(check_mode)
  type: dict
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.aaa.aaa import AaaArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.aaa.aaa import Aaa


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=AaaArgs.argument_spec,
                           supports_check_mode=True)

    result = Aaa(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
