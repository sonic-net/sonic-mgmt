#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ssh_server
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_ssh_server
version_added: '3.1.0'
short_description: Manage SSH server configurations on SONiC
description:
  - This module provides SSH server configuration management to specify the
     algorithms used for SSH connection in devices running SONiC.
author: Bhavesh (@bhaveshdell)
options:
  config:
    description:
      - SSH servers use the following configurations for SSH connections.
    type: dict
    suboptions:
      server_globals:
        description:
          - SSH server global configuration.
          - For options of 'str' type, deletion results in restoring them to their default values.
        type: dict
        suboptions:
          password_authentication:
            description:
              - Configure password authentication on ssh server.
              - By default it is enabled.
              - Default is True.
            type: bool
          publickey_authentication:
            description:
              - Configure publickey authentication on ssh server.
              - Default is True.
            type: bool
          max_auth_retries:
            description:
              - Number of authentication retries allowed before session terminates.
              - Range 0-10.
              - Default is 6.
            type: int
          disable_forwarding:
            description:
              - Configure disable forwarding on ssh server.
              - Default is False.
            type: bool
          permit_root_login:
            description:
              - Configure permit root login on ssh server.
              - Default is False.
            type: bool
          permit_user_rc:
            description:
              - Configure permit user rc on ssh server.
              - Default is True.
            type: bool
          x11_forwarding:
            description:
              - Configure x11 forwarding on ssh server.
              - Default is False.
            type: bool
          permit_user_environment:
            description:
              - Configure permit user environment on ssh server.
              - Default is False.
            type: bool
          ciphers:
            description:
              - Configure ciphers on ssh server.
              - Defaults are aes128-ctr,aes192-ctr,aes256-ctr,chacha20-poly1305@openssh.com,
                aes128-gcm@openssh.com,aes256-gcm@openssh.com.
            type: str
          macs:
            description:
              - Configure macs on ssh server.
              - Defaults are umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,
                hmac-sha2-512-etm@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512.
            type: str
          kexalgorithms:
            description:
              - Configure key exchange algorithms.
              - Defaults are curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,
                ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,
                diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,
            type: str
          hostkeyalgorithms:
            description:
              - Configure hostkey algorithms on ssh server.
              - Defaults are ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-256,rsa-sha2-512,ssh-rsa.
            type: str
  state:
    description:
      - The state of the configuration after module completion.
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
# sonic# show running-configuration | grep "ip ssh"
# ip ssh disable-publickey-authentication true
# sonic#

- name: Delete specified SSH configurations
  dellemc.enterprise_sonic.sonic_ssh_server:
    config:
      server_globals:
        publickey_authentication: false
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip ssh"
# ip ssh disable-publickey-authentication false
# sonic#


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep "ip ssh"
# ip ssh disable-publickey-authentication false
# sonic#

- name: Modify SSH configurations
  dellemc.enterprise_sonic.sonic_ssh_server:
    config:
      server_globals:
        publickey_authentication: false
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip ssh"
# ip ssh disable-publickey-authentication true
# sonic#


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep "ip ssh client"
# ip ssh client ciphers aes192-ctr,chacha20-poly1305@openssh.com
# ip ssh client kexalgorithms curve25519-sha256,diffie-hellman-group16-sha512
# ip ssh client macs umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com
# sonic#

- name: Replace SSH configurations
  dellemc.enterprise_sonic.sonic_ssh:
    config:
      server_globals:
        cipher: 'aes256-ctr'
        kex: 'curve25519-sha256,diffie-hellman-group16-sha512'
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip ssh client"
# ip ssh client ciphers aes256-ctr
# ip ssh client kexalgorithms curve25519-sha256,diffie-hellman-group16-sha512
# sonic#


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep "ip ssh"
# ip ssh disable-publickey-authentication false
# sonic#

- name: Override SSH configurations
  dellemc.enterprise_sonic.sonic_ssh:
    config:
      server_globals:
        publickey_authentication: false
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip ssh"
# ip ssh disable-publickey-authentication true
# sonic#
"""

RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: dict
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The configuration resulting from module invocation.
  returned: when changed
  type: dict
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after(generated):
  description: The configuration that would be generated by module invocation in non-check mode.
  returned: when C(check_mode)
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ssh_server.ssh_server import Ssh_serverArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ssh_server.ssh_server import Ssh_server


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Ssh_serverArgs.argument_spec,
                           supports_check_mode=True)

    result = Ssh_server(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
