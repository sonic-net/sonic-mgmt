#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ssh
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_ssh
version_added: '3.0.0'
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).

short_description: Manage SSH configurations on SONiC
description:
  - This module provides SSH configuration management to specify the
     algorithms used for SSH connection in devices running SONiC.
author: 'Balasubramaniam Koundappa(@balasubramaniam-k)'
options:
  config:
    description:
      - SSH clients and servers use the following configurations for SSH connections.
    type: dict
    suboptions:
      client:
        description:
          - SSH client configuration
        type: dict
        suboptions:
          cipher:
            description:
              - Cipher algorithm used in SSH connection for encryption.
                 When configured, this value is used by SSH clients
                 which communicate with the server.
              - Specify as a comma separated list.
              -   Options are aes128-ctr, aes192-ctr, aes256-ctr
              -    chacha20-poly1305@openssh.com, aes128-gcm@openssh.com
              -    and aes256-gcm@openssh.com
            type: str
          kex:
            description:
              - KEX algorithm used in SSH connection for key exchange.
                 When configured, this value is used by SSH clients
                 which communicate with the server.
              - Specify as a comma separated list.
              -   Options are curve25519-sha256, curve25519-sha256@libssh.org
              -    ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521,
              -    diffie-hellman-group-exchange-sha256,
              -    diffie-hellman-group16-sha512,
              -    diffie-hellman-group18-sha512 and
              -    diffie-hellman-group14-sha256
            type: str
          mac:
            description:
              - MAC algorithm used in SSH connection for generating and
                 verifying Message Authentication Codes. When configured,
                 this value is used by SSH clients which communicate with
                 the server.
              - Specify as a comma separated list.
              -   Options are umac-128-etm@openssh.com,
              -    hmac-sha2-256-etm@openssh.com,
              -    hmac-sha2-512-etm@openssh.com, umac-128@openssh.com,
              -    hmac-sha2-256 and hmac-sha2-512
            type: str
  state:
    description:
      - The state specifies the type of configuration update to be performed on the device.
      -   If the state is "merged", merge specified attributes with existing configured attributes.
      -   For "deleted", delete the specified attributes from existing configuration.
      -   For "replaced", replace on-device SSH configuration with the specified configuration.
      -   For "overridden", override on-device SSH configurations with the specified configuration.
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
# sonic# show running-configuration | grep "ip ssh client"
# ip ssh client ciphers aes192-ctr,chacha20-poly1305@openssh.com
# ip ssh client macs umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com
# ip ssh client kexalgorithms curve25519-sha256,diffie-hellman-group16-sha512
# sonic#

- name: Delete specified SSH configurations
  dellemc.enterprise_sonic.sonic_ssh:
    config:
      client:
        cipher: 'aes192-ctr,chacha20-poly1305@openssh.com'
        mac: 'umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com'
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip ssh client"
# ip ssh client kexalgorithms curve25519-sha256,diffie-hellman-group16-sha512
# sonic#


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep "ip ssh client"
# ip ssh client ciphers aes192-ctr,chacha20-poly1305@openssh.com
# ip ssh client kexalgorithms curve25519-sha256,diffie-hellman-group16-sha512
# ip ssh client macs umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com
# sonic#

- name: Delete all SSH configurations
  dellemc.enterprise_sonic.sonic_ssh:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip ssh client"
# (No "ip ssh client" configuration present)
# sonic#


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep "ip ssh client"
# sonic
# (No "ip ssh client" configuration present)

- name: Modify SSH configurations
  dellemc.enterprise_sonic.sonic_ssh:
    config:
      client:
        cipher: 'aes192-ctr,chacha20-poly1305@openssh.com'
        mac: 'umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com'
        kex: 'curve25519-sha256,diffie-hellman-group16-sha512'
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip ssh client"
# ip ssh client ciphers aes192-ctr,chacha20-poly1305@openssh.com
# ip ssh client kexalgorithms curve25519-sha256,diffie-hellman-group16-sha512
# ip ssh client macs umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com
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

- name: Modify SSH configurations
  dellemc.enterprise_sonic.sonic_ssh:
    config:
      client:
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
# sonic# show running-configuration | grep "ip ssh client"
# ip ssh client ciphers aes192-ctr,chacha20-poly1305@openssh.com
# ip ssh client kexalgorithms curve25519-sha256,diffie-hellman-group16-sha512
# ip ssh client macs umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com
# sonic#

- name: Modify SSH configurations
  dellemc.enterprise_sonic.sonic_ssh:
    config:
      client:
        cipher: 'aes256-ctr'
        mac: 'umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com'
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration | grep "ip ssh client"
# ip ssh client ciphers aes256-ctr
# ip ssh client macs umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com
# sonic#
"""

RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: dict
  sample: >
    The configuration returned will always be in the same format
     as the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  type: dict
  sample: >
    The configuration returned will always be in the same format
     as the parameters above.
after(generated):
  description: The generated configuration from module invocation.
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ssh.ssh import SshArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ssh.ssh import Ssh


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=SshArgs.argument_spec,
                           supports_check_mode=True)

    result = Ssh(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
