#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_users
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_users
version_added: 1.1.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
author: Niraimadaiselvam M (@niraimadaiselvamm)
short_description: Manage users and its parameters
description:
  - This module provides configuration management of users parameters on devices running Enterprise SONiC.
options:
  config:
    description:
      - Specifies the users related configuration.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Specifies the name of the user.
        type: str
        required: true
      role:
        description:
          - Specifies the role of the user.
        type: str
        choices:
          - admin
          - operator
          - netadmin
          - secadmin
      password:
        description:
          - Specifies the password of the user.
        type: str
      update_password:
        description:
          - Specifies the update password flag.
          - In case of always, password will be updated every time.
          - In case of on_create, password will be updated only when user is created.
        type: str
        choices:
          - always
          - on_create
        default: always
      ssh_key:
        version_added: 3.1.0
        description:
          - Specifies the user ssh key for an existing user.
          - The ssh key pair (public and private key) can be created using ssh-keygen command on the server from
          - where the user will connect to the SONiC device.
          - Only the public key is configured in the ssh_key field.
          - The ssh_key option can only be "merged" after initial creation of the affected "user" instance
          - and must be merged without any additional options specified other than "name".
          - It can only be deleted as an individual option if it is the only option specified.
          - If other options are specified for deletion, the entire user instance is deleted.
        type: str
  state:
    description:
      - Specifies the operation to be performed on the users configured on the device.
      - In case of merged, the input configuration will be merged with the existing users configuration on the device.
      - In case of deleted the existing users configuration will be removed from the device.
      - In case of replaced, the existing specified user configuration will be replaced with provided configuration.
      - In case of overridden, the existing users configuration will be overridden with the provided configuration.
    default: merged
    choices: ['merged', 'deleted', 'overridden', 'replaced']
    type: str
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show users configured
# ----------------------------------------------------------------------
# User                              Role(s)
# ----------------------------------------------------------------------
# admin                             admin
# sysadmin                          admin
# sysoperator                       operator

- name: Delete user
  dellemc.enterprise_sonic.sonic_users:
    config:
      - name: sysoperator
    state: deleted

# After state:
# ------------
#
# sonic# show users configured
# ----------------------------------------------------------------------
# User                              Role(s)
# ----------------------------------------------------------------------
# admin                             admin
# sysadmin                          admin

# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show users configured
# ----------------------------------------------------------------------
# User                              Role(s)
# ----------------------------------------------------------------------
# admin                             admin
# sysadmin                          admin
# sysoperator                       operator

- name: Delete all users configurations except admin
  dellemc.enterprise_sonic.sonic_users:
    config:
    state: deleted

# After state:
# ------------
#
# sonic# show users configured
# ----------------------------------------------------------------------
# User                              Role(s)
# ----------------------------------------------------------------------
# admin                             admin

# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show users configured
# ----------------------------------------------------------------------
# User                              Role(s)
# ----------------------------------------------------------------------
# admin                             admin

- name: Merge users configurations
  dellemc.enterprise_sonic.sonic_users:
    config:
      - name: sysadmin
        role: admin
        password: admin
        update_password: always
      - name: sysoperator
        role: operator
        password: operator
        update_password: always
    state: merged

# After state:
# ------------
#
# sonic# show users configured
# ----------------------------------------------------------------------
# User                              Role(s)
# ----------------------------------------------------------------------
# admin                             admin
# sysadmin                          admin
# sysoperator                       operator

# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show users configured
# ----------------------------------------------------------------------
# User                              Role(s)
# ----------------------------------------------------------------------
# admin                             admin
# sysadmin                          admin
# sysoperator                       operator

- name: Override users configurations
  dellemc.enterprise_sonic.sonic_users:
    config:
      - name: user1
        role: secadmin
        password: 123abc
        update_password: always
    state: overridden

# After state:
# ------------
#
# sonic# show users configured
# ----------------------------------------------------------------------
# User                              Role(s)
# ----------------------------------------------------------------------
# admin                             admin
# user1                             secadmin

# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show users configured
# ----------------------------------------------------------------------
# User                              Role(s)
# ----------------------------------------------------------------------
# admin                             admin
# user1                             secadmin
# user2                             operator

- name: Replace users configurations
  dellemc.enterprise_sonic.sonic_users:
    config:
      - name: user1
        role: operator
        password: 123abc
        update_password: always
      - name: user2
        role: netadmin
        password: 123abc
        update_password: always
    state: replaced

# After state:
# ------------
#
# sonic# show users configured
# ----------------------------------------------------------------------
# User                              Role(s)
# ----------------------------------------------------------------------
# admin                             admin
# user1                             operator
# user2                             netadmin

# Using Merged
#
# Before state:
# -------------
#
# sonic# show users sshkey
#
# sonic# show users configured
# --------------------------------------------------------------------
# User                           Role(s)
# --------------------------------------------------------------------
# admin                          admin
# user1                          operator
# user2                          netadmin

- name: Configure user sshkey
  dellemc.enterprise_sonic.sonic_users:
    config:
      - name: user1
        ssh_key: >
          ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCoCc6lPgrSAXZByJAPH6cwn0Mhj9J1zYUfiLc
          /iz/IwHt/7s++bN1tnL6bAan6Ssg4XvOF0mcP5K53AAP+bX5WHy/d1wm7icllBI0JT150qp9nY5y
          bjNdvLH11cxqc+mmNYa7d40fpeoUgMdSBGtSL0jY2PHHRCvVscFYjSm6tQQ== root@sonic
    state: merged

# After state:
# ------------
#
# sonic# show users configured
# ----------------------------------------------------------------------
# sonic# show users sshKey
# User: user1
# SSH Key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCoCc6lPgrSAXZByJAPH6cwn0Mhj9J1zYUfiLc/iz/IwHt/7s
#          ++bN1tnL6bAan6Ssg4XvOF0mcP5K53AAP+bX5WHy/d1wm7icllBI0JT150qp9nY5ybjNdvLH11cxqc+mmNYa7d
#          40fpeoUgMdSBGtSL0jY2PHHRCvVscFYjSm6tQQ== root@sonic
# ----------------------------------------------------------------------

# Using Deleted
#
# Before state:
# -------------
#
# sonic# show users sshKey
# User: user1
# SSH Key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDHD2TJqQ/Fve+fG5i6heOJH55wgbEf+7kTtUGBUtNttQ9OXgBRr
#          A2h2GKSyUNlyfaVijBrcr2MKwhSASvk58WnEqZhfmmhRDsdNVXPlMQuDBheIlCaXyOh+URJZCfmfeERSVO7kjRhqM
#          mbHlpTbMDHdFgYEvHGcrHMwIZyZ6KbBw== root@sonic
# ----------------------------------------------------------------------

- name: Delete sshkey for existing users
  dellemc.enterprise_sonic.sonic_users:
    config:
      - name: user1
        ssh_key:
    state: deleted

# After state:
# ------------
#
# sonic# show users sshkey
# ----------------------------------------------------------------------
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.users.users import UsersArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.users.users import Users


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=UsersArgs.argument_spec,
                           supports_check_mode=True)

    result = Users(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
