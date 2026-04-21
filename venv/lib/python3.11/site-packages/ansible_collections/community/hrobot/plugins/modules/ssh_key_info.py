#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: ssh_key_info
short_description: Query information on SSH keys
version_added: 1.2.0
author:
  - Felix Fontein (@felixfontein)
description:
  - List information on all your SSH keys stored in Hetzner's Robot.
seealso:
  - module: community.hrobot.ssh_key
    description: Add, remove or update SSH key.
extends_documentation_fragment:
  - community.hrobot.robot
  - community.hrobot.attributes
  - community.hrobot.attributes.actiongroup_robot
  - community.hrobot.attributes.idempotent_not_modify_state
  - community.hrobot.attributes.info_module
attributes:
  action_group:
    version_added: 1.6.0
"""

EXAMPLES = r"""
---
- name: List all SSH keys
  community.hrobot.ssh_key_info:
    hetzner_user: foo
    hetzner_password: bar
  register: ssh_keys

- name: Show how many keys were found
  ansible.builtin.debug:
    msg: "Found {{ ssh_keys.ssh_keys | length }} keys"
"""

RETURN = r"""
ssh_keys:
  description:
    - The list of all SSH keys stored in Hetzner's Robot for your user.
  returned: success
  type: list
  elements: dict
  contains:
    name:
      description:
        - The key's name shown in the UI.
      type: str
      sample: key1
    fingerprint:
      description:
        - The key's MD5 fingerprint.
      type: str
      sample: 56:29:99:a4:5d:ed:ac:95:c1:f5:88:82:90:5d:dd:10
    type:
      description:
        - The key's algorithm type.
      type: str
      sample: ECDSA
    size:
      description:
        - The key's size in bits.
      type: int
      sample: 521
    data:
      description:
        - The key data in OpenSSH's format.
      type: str
      sample: ecdsa-sha2-nistp521 AAAAE2VjZHNh ...
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    BASE_URL,
    ROBOT_DEFAULT_ARGUMENT_SPEC,
    fetch_url_json,
)


def main():
    argument_spec = dict()
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    url = "{0}/key".format(BASE_URL)
    result, error = fetch_url_json(module, url, accept_errors=['NOT_FOUND'])
    if error == 'NOT_FOUND':
        result = []
    elif error is not None:
        raise AssertionError('Unexpected error {0}'.format(error))  # pragma: no cover

    keys = []
    for key in result:
        keys.append(key['key'])

    module.exit_json(changed=False, ssh_keys=keys)


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
