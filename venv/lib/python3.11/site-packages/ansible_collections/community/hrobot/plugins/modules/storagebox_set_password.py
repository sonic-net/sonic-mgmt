#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
module: storagebox_set_password
short_description: (Re)set the password for a storage box
version_added: 2.1.0
author:
  - Matthias Hurdebise (@matthiashurdebise)
description:
  - (Re)set the password for a storage box.
extends_documentation_fragment:
  - community.hrobot.api._robot_compat_shim_deprecation  # must come before api and robot
  - community.hrobot.api
  - community.hrobot.robot
  - community.hrobot.attributes
  - community.hrobot.attributes._actiongroup_robot_and_api_deprecation  # must come before the other two!
  - community.hrobot.attributes.actiongroup_api
  - community.hrobot.attributes.actiongroup_robot

attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
  idempotent:
    support: none
    details:
      - This module performs an action on every invocation.

options:
  hetzner_token:
    version_added: 2.5.0
  id:
    description:
      - The ID of the storage box to modify.
    type: int
    required: true
  password:
    description:
      - The new password for the storage box.
      - If not provided, a random password will be created by the Robot API
        and returned as RV(password).
      - This option is required if O(hetzner_token) is provided, since the new API does not support setting (and returning) a random password.
    type: str
"""

EXAMPLES = r"""
---
- name: Set the password
  community.hrobot.storagebox_set_password:
    id: 123
    password: "newpassword"

- name: Set a random password (only works with the legacy Robot API)
  community.hrobot.storagebox_set_password:
    id: 123
  register: result

- name: Output new password
  ansible.builtin.debug:
    msg: "New password: {{ result.password }}"
"""

RETURN = r"""
password:
  description:
    - The new password for the storage box.
    - Note that if the password has been provided as O(password), Ansible will censor this return value to something
      like C(VALUE_SPECIFIED_IN_NO_LOG_PARAMETER).
  returned: success
  type: str
  sample: "newpassword"
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    BASE_URL,
    ROBOT_DEFAULT_ARGUMENT_SPEC,
    _ROBOT_DEFAULT_ARGUMENT_SPEC_COMPAT_DEPRECATED,
    fetch_url_json,
)

from ansible_collections.community.hrobot.plugins.module_utils.api import (
    API_BASE_URL,
    API_DEFAULT_ARGUMENT_SPEC,
    _API_DEFAULT_ARGUMENT_SPEC_COMPAT,
    ApplyActionError,
    api_apply_action,
)

try:
    from urllib.parse import urlencode
except ImportError:
    # Python 2.x fallback:
    from urllib import urlencode


def main():
    argument_spec = dict(
        id=dict(type="int", required=True),
        password=dict(type="str", no_log=True),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    argument_spec.update(_ROBOT_DEFAULT_ARGUMENT_SPEC_COMPAT_DEPRECATED)
    argument_spec.update(API_DEFAULT_ARGUMENT_SPEC)
    argument_spec.update(_API_DEFAULT_ARGUMENT_SPEC_COMPAT)
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=False,
        required_by={"hetzner_token": "password"},
    )

    id = module.params["id"]
    password = module.params.get("password")

    if module.params["hetzner_user"] is not None:
        module.deprecate(
            "The hetzner_token parameter will be required from community.hrobot 3.0.0 on.",
            collection_name="community.hrobot",
            version="3.0.0",
        )
        # DEPRECATED: old API
        url = "{0}/storagebox/{1}/password".format(BASE_URL, id)
        accepted_errors = ["STORAGEBOX_NOT_FOUND", "STORAGEBOX_INVALID_PASSWORD"]

        if password:
            headers = {"Content-type": "application/x-www-form-urlencoded"}
            result, error = fetch_url_json(
                module, url, method="POST", accept_errors=accepted_errors, data=urlencode({"password": password}), headers=headers)
        else:
            result, error = fetch_url_json(
                module, url, method="POST", accept_errors=accepted_errors)

        if error == 'STORAGEBOX_NOT_FOUND':
            module.fail_json(
                msg='Storage Box with ID {0} not found'.format(id))

        if error == 'STORAGEBOX_INVALID_PASSWORD':
            module.fail_json(
                msg="The chosen password has been considered insecure or does not comply with Hetzner's password guideline")

        module.exit_json(changed=True, password=result["password"])

    else:
        # NEW API!
        action_url = "{0}/v1/storage_boxes/{1}/actions/reset_password".format(API_BASE_URL, id)
        action = {
            "password": password,
        }
        try:
            dummy, error = api_apply_action(
                module,
                action_url,
                action,
                lambda action_id: "{0}/v1/storage_boxes/actions/{1}".format(API_BASE_URL, action_id),
                check_done_delay=1,
                check_done_timeout=60,
                accept_errors=["not_found"],
            )
        except ApplyActionError as exc:
            module.fail_json(msg='Error while resetting password: {0}'.format(exc))

        if error == "not_found":
            module.fail_json(msg='Storage Box with ID {0} not found'.format(id))

        module.exit_json(changed=True, password=password)


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
