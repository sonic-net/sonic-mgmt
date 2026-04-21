#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: storagebox
short_description: Modify a storage box's basic configuration
version_added: 2.1.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Modify a storage box's basic configuration.
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
    support: full
  diff_mode:
    support: full
  idempotent:
    support: full

options:
  hetzner_token:
    version_added: 2.5.0
  id:
    description:
      - The ID of the storage box to modify.
    type: int
    required: true
  name:
    description:
      - The name of the storage box.
    type: str
  samba:
    description:
      - Whether the storage box is accessible through SAMBA.
    type: bool
  webdav:
    description:
      - Whether the storage box is accessible through WebDAV.
    type: bool
  ssh:
    description:
      - Whether the storage box is accessible through SSH.
    type: bool
  external_reachability:
    description:
      - Whether the storage box is externally reachable.
    type: bool
  zfs:
    description:
      - Whether the ZFS directory is visible.
    type: bool
"""

EXAMPLES = r"""
---
- name: Setup storagebox
  community.hrobot.storagebox:
    hetzner_user: foo
    hetzner_password: bar
    name: "My storage box"
    ssh: true
    samba: false
    webdav: false
    external_reachability: false
    zfs: false
"""

RETURN = r"""
name:
  description:
    - The storage box's name.
  type: str
  sample: Backup Server 1
  returned: success
webdav:
  description:
    - Whether WebDAV is active.
  type: bool
  sample: true
  returned: success
samba:
  description:
    - Whether SAMBA is active.
  type: bool
  sample: true
  returned: success
ssh:
  description:
    - Whether SSH is active.
  type: bool
  sample: true
  returned: success
external_reachability:
  description:
    - Whether the storage box is reachable externally.
  type: bool
  sample: true
  returned: success
zfs:
  description:
    - Shows whether the ZFS directory is visible.
  type: bool
  sample: false
  returned: success
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

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
    api_fetch_url_json,
)

try:
    from urllib.parse import urlencode
except ImportError:
    # Python 2.x fallback:
    from urllib import urlencode


PARAMETERS_LEGACY = {
    'name': ('name', 'storagebox_name'),
    'webdav': ('webdav', 'webdav'),
    'samba': ('samba', 'samba'),
    'ssh': ('ssh', 'ssh'),
    'external_reachability': ('external_reachability', 'external_reachability'),
    'zfs': ('zfs', 'zfs'),
}

UPDATE_PARAMETERS = {
    'name': ('name', ['name'], 'name'),
}

ACTION_PARAMETERS = {
    'webdav': ('webdav', ['access_settings', 'webdav_enabled'], 'webdav_enabled'),
    'samba': ('samba', ['access_settings', 'samba_enabled'], 'samba_enabled'),
    'ssh': ('ssh', ['access_settings', 'ssh_enabled'], 'ssh_enabled'),
    'external_reachability': ('external_reachability', ['access_settings', 'reachable_externally'], 'reachable_externally'),
    'zfs': ('zfs', ['access_settings', 'zfs_enabled'], 'zfs_enabled'),
}

PARAMETERS = dict(UPDATE_PARAMETERS)
PARAMETERS.update(ACTION_PARAMETERS)


def extract_legacy(result):
    sb = result['storagebox']
    return {key: sb.get(key) for key, dummy in PARAMETERS_LEGACY.values()}


def extract(result):
    sb = result['storage_box']

    def get(keys):
        value = sb
        for key in keys:
            value = value[key]
        return value

    return {data_key: get(keys) for data_key, keys, dummy2 in PARAMETERS.values()}


def main():
    argument_spec = dict(
        id=dict(type='int', required=True),
        name=dict(type='str'),
        samba=dict(type='bool'),
        webdav=dict(type='bool'),
        ssh=dict(type='bool'),
        external_reachability=dict(type='bool'),
        zfs=dict(type='bool'),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    argument_spec.update(_ROBOT_DEFAULT_ARGUMENT_SPEC_COMPAT_DEPRECATED)
    argument_spec.update(API_DEFAULT_ARGUMENT_SPEC)
    argument_spec.update(_API_DEFAULT_ARGUMENT_SPEC_COMPAT)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=[("hetzner_user", "hetzner_password")],
        required_one_of=[("hetzner_user", "hetzner_token")],
        mutually_exclusive=[("hetzner_user", "hetzner_token")],
    )

    storagebox_id = module.params['id']
    before = {}
    after = {}
    changes = {}

    if module.params["hetzner_user"] is not None:
        module.deprecate(
            "The hetzner_token parameter will be required from community.hrobot 3.0.0 on.",
            collection_name="community.hrobot",
            version="3.0.0",
        )
        # DEPRECATED: old API
        url = "{0}/storagebox/{1}".format(BASE_URL, storagebox_id)
        result, error = fetch_url_json(module, url, accept_errors=['STORAGEBOX_NOT_FOUND'])
        if error:
            module.fail_json(msg='Storagebox with ID {0} does not exist'.format(storagebox_id))

        before = extract_legacy(result)
        after = dict(before)

        for option_name, (data_name, change_name) in PARAMETERS_LEGACY.items():
            value = module.params[option_name]
            if value is not None:
                if before[data_name] != value:
                    after[data_name] = value
                    if isinstance(value, bool):
                        changes[change_name] = str(value).lower()
                    else:
                        changes[change_name] = value

        if changes and not module.check_mode:
            headers = {"Content-type": "application/x-www-form-urlencoded"}
            result, error = fetch_url_json(
                module,
                url,
                data=urlencode(changes),
                headers=headers,
                method='POST',
                accept_errors=['INVALID_INPUT'],
            )
            if error:
                invalid = result['error'].get('invalid') or []
                module.fail_json(msg='The values to update were invalid ({0})'.format(', '.join(invalid)))
            after = extract_legacy(result)

    else:
        # NEW API!
        url = "{0}/v1/storage_boxes/{1}".format(API_BASE_URL, storagebox_id)
        result, dummy, error = api_fetch_url_json(module, url, accept_errors=['not_found'])
        if error:
            module.fail_json(msg='Storagebox with ID {0} does not exist'.format(storagebox_id))

        before = extract(result)
        after = dict(before)

        update = {}
        for option_name, (data_name, dummy, change_name) in UPDATE_PARAMETERS.items():
            value = module.params[option_name]
            if value is not None:
                if before[data_name] != value:
                    after[data_name] = value
                    changes[change_name] = value
                    update[change_name] = value

        action = {}
        update_after_update = {}
        for option_name, (data_name, dummy, change_name) in ACTION_PARAMETERS.items():
            value = module.params[option_name]
            if value is not None:
                if before[data_name] != value:
                    after[data_name] = value
                    update_after_update[data_name] = value
                    changes[change_name] = value
                    action[change_name] = value

        if update and not module.check_mode:
            headers = {"Content-type": "application/json"}
            result, dummy, error = api_fetch_url_json(
                module,
                url,
                data=module.jsonify(update),
                headers=headers,
                method='PUT',
                accept_errors=['invalid_input'],
            )
            if error:
                details = result['error'].get('details') or {}
                fields = details.get("fields") or []
                details_str = ", ".join(['{0}: {1}'.format(to_native(field["name"]), to_native(field["message"])) for field in fields])
                module.fail_json(msg='The values to update were invalid ({0})'.format(details_str or "no details"))
            after = extract(result)

        if action and not module.check_mode:
            after.update(update_after_update)
            action_url = "{0}/actions/update_access_settings".format(url)
            try:
                api_apply_action(
                    module,
                    action_url,
                    action,
                    lambda action_id: "{0}/v1/storage_boxes/actions/{1}".format(API_BASE_URL, action_id),
                    check_done_delay=1,
                    check_done_timeout=60,
                )
            except ApplyActionError as exc:
                module.fail_json(msg='Error while updating access settings: {0}'.format(exc))

    result = dict(after)
    result['changed'] = bool(changes)
    result['diff'] = {
        'before': before,
        'after': after,
    }
    module.exit_json(**result)


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
