#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Matthias Hurdebise <matthias_hurdebise@hotmail.fr>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: storagebox_snapshot_info
short_description: Query the snapshots for a storage box
version_added: 2.4.0
author:
  - Matthias Hurdebise (@matthiashurdebise)
description:
  - Query the snapshots for a storage box.
extends_documentation_fragment:
  - community.hrobot.api._robot_compat_shim_deprecation  # must come before api and robot
  - community.hrobot.api
  - community.hrobot.robot
  - community.hrobot.attributes
  - community.hrobot.attributes._actiongroup_robot_and_api_deprecation  # must come before the other two!
  - community.hrobot.attributes.actiongroup_api
  - community.hrobot.attributes.actiongroup_robot
  - community.hrobot.attributes.idempotent_not_modify_state
  - community.hrobot.attributes.info_module

options:
  hetzner_token:
    version_added: 2.5.0
  storagebox_id:
    description:
      - The ID of the storage box to query.
    type: int
    required: true
"""

EXAMPLES = r"""
---
- name: Query the snapshots
  community.hrobot.storagebox_snapshot_info:
    hetzner_user: foo
    hetzner_password: bar
    id: 123
  register: result

- name: Output data
  ansible.builtin.debug:
    msg: "Timestamp of the first snapshot : {{ result.snapshots[0].timestamp }}"
"""

RETURN = r"""
snapshots:
  description:
    - The storage box's info.
    - All date and time parameters are in UTC.
  returned: success
  type: list
  elements: dict
  contains:
    name:
      description:
        - The snapshot name.
      type: str
      sample: "2025-01-21T12-40-38"
      returned: success
    timestamp:
      description:
        - The timestamp of snapshot in UTC.
        - Note that this is copied from RV(snapshots[].created) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: str
      sample: "2025-01-21T13:40:38+00:00"
      returned: success
    size:
      description:
        - The Snapshot size in MB.
        - Note that this is copied from RV(snapshots[].stats.size) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: int
      sample: 400
      returned: success
    filesystem_size:
      description:
        - The size of the Storage Box at creation time of the snapshot in MB.
        - Note that this is computed from RV(snapshots[].stats.size_filesystem) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: int
      sample: 12345
      returned: success
    automatic:
      description:
        - Whether the snapshot was created automatically.
        - Note that this is computed from RV(snapshots[].is_automatic) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: bool
      sample: false
      returned: success
    comment:
      description:
        - The comment for the snapshot.
        - Note that this is copied from RV(snapshots[].description) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: str
      sample: "This is a snapshot"
      returned: success
    id:
      description:
        - The snapshot's ID.
      type: int
      sample: 1
      returned: success and O(hetzner_token) is specified
      version_added: 2.5.0
    stats:
      description:
        - Statistics about the snapshot.
      type: dict
      returned: success and O(hetzner_token) is specified
      version_added: 2.5.0
      contains:
        size:
          description:
            - Total size of the snapshot in bytes.
          type: int
          sample: 2097152
        size_filesystem:
          description:
            - Actual size of the snapshot on the filesystem in bytes (after deduplication).
          type: int
          sample: 1048576
    is_automatic:
      description:
        - Whether the snapshot was created automatically.
      type: bool
      sample: true
      returned: success and O(hetzner_token) is specified
      version_added: 2.5.0
    description:
      description:
        - The snapshot's description (used to be called comment in the Robot API).
      type: int
      sample: my-description
      returned: success and O(hetzner_token) is specified
      version_added: 2.5.0
    created:
      description:
        - The creation timestamp of snapshot in UTC, in ISO-8601 format.
      type: int
      sample: "2016-01-30T23:55:00+00:00"
      returned: success and O(hetzner_token) is specified
      version_added: 2.5.0
    storage_box:
      description:
        - ID of the associated storage box.
      type: int
      sample: 42
      returned: success and O(hetzner_token) is specified
      version_added: 2.5.0
    labels:
      description:
        - User-defined labels for the snapshot.
      type: dict
      returned: success and O(hetzner_token) is specified
      version_added: 2.5.0
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
    api_fetch_url_json,
)

from ansible_collections.community.hrobot.plugins.module_utils._tagging import (
    deprecate_value,
)


def adjust_legacy(snapshot):
    result = dict(snapshot)
    result["timestamp"] = deprecate_value(
        result["created"],
        "The return value `timestamp` is deprecated; use `created` instead.",
        version="3.0.0",
    )
    result["size"] = deprecate_value(
        result["stats"]["size"] // (1024 * 1024),
        "The return value `size` is deprecated; use `stats.size / (1024*1024)` instead.",
        version="3.0.0",
    )
    result["filesystem_size"] = deprecate_value(
        result["stats"]["size_filesystem"] // (1024 * 1024),
        "The return value `filesystem_size` is deprecated; use `stats.size_filesystem / (1024*1024)` instead.",
        version="3.0.0",
    )
    result["automatic"] = deprecate_value(
        result["is_automatic"],
        "The return value `automatic` is deprecated; use `is_automatic` instead.",
        version="3.0.0",
    )
    result["comment"] = deprecate_value(
        result["description"],
        "The return value `comment` is deprecated; use `description` instead.",
        version="3.0.0",
    )
    return result


def main():
    argument_spec = dict(
        storagebox_id=dict(type='int', required=True),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    argument_spec.update(_ROBOT_DEFAULT_ARGUMENT_SPEC_COMPAT_DEPRECATED)
    argument_spec.update(API_DEFAULT_ARGUMENT_SPEC)
    argument_spec.update(_API_DEFAULT_ARGUMENT_SPEC_COMPAT)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    storagebox_id = module.params['storagebox_id']

    if module.params["hetzner_user"] is not None:
        module.deprecate(
            "The hetzner_token parameter will be required from community.hrobot 3.0.0 on.",
            collection_name="community.hrobot",
            version="3.0.0",
        )
        # DEPRECATED: old API
        url = "{0}/storagebox/{1}/snapshot".format(BASE_URL, storagebox_id)
        result, error = fetch_url_json(module, url, accept_errors=['STORAGEBOX_NOT_FOUND'])
        if error:
            module.fail_json(msg='Storagebox with ID {0} does not exist'.format(storagebox_id))

        module.exit_json(
            changed=False,
            snapshots=[item['snapshot'] for item in result],
        )

    else:
        # NEW API!

        url = "{0}/v1/storage_boxes/{1}/snapshots".format(API_BASE_URL, storagebox_id)
        result, dummy, error = api_fetch_url_json(module, url, accept_errors=['not_found'])
        if error:
            module.fail_json(msg='Storagebox with ID {0} does not exist'.format(storagebox_id))

        module.exit_json(
            changed=False,
            snapshots=[adjust_legacy(item) for item in result['snapshots']],
        )


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
