#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: storagebox_snapshot_plan_info
short_description: Query the snapshot plans for a storage box
version_added: 2.1.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Query the snapshot plans for a storage box.
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
- name: Query the snapshot plans
  community.hrobot.storagebox_snapshot_plan_info:
    hetzner_user: foo
    hetzner_password: bar
    id: 123
  register: result

- name: Output data
  ansible.builtin.debug:
    msg: "Status of the first snapshot plan: {{ result.plans[0].status }}"
"""

RETURN = r"""
plans:
  description:
    - The storage box's snapshot plan configurations.
    - All date and time parameters are in UTC.
  returned: success
  type: list
  elements: dict
  contains:
    status:
      description:
        - The status of the snapshot plan.
      type: str
      sample: enabled
      returned: success
      choices:
        - enabled
        - disabled
    minute:
      description:
        - The minute of execution of the plan.
      type: int
      sample: 5
      returned: success
    hour:
      description:
        - The hour of execution of the plan.
      type: int
      sample: 12
      returned: success
    day_of_week:
      description:
        - The day of the week of execution of the plan. V(1) is Monday, V(7) is Sunday.
        - If set to V(null), the plan is run every day of a week, unless there are other restrictions.
      type: int
      sample: 2
      returned: success
    day_of_month:
      description:
        - The day of month of execution of the plan. V(1) is the 1st day of the month.
        - If set to V(null), the plan is run every day of a month, unless there are other restrictions.
      type: int
      sample: null
      returned: success
    month:
      description:
        - The month of execution of the plan. V(1) is January, V(12) is December.
        - If set to V(null), the plan is run every month.
        - Always V(null) if O(hetzner_token) is provided.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: int
      sample: null
      returned: success
    max_snapshots:
      description:
        - The maximum number of automatic snapshots of this plan.
      type: int
      sample: 2
      returned: success
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


def extract_legacy(result):
    sb = result['snapshotplan']
    return {
        'status': sb['status'],
        'minute': sb['minute'],
        'hour': sb['hour'],
        'day_of_week': sb['day_of_week'],
        'day_of_month': sb['day_of_month'],
        'month': sb['month'],
        'max_snapshots': sb['max_snapshots'],
    }


def extract(result):
    sb = result['storage_box']
    sp = sb.get('snapshot_plan')
    if not sp:
        return {
            'status': 'disabled',
            'minute': None,
            'hour': None,
            'day_of_week': None,
            'day_of_month': None,
            'month': deprecate_value(None, "The return value `month` is deprecated; it is always null.", version="3.0.0"),
            'max_snapshots': None,
        }

    return {
        'status': 'enabled',
        'minute': sp['minute'],
        'hour': sp['hour'],
        'day_of_week': sp['day_of_week'],
        'day_of_month': sp['day_of_month'],
        'month': deprecate_value(None, "The return value `month` is deprecated; it is always null.", version="3.0.0"),
        'max_snapshots': sp['max_snapshots'],
    }


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
        url = "{0}/storagebox/{1}/snapshotplan".format(BASE_URL, storagebox_id)
        result, error = fetch_url_json(module, url, accept_errors=['STORAGEBOX_NOT_FOUND'])
        if error:
            module.fail_json(msg='Storagebox with ID {0} does not exist'.format(storagebox_id))

        # The documentation (https://robot.hetzner.com/doc/webservice/en.html#get-storagebox-storagebox-id-snapshotplan)
        # claims that the result is a list, but actually it is a dictionary. Convert it to a list of dicts if that's the case.
        if isinstance(result, dict):
            result = [result]

        plans = [extract_legacy(plan) for plan in result]

    else:
        # NEW API!
        url = "{0}/v1/storage_boxes/{1}".format(API_BASE_URL, storagebox_id)
        result, dummy, error = api_fetch_url_json(module, url, accept_errors=["not_found"])
        if error:
            module.fail_json(msg='Storagebox with ID {0} does not exist'.format(storagebox_id))

        plans = [extract(result)]

    module.exit_json(
        changed=False,
        plans=plans,
    )


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
