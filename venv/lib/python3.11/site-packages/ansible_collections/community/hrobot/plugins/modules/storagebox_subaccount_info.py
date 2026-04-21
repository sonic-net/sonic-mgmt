#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Victor LEFEBVRE <dev@vic1707.xyz>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
module: storagebox_subaccount_info
short_description: Query the subaccounts for a storage box
version_added: 2.4.0
author:
  - Victor LEFEBVRE (@vic1707)
description:
  - Query the subaccounts for a storage box.
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
- name: Query the subaccounts
  community.hrobot.storagebox_subaccount_info:
    hetzner_user: foo
    hetzner_password: bar
    storage_box_id: 123
  register: result

- name: Output data
  ansible.builtin.debug:
    msg: "Username of the first subaccount: {{ result.subaccounts[0].username }}"
"""

RETURN = r"""
subaccounts:
  description:
    - The storage box's info.
    - All date and time parameters are in UTC.
  returned: success
  type: list
  elements: dict
  contains:
    username:
      description:
        - Username of the sub-account.
      type: str
      sample: "u2342-sub1"
      returned: success
    accountid:
      description:
        - Username of the main user.
        - Not supported by the new Hetzner API.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: str
      sample: "u2342"
      returned: success and if O(hetzner_token) is not specified
    server:
      description:
        - Server on which the sub-account resides.
      type: str
      sample: "sb1234.your-storagebox.de"
      returned: success
    homedirectory:
      description:
        - Homedirectory of the sub-account.
        - Note that this is copied from RV(subaccounts[].home_directory) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: str
      sample: "/home/u2342-sub1"
      returned: success
    samba:
      description:
        - Status of Samba support.
        - Note that this is copied from RV(subaccounts[].access_settings.samba_enabled) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: bool
      sample: true
      returned: success
    ssh:
      description:
        - Status of SSH support.
        - Note that this is copied from RV(subaccounts[].access_settings.ssh_enabled) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: bool
      sample: true
      returned: success
    external_reachability:
      description:
        - Status of external reachability.
        - Note that this is copied from RV(subaccounts[].access_settings.reachable_externally) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: bool
      sample: false
      returned: success
    webdav:
      description:
        - Status of WebDAV support.
        - Note that this is copied from RV(subaccounts[].access_settings.webdav_enabled) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: bool
      sample: true
      returned: success
    readonly:
      description:
        - Indicates if the sub-account is in readonly mode.
        - Note that this is copied from RV(subaccounts[].access_settings.readonly) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: bool
      sample: false
      returned: success
    createtime:
      description:
        - Timestamp when the sub-account was created.
        - Note that this is copied from RV(subaccounts[].created) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: str
      sample: "2023-08-25T14:23:05Z"
      returned: success
    comment:
      description:
        - Custom comment for the sub-account.
        - Note that this is copied from RV(subaccounts[].description) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: str
      sample: "This is a subaccount"
      returned: success
    id:
      description:
        - The subaccount's ID.
      type: int
      sample: 42
      version_added: 2.5.0
    home_directory:
      description:
        - Home directory of the subaccount.
      type: str
      sample: "my_backups/host01.my.company"
      version_added: 2.5.0
    access_settings:
      description:
        - Access settings of the subaccount.
      type: dict
      version_added: 2.5.0
      contains:
        samba_enabled:
          description:
            - Whether the subaccount can be accessed through SAMBA.
          type: bool
          sample: false
        ssh_enabled:
          description:
            - Whether the subaccount can be accessed through SSH.
          type: bool
          sample: true
        webdav_enabled:
          description:
            - Whether the subaccount can be accessed through WebDAV.
          type: bool
          sample: false
        reachable_externally:
          description:
            - Whether the subaccount is reachable from outside Hetzner's network.
          type: bool
          sample: true
        readonly:
          description:
            - Whether the subaccount is read-only.
          type: bool
          sample: false
    description:
      description:
        - A user-defined description for the subaccount.
      type: str
      sample: "host01 backup"
      version_added: 2.5.0
    created:
      description:
        - Creation timestamp in ISO-8601 format.
      type: str
      sample: "2025-02-22:00:02.000Z"
      version_added: 2.5.0
    labels:
      description:
        - User-defined labels for the subaccount.
      type: dict
      version_added: 2.5.0
    storage_box:
      description:
        - The associated storage box's ID.
      type: int
      sample: 42
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


def adjust_legacy(subaccount):
    result = dict(subaccount)
    result['homedirectory'] = deprecate_value(
        subaccount['home_directory'],
        "The return value `homedirectory` is deprecated; use `home_directory` instead.",
        version="3.0.0",
    )
    result['samba'] = deprecate_value(
        subaccount['access_settings']['samba_enabled'],
        "The return value `samba` is deprecated; use `access_settings.samba_enabled` instead.",
        version="3.0.0",
    )
    result['ssh'] = deprecate_value(
        subaccount['access_settings']['ssh_enabled'],
        "The return value `ssh` is deprecated; use `access_settings.ssh_enabled` instead.",
        version="3.0.0",
    )
    result['webdav'] = deprecate_value(
        subaccount['access_settings']['webdav_enabled'],
        "The return value `webdav` is deprecated; use `access_settings.webdav_enabled` instead.",
        version="3.0.0",
    )
    result['external_reachability'] = deprecate_value(
        subaccount['access_settings']['reachable_externally'],
        "The return value `external_reachability` is deprecated; use `access_settings.reachable_externally` instead.",
        version="3.0.0",
    )
    result['readonly'] = deprecate_value(
        subaccount['access_settings']['readonly'],
        "The return value `readonly` is deprecated; use `access_settings.readonly` instead.",
        version="3.0.0",
    )
    result['createtime'] = deprecate_value(
        subaccount['created'],
        "The return value `createtime` is deprecated; use `created` instead.",
        version="3.0.0",
    )
    result['comment'] = deprecate_value(
        subaccount['description'],
        "The return value `comment` is deprecated; use `description` instead.",
        version="3.0.0",
    )
    return result


def main():
    argument_spec = dict(
        storagebox_id=dict(type="int", required=True),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    argument_spec.update(_ROBOT_DEFAULT_ARGUMENT_SPEC_COMPAT_DEPRECATED)
    argument_spec.update(API_DEFAULT_ARGUMENT_SPEC)
    argument_spec.update(_API_DEFAULT_ARGUMENT_SPEC_COMPAT)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    storagebox_id = module.params["storagebox_id"]

    if module.params["hetzner_user"] is not None:
        module.deprecate(
            "The hetzner_token parameter will be required from community.hrobot 3.0.0 on.",
            collection_name="community.hrobot",
            version="3.0.0",
        )
        # DEPRECATED: old API

        url = "{0}/storagebox/{1}/subaccount".format(BASE_URL, storagebox_id)
        result, error = fetch_url_json(module, url, accept_errors=["STORAGEBOX_NOT_FOUND"])
        if error:
            module.fail_json(
                msg="Storagebox with ID {0} does not exist".format(storagebox_id)
            )

        module.exit_json(
            changed=False,
            subaccounts=[item["subaccount"] for item in result],
        )

    else:
        # NEW API!

        url = "{0}/v1/storage_boxes/{1}/subaccounts".format(API_BASE_URL, storagebox_id)
        result, dummy, error = api_fetch_url_json(module, url, accept_errors=['not_found'])
        if error:
            module.fail_json(msg='Storagebox with ID {0} does not exist'.format(storagebox_id))

        module.exit_json(
            changed=False,
            subaccounts=[adjust_legacy(item) for item in result['subaccounts']],
        )


if __name__ == "__main__":  # pragma: no cover
    main()  # pragma: no cover
