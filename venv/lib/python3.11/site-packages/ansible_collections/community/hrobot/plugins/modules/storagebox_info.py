#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: storagebox_info
short_description: Query information on one or more storage boxes
version_added: 2.1.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Query information on one or more storage box.
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
      - Limit result list to storage boxes with this ID.
    type: int
  linked_server_number:
    description:
      - Limit result list to storage boxes linked to the server with this number.
      - Ignored when O(storagebox_id) has been specified, or when O(hetzner_token) has been specified.
    type: int
  full_info:
    description:
      - Whether to provide full information for every storage box.
      - Setting this to V(true) requires one REST call per storage box, which is slow and reduces your rate limit. Use with care.
      - When O(storagebox_id) is specified, this option is always treated as having value V(true).
      - B(Note) that this option has no effect if O(hetzner_token) is specified.
    type: bool
    default: false
"""

EXAMPLES = r"""
---
- name: Query a list of all storage boxes
  community.hrobot.storagebox_info:
    hetzner_user: foo
    hetzner_password: bar
  register: result

- name: Query a specific storage box
  community.hrobot.storagebox_info:
    hetzner_user: foo
    hetzner_password: bar
    storagebox_id: 23
  register: result

- name: Output data on specific storage box
  ansible.builtin.debug:
    msg: "Storage box name: {{ result.storageboxes[0].name }}"
"""

RETURN = r"""
storageboxes:
  description:
    - List of storage boxes matching the provided options.
  returned: success
  type: list
  elements: dict
  contains:
    id:
      description:
        - The storage box's ID.
      type: int
      sample: 123456
      returned: success
    login:
      description:
        - The storage box's login name.
        - Note that this is copied from RV(storageboxes[].username) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: str
      sample: u12345
      returned: success
    username:
      description:
        - The storage box's login name.
      type: str
      sample: u12345
      returned: success if O(hetzner_token) is specified.
      version_added: 2.5.0
    name:
      description:
        - The storage box's name.
      type: str
      sample: Backup Server 1
      returned: success and O(hetzner_user) is specified
    product:
      description:
        - The product name.
      type: str
      sample: BX60
      returned: success and O(hetzner_user) is specified
    cancelled:
      description:
        - Whether the storage box has been cancelled.
        - The cancellation can still be un-done until RV(storageboxes[].paid_until) has been exceeded.
      type: bool
      sample: false
      returned: success and O(hetzner_user) is specified
    locked:
      description:
        - Whether the IP is locked.
      type: bool
      sample: false
      returned: success and O(hetzner_user) is specified
    location:
      description:
        - The storage box's location.
        - This is a string if O(hetzner_user) is specified, and a dictionary if O(hetzner_token) is specified.
      type: raw
      sample: FSN1
      returned: success
#    location:
#      description:
#        - The storage box's location.
#      type: dict
#      returned: when O(hetzner_token) is specified
#      contains:
#        id:
#          description:
#            - The location's ID.
#          type: int
#          sample: 42
#          version_added: 2.5.0
#        name:
#          description:
#            - The location's name (unique identifier).
#          type: str
#          sample: "fsn1"
#          version_added: 2.5.0
#        description:
#          description:
#            - Human readable description of the location.
#          type: str
#          sample: "Falkenstein DC Park 1"
#          version_added: 2.5.0
#        country:
#          description:
#            - Country code (ISO 3166-1 alpha-2).
#          type: str
#          sample: "DE"
#          version_added: 2.5.0
#        city:
#          description:
#            - Closest city to the location.
#          type: str
#          sample: "Falkenstein"
#          version_added: 2.5.0
#        latitude:
#          description:
#            - Latitude of the closest city to the location.
#          type: float
#          sample: 50.47612
#          version_added: 2.5.0
#        longitude:
#          description:
#            - Longitude of the closest city to the location.
#          type: float
#          sample: 12.370071
#          version_added: 2.5.0
#        network_zone:
#          description:
#            - Name of the network zone the location is part of.
#          type: str
#          sample: "eu-central"
#          version_added: 2.5.0
    linked_server:
      description:
        - The ID (server number) of the connected server, if available. Is V(null) otherwise.
      type: int
      sample: 123456
      returned: success and O(hetzner_user) is specified
    paid_until:
      description:
        - The date until which the storage box has been paid for.
      type: str
      sample: "2015-10-23"
      returned: success and O(hetzner_user) is specified
    disk_quota:
      description:
        - Total amount of MB available.
        - Note that this is copied from RV(storageboxes[].storage_box_type.size) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: int
      sample: 10240000
      returned: when O(full_info=true), or O(hetzner_token) is specified
    disk_usage:
      description:
        - The amount of MB in use.
        - Note that this is copied from RV(storageboxes[].stats.size) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: int
      sample: 900
      returned: when O(full_info=true), or O(hetzner_token) is specified
    disk_usage_data:
      description:
        - The amount of MB used by files.
        - Note that this is copied from RV(storageboxes[].stats.size_data) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: int
      sample: 500
      returned: when O(full_info=true), or O(hetzner_token) is specified
    disk_usage_snapshots:
      description:
        - The amount of MB used by snapshots.
        - Note that this is copied from RV(storageboxes[].stats.size_snapshots) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: int
      sample: 400
      returned: when O(full_info=true), or O(hetzner_token) is specified
    webdav:
      description:
        - Whether WebDAV is active.
        - Note that this is copied from RV(storageboxes[].access_settings.webdav_enabled) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: bool
      sample: true
      returned: when O(full_info=true), or O(hetzner_token) is specified
    samba:
      description:
        - Whether SAMBA is active.
        - Note that this is copied from RV(storageboxes[].access_settings.samba_enabled) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: bool
      sample: true
      returned: when O(full_info=true), or O(hetzner_token) is specified
    ssh:
      description:
        - Whether SSH is active.
        - Note that this is copied from RV(storageboxes[].access_settings.ssh_enabled) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: bool
      sample: true
      returned: when O(full_info=true), or O(hetzner_token) is specified
    external_reachability:
      description:
        - Whether the storage box is reachable externally.
        - Note that this is copied from RV(storageboxes[].access_settings.reachable_externally) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: bool
      sample: true
      returned: when O(full_info=true), or O(hetzner_token) is specified
    zfs:
      description:
        - Shows whether the ZFS directory is visible.
        - Note that this is copied from RV(storageboxes[].access_settings.zfs_enabled) in case O(hetzner_token) is specified.
        - B(This return value is deprecated and will be removed from community.hrobot 3.0.0.)
          If you are using ansible-core 2.19 or newer, you will see a deprecation message when using this return value when using O(hetzner_token).
      type: bool
      sample: false
      returned: when O(full_info=true), or O(hetzner_token) is specified
    server:
      description:
        - The storage box's hostname.
      type: str
      sample: u12345.your-storagebox.de
      returned: when O(full_info=true); or O(hetzner_token) is specified and RV(storageboxes[].status) is not V(initializing)
    host_system:
      description:
        - Identifier of the storage box's host.
      type: str
      sample: FSN1-BX355
      returned: when O(full_info=true) and O(hetzner_user) is specified
    system:
      description:
        - Identifier of the storage box's host.
      type: str
      sample: FSN1-BX355
      returned: when O(hetzner_token) is specified and RV(storageboxes[].status) is not V(initializing)
      version_added: 2.5.0
    status:
      description:
        - Status of the storage box.
      type: str
      sample: active
      choices:
        - active
        - initializing
        - locked
      returned: when O(hetzner_token) is specified
      version_added: 2.5.0
    created:
      description:
        - Creation timestamp in ISO 8601 format.
      type: str
      sample: "2016-01-30T23:55:00+00:00"
      returned: when O(hetzner_token) is specified
      version_added: 2.5.0
    storage_box_type:
      description:
        - Information on the storage box's type.
      type: dict
      returned: when O(hetzner_token) is specified
      version_added: 2.5.0
      contains:
        name:
          description:
            - Identifier of the storage box's type.
          type: str
          sample: "bx11"
        description:
          description:
            - Description of the storage box's type.
          type: str
          sample: "BX11"
        snapshot_limit:
          description:
            - Maximum number of allowed manual snapshots.
          type: int
          sample: 10
        automatic_snapshot_limit:
          description:
            - Maximum number of snapshots created automatically by a snapshot plan.
          type: int
          sample: 10
        subaccounts_limit:
          description:
            - Maximum number of allowed subaccounts.
          type: int
          sample: 200
        size:
          description:
            - Available storage in bytes.
          type: int
          sample: 1073741824
        prices:
          description:
            - Price per location.
          type: list
          elements: dict
          contains:
            location:
              description:
                - Name of the location.
              type: str
              sample: "fsn1"
            price_hourly:
              description:
                - The hourly rate.
              type: dict
              contains:
                net:
                  description:
                    - Hourly price (without VAT).
                  type: str
                  sample: "1.0000"
                gross:
                  description:
                    - Hourly price (with VAT).
                  type: str
                  sample: "1.1900"
            price_monthly:
              description:
                - The monthly rate.
              type: dict
              contains:
                net:
                  description:
                    - Monthly price (without VAT).
                  type: str
                  sample: "1.0000"
                gross:
                  description:
                    - Monthly price (with VAT).
                  type: str
                  sample: "1.1900"
            setup_fee:
              description:
                - The setup fee.
              type: dict
              contains:
                net:
                  description:
                    - Setup fee (without VAT).
                  type: str
                  sample: "1.0000"
                gross:
                  description:
                    - Setup fee (with VAT).
                  type: str
                  sample: "1.1900"
        deprecation:
          description:
            - Set to V(none) (JSON V(null)) if the storage box's type is not deprecated.
            - If set to a dictionary, this storage box's type is deprecated.
          type: dict
          contains:
            unavailable_after:
              description:
                - ISO 8601 timestamp when the resource will be removed.
              type: str
              sample: "2023-09-01T00:00:00+00:00"
            announced:
              description:
                - ISO 8601 timestamp when the deprecation was announced.
              type: str
              sample: "2023-06-01T00:00:00+00:00"
    access_settings:
      description:
        - Access settings for the storage box.
      type: dict
      returned: when O(hetzner_token) is specified
      version_added: 2.5.0
      contains:
        reachable_externally:
          description:
            - Whether the storage box is accessible from outside Hetzner's network.
          type: bool
          sample: false
        samba_enabled:
          description:
            - Whether SAMBA is enabled.
          type: bool
          sample: false
        ssh_enabled:
          description:
            - Whether SSH is enabled.
          type: bool
          sample: false
        webdav_enabled:
          description:
            - Whether WebDAV is enabled.
          type: bool
          sample: false
        zfs_enabled:
          description:
            - Whether ZFS is enabled.
          type: bool
          sample: false
    stats:
      description:
        - Information on disk usage.
      type: dict
      returned: when O(hetzner_token) is specified and RV(storageboxes[].status) is not V(initializing)
      version_added: 2.5.0
      contains:
        size:
          description:
            - Current disk usage in bytes.
          type: int
          sample: 0
        size_data:
          description:
            - Current disk usage for data in bytes.
          type: int
          sample: 0
        size_snapshots:
          description:
            - Current disk usage for snapshots in bytes.
          type: int
          sample: 0
    labels:
      description:
        - User-defined labels for the storage box.
      type: dict
      returned: when O(hetzner_token) is specified
      version_added: 2.5.0
    protection:
      description:
        - Protection configuration for the storage box.
      type: dict
      returned: when O(hetzner_token) is specified
      version_added: 2.5.0
      contains:
        delete:
          description:
            - Whether deletion of the storage box is disabled.
          type: bool
          sample: false
    snapshot_plan:
      description:
        - The snapshot plan for the storage box.
        - Will be V(none) (JSON V(null)) if no plan is active.
      type: dict
      returned: when O(hetzner_token) is specified and RV(storageboxes[].status) is not V(initializing)
      version_added: 2.5.0
      contains:
        max_snapshots:
          description:
            - Maximum number of automatic snapshots to be kept.
          type: int
          sample: 10
        minute:
          description:
            - Minute the snapshot plan is executed (in UTC).
          type: int
          sample: null
        hour:
          description:
            - Hour the snapshot plan is executed (in UTC).
          type: int
          sample: null
        day_of_week:
          description:
            - Day of the week the snapshot plan is executed.
            - Will be V(none) (JSON V(null)) if this restriction is not set (that is, create a snapshot every day unless the day of month is specified).
          type: int
          sample: null
        day_of_month:
          description:
            - Day of the month the snapshot plan is executed.
            - Will be V(none) (JSON V(null)) if this restriction is not set (that is, create a snapshot every day unless the day of week is specified).
          type: int
          sample: null
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
    api_fetch_url_json_list,
)

from ansible_collections.community.hrobot.plugins.module_utils._tagging import (
    deprecate_value,
)

try:
    from urllib.parse import urlencode
except ImportError:
    # Python 2.x fallback:
    from urllib import urlencode


_CONVERT = {
    "login": ["username"],
    "disk_quota": ["storage_box_type", "size"],
    "disk_usage": ["stats", "size"],
    "disk_usage_data": ["stats", "size_data"],
    "disk_usage_snapshots": ["stats", "size_snapshots"],
    "webdav": ["access_settings", "webdav_enabled"],
    "samba": ["access_settings", "samba_enabled"],
    "ssh": ["access_settings", "ssh_enabled"],
    "external_reachability": ["access_settings", "reachable_externally"],
    "zfs": ["access_settings", "zfs_enabled"],
}


def add_hrobot_compat_shim(storagebox):
    result = dict(storagebox)
    for dest, source in _CONVERT.items():
        value = storagebox
        for src in source:
            value = value[src]
        result[dest] = deprecate_value(
            value,
            "The return value `{0}` is deprecated; use `{1}` instead.".format(dest, ".".join(source)),
            version="3.0.0",
        )
    return result


def main():
    argument_spec = dict(
        storagebox_id=dict(type='int'),
        linked_server_number=dict(type='int'),
        full_info=dict(type='bool', default=False),
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

    storagebox_id = module.params['storagebox_id']
    linked_server_number = module.params['linked_server_number']
    full_info = module.params['full_info']

    storageboxes = []
    if module.params["hetzner_user"] is not None:
        module.deprecate(
            "The hetzner_token parameter will be required from community.hrobot 3.0.0 on.",
            collection_name="community.hrobot",
            version="3.0.0",
        )
        # DEPRECATED: old API
        if storagebox_id is not None:
            storagebox_ids = [storagebox_id]
        else:
            url = "{0}/storagebox".format(BASE_URL)
            data = None
            headers = None
            if linked_server_number is not None:
                data = urlencode({
                    "linked_server": linked_server_number,
                })
                headers = {
                    "Content-type": "application/x-www-form-urlencoded",
                }
            result, error = fetch_url_json(module, url, accept_errors=['STORAGEBOX_NOT_FOUND'], data=data)
            storagebox_ids = []
            if not error:
                # When filtering by linked_server, the result should be a dictionary
                if isinstance(result, dict):
                    result = [result]
                for entry in result:
                    if full_info:
                        storagebox_ids.append(entry['storagebox']['id'])
                    else:
                        storageboxes.append(entry['storagebox'])

        for storagebox_id in storagebox_ids:
            url = "{0}/storagebox/{1}".format(BASE_URL, storagebox_id)
            result, error = fetch_url_json(module, url, accept_errors=['STORAGEBOX_NOT_FOUND'])
            if not error:
                storageboxes.append(result['storagebox'])

    else:
        # NEW API!
        if storagebox_id is not None:
            url = "{0}/v1/storage_boxes/{1}".format(API_BASE_URL, storagebox_id)
            result, dummy, error = api_fetch_url_json(module, url, accept_errors=["not_found"])
            if error is None:
                storageboxes = [result["storage_box"]]
        else:
            url = "{0}/v1/storage_boxes".format(API_BASE_URL)
            storageboxes, dummy = api_fetch_url_json_list(module, url, data_key="storage_boxes")
        storageboxes = [add_hrobot_compat_shim(storagebox) for storagebox in storageboxes]

    module.exit_json(
        changed=False,
        storageboxes=storageboxes,
    )


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
