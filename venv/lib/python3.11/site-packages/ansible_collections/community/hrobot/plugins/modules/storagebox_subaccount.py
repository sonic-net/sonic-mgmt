#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Victor LEFEBVRE <dev@vic1707.xyz>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
module: storagebox_subaccount
short_description: Create, update, or delete a subaccount for a storage box
version_added: 2.4.0
author:
  - Victor LEFEBVRE (@vic1707)
description:
  - Create, update, or delete a subaccount for a storage box.
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
    support: none
  idempotent:
    support: partial
    details:
      - The Hetzner API does not allow to create subaccounts with specific usernames.
        You can instead use O(comment) to identify accounts by setting O(idempotence=comment),
        that way creation is idempotent.
      - The module is never idempotent if O(password_mode=set-to-random), or if O(password_mode=update-if-provided) and O(password) is specified.
        Set O(password_mode=ignore-if-exists) if you want to provide O(password) on every invocation
        and do not want the module to always change it. Due to how Hetzner's API works, it is not possible
        to query the current password for a subaccount, or check whether a given password is set.

options:
  hetzner_token:
    version_added: 2.5.0
  storagebox_id:
    description:
      - The ID of the storage box to query.
    type: int
    required: true
  password_mode:
    description:
      - Controls how password updates are handled.
      - If C(update-if-provided), the password always updated if provided (default).
      - If C(ignore-if-exists), password is only used during creation.
      - If C(set-to-random), password is reset to a randomly generated one.
        Note that this is not supported by the new API (when O(hetzner_token) is set).
        The value has been deprecated in community.hrobot 2.7.0 and will be removed from community.hrobot 3.0.0.
      - When a new subaccount is created, the password is set to the specified one if O(password) is provided,
        and a random password is set if O(password) is not provided.
    type: str
    choices: [update-if-provided, ignore-if-exists, set-to-random]
    default: update-if-provided
    required: false

  state:
    description:
      - Desired state of this subaccount.
    choices: [present, absent]
    type: str
    default: present

  username:
    description:
      - Username of the subaccount.
      - Required when using O(idempotence=username) for updates or deletion of a subaccount.
      - If O(idempotence=username) and this is not specified, a new subaccount will always be created.
        If O(idempotence=comment), this option is ignored, as the Hetzner API does not allow to chose or modify the username.
    type: str
    required: false

  password:
    description:
      - Password to use or change.
      - See O(password_mode) for how and when this is used.
      - Will be ignored if O(password_mode=set-to-random).
    type: str
    required: false

  homedirectory:
    description:
      - Home directory of the subaccount.
      - Required only when creating a subaccount (O(state=present)).
    type: str
    required: false

  samba:
    description:
      - Enable or disable Samba.
    type: bool
    required: false

  ssh:
    description:
      - Enable or disable SSH access.
    type: bool
    required: false

  external_reachability:
    description:
      - Enable or disable external reachability (from outside Hetzner's networks).
    type: bool
    required: false

  webdav:
    description:
      - Enable or disable WebDAV.
    type: bool
    required: false

  readonly:
    description:
      - Enable or disable read-only mode.
    type: bool
    required: false

  comment:
    description:
      - A custom comment for the subaccount.
      - Is required when using O(idempotence=comment) for updates or deletion of a subaccount.
    type: str
    required: false

  idempotence:
    description:
      - Select which attribute to use to check subaccount existence.
      - If set to C(username), then subaccounts are identified by their username.
        Note that usernames cannot be specified on creation, so you need to use different
        module arguments for creation and updating.
      - If set to C(comment), then subaccounts are identified by their comment.
        If there already exist more than one subaccount with the given comment, the module will fail.
    type: str
    choices: [username, comment]
    default: username
    required: false

notes:
  - When passwords are autogenerated by the API (by omitting the O(password) field), the resulting password is returned.
"""

EXAMPLES = r"""
---
- name: Create a new subaccount with random password
  community.hrobot.storagebox_subaccount:
    storagebox_id: 123456
    homedirectory: "/backups/project1"
    samba: true
    ssh: true
    webdav: false
    comment: "Backup for Project 1"

- name: Create a subaccount with custom password
  community.hrobot.storagebox_subaccount:
    storagebox_id: 123456
    username: "backup1"
    password: "s3cretPass123"
    homedirectory: "/data/backup1"
    readonly: false
    samba: true
    ssh: false

- name: Update an existing subaccount
  community.hrobot.storagebox_subaccount:
    storagebox_id: 123456
    state: present
    username: "backup1"
    homedirectory: "/data/backup1-updated"
    readonly: true
    comment: "Updated path and readonly mode"

- name: Delete a subaccount
  community.hrobot.storagebox_subaccount:
    storagebox_id: 123456
    state: absent
    username: "backup1"

- name: Change password for a subaccount
  community.hrobot.storagebox_subaccount:
    storagebox_id: 123456
    state: present
    username: "backup1"
    password: "n3wSecur3Pass"

- name: Create subaccount using comment for idempotence
  community.hrobot.storagebox_subaccount:
    storagebox_id: 123456
    homedirectory: "/projects/backup1"
    samba: true
    ssh: true
    webdav: false
    readonly: false
    comment: "Backup1 - Project Foo"
    idempotence: comment

- name: Update subaccount identified by comment
  community.hrobot.storagebox_subaccount:
    storagebox_id: 123456
    homedirectory: "/projects/backup1-updated"
    readonly: true
    comment: "Backup1 - Project Foo"
    idempotence: comment

- name: Update password for subaccount using comment idempotence
  community.hrobot.storagebox_subaccount:
    storagebox_id: 123456
    password: "Sup3rSecur3!"
    comment: "Backup1 - Project Foo"
    idempotence: comment
    password_mode: update-if-provided

- name: Delete subaccount identified by comment
  community.hrobot.storagebox_subaccount:
    storagebox_id: 123456
    state: absent
    comment: "Backup1 - Project Foo"
    idempotence: comment

- name: Use password only during creation
  community.hrobot.storagebox_subaccount:
    storagebox_id: 123456
    password: "InitPass$42"
    homedirectory: "/mnt/init"
    samba: true
    ssh: false
    comment: "Init Subaccount"
    idempotence: comment
    password_mode: ignore-if-exists

- name: Always reset to a random password
  community.hrobot.storagebox_subaccount:
    storagebox_id: 123456
    comment: "Temp Access - CI/CD"
    idempotence: comment
    password_mode: set-to-random
"""

RETURN = r"""
created:
  description: Whether a new subaccount was created.
  type: bool
  returned: success

deleted:
  description: Whether the subaccount was deleted.
  type: bool
  returned: success

updated:
  description: Whether the subaccount's configuration was updated (excluding password changes).
  type: bool
  returned: success

password_updated:
  description: Whether the subaccount's password was updated.
  type: bool
  returned: success

subaccount:
  description:
    - The subaccount object returned by the API.
    - If O(hetzner_token) is provided, some extra fields are added to make this more compatible with the format returned by O(hetzner_user).
    - B(This extra return values are deprecated and will be removed from community.hrobot 3.0.0.)
      If you are using ansible-core 2.19 or newer, you will see a deprecation message when using these return values.
      These return values are RV(ignore:homedirectory), RV(ignore:samba), RV(ignore:ssh), RV(ignore:webdav), RV(ignore:external_reachability),
      RV(ignore:readonly), RV(ignore:createtime), and RV(ignore:comment).
  type: dict
  returned: if O(state=present)
"""

from copy import deepcopy
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
    api_fetch_url_json,
)

from ansible_collections.community.hrobot.plugins.module_utils._tagging import (
    deprecate_value,
)

try:
    from urllib.parse import urlencode
except ImportError:
    # Python 2.x fallback:
    from urllib import urlencode


def legacy_encode_data(data):
    """Converts booleans to lowercase strings and filters out None values."""
    return urlencode(
        {
            key: str(value).lower() if isinstance(value, bool) else value
            for key, value in data.items()
            if value is not None
        }
    )


def legacy_create_subaccount(module, storagebox_id, subaccount):
    url = "{0}/storagebox/{1}/subaccount".format(BASE_URL, storagebox_id)
    res, error = fetch_url_json(
        module,
        url,
        method="POST",
        data=legacy_encode_data(subaccount),
        headers={"Content-type": "application/x-www-form-urlencoded"},
        accept_errors=[
            "STORAGEBOX_SUBACCOUNT_LIMIT_EXCEEDED",
            "STORAGEBOX_INVALID_PASSWORD",
        ],
        timeout=30000,  # this endpoint is stupidly slow
    )

    if error == "STORAGEBOX_INVALID_PASSWORD":
        module.fail_json(msg="Invalid password (says Hetzner)")
    if error == "STORAGEBOX_SUBACCOUNT_LIMIT_EXCEEDED":
        module.fail_json(msg="Subaccount limit exceeded")

    # Contains all subaccount informations
    # { "subaccount": <data> }
    return res["subaccount"]


def legacy_merge_subaccounts_infos(original, updates):
    # None values aren't updated
    result = original.copy()
    for key, value in updates.items():
        if value is not None:
            result[key] = value
    return result


def legacy_is_subaccount_updated(before, after):
    for key, value in after.items():
        # Means user didn't provide a value
        # we assume we don't want to update that field
        if value is None:
            continue
        # password aren't considered part of update check
        # due to being a different API call
        if key == "password":
            continue
        if before.get(key) != value:
            return True
    return False


def legacy_delete_subaccount(module, storagebox_id, subaccount):
    empty, error = fetch_url_json(
        module,
        "{0}/storagebox/{1}/subaccount/{2}".format(
            BASE_URL, storagebox_id, subaccount["username"]
        ),
        method="DELETE",
        allow_empty_result=True,
        headers={"Content-type": "application/x-www-form-urlencoded"},
    )


def legacy_update_subaccount(module, storagebox_id, subaccount):
    empty, error = fetch_url_json(
        module,
        "{0}/storagebox/{1}/subaccount/{2}".format(
            BASE_URL, storagebox_id, subaccount["username"]
        ),
        method="PUT",
        data=legacy_encode_data({key: value for key, value in subaccount.items() if key != "password"}),
        headers={"Content-type": "application/x-www-form-urlencoded"},
        allow_empty_result=True,
        timeout=30000,  # this endpoint is stupidly slow
    )


def legacy_update_subaccount_password(module, storagebox_id, subaccount):
    new_password, error = fetch_url_json(
        module,
        "{0}/storagebox/{1}/subaccount/{2}/password".format(
            BASE_URL, storagebox_id, subaccount["username"]
        ),
        method="POST",
        data=legacy_encode_data({"password": subaccount["password"]}),
        headers={"Content-type": "application/x-www-form-urlencoded"},
        accept_errors=[
            "STORAGEBOX_INVALID_PASSWORD",
        ],
        timeout=30000,  # this endpoint is stupidly slow
    )
    if error == "STORAGEBOX_INVALID_PASSWORD":
        module.fail_json(msg="Invalid password (says Hetzner)")

    # { "password": <password> }
    return new_password["password"]


def legacy_get_subaccounts(module, storagebox_id):
    url = "{0}/storagebox/{1}/subaccount".format(BASE_URL, storagebox_id)
    result, error = fetch_url_json(module, url, accept_errors=["STORAGEBOX_NOT_FOUND"])
    if error:
        module.fail_json(
            msg="Storagebox with ID {0} does not exist".format(storagebox_id)
        )
    # Hetzner's response [ { "subaccount": <data> }, ... ]
    return [item["subaccount"] for item in result]


# -----------------------------------------


def create_subaccount(module, storagebox_id, subaccount):
    action_url = "{0}/v1/storage_boxes/{1}/subaccounts".format(API_BASE_URL, storagebox_id)
    access_settings = {
        'samba_enabled': subaccount['samba'],
        'ssh_enabled': subaccount['ssh'],
        'webdav_enabled': subaccount['webdav'],
        'readonly': subaccount['readonly'],
        'reachable_externally': subaccount['external_reachability'],
    }
    action = {
        'password': subaccount['password'],
        # For some reason, the home directory must **not** start with a slash, despite being returned that way...
        'home_directory': subaccount['homedirectory'].lstrip('/') if subaccount['homedirectory'] else subaccount['homedirectory'],
        'description': subaccount['comment'],
        'access_settings': {k: v for k, v in access_settings.items() if v is not None},
    }
    try:
        extracted_ids, dummy = api_apply_action(
            module,
            action_url,
            {k: v for k, v in action.items() if v is not None},
            lambda action_id: "{0}/v1/storage_boxes/actions/{1}".format(API_BASE_URL, action_id),
            method='POST',
            check_done_delay=1,
            check_done_timeout=120,
        )
        return extracted_ids["storage_box_subaccount"]
    except ApplyActionError as exc:
        module.fail_json(msg='Error while creating subaccount: {0}'.format(exc))


FIELDS = {
    "username": (["username"], None, None),
    "samba": (["access_settings", "samba_enabled"], None, "samba_enabled"),
    "ssh": (["access_settings", "ssh_enabled"], None, "ssh_enabled"),
    "external_reachability": (["access_settings", "reachable_externally"], None, "reachable_externally"),
    "webdav": (["access_settings", "webdav_enabled"], None, "webdav_enabled"),
    "readonly": (["access_settings", "readonly"], None, "readonly"),
    "comment": (["description"], "description", None),
}


def set_value(dictionary, path, value):
    for key in path[:-1]:
        if key not in dictionary:
            dictionary[key] = {}
        dictionary = dictionary[key]
    dictionary[path[-1]] = value


def merge_subaccounts_infos(original, updates):
    # None values aren't updated
    result = deepcopy(original)
    for key, value in updates.items():
        if value is not None:
            if key == 'password':
                result[key] = value
            elif key == 'homedirectory':
                result["home_directory"] = value
            else:
                set_value(result, FIELDS[key][0], value)
    return result


def get_value(dictionary, path):
    for key in path[:-1]:
        dictionary = dictionary[key]
    return dictionary.get(path[-1])


def get_subaccount_updates(before, after):
    update = {}
    access_settings = {}
    for key, value in after.items():
        # Means user didn't provide a value
        # we assume we don't want to update that field
        if value is None:
            continue
        # password and home directory aren't considered part of update check
        # due to being a different API call
        if key == "password" or key == "homedirectory":
            continue
        path, update_key, access_settings_key = FIELDS[key]
        current_value = get_value(before, path)
        if current_value != value:
            if update_key is not None:
                update[update_key] = value
            if access_settings_key is not None:
                access_settings[access_settings_key] = value
    return update, access_settings


def delete_subaccount(module, storagebox_id, subaccount):
    action_url = "{0}/v1/storage_boxes/{1}/subaccounts/{2}".format(API_BASE_URL, storagebox_id, subaccount['id'])
    try:
        api_apply_action(
            module,
            action_url,
            None,
            lambda action_id: "{0}/v1/storage_boxes/actions/{1}".format(API_BASE_URL, action_id),
            method='DELETE',
            check_done_delay=1,
            check_done_timeout=120,
        )
    except ApplyActionError as exc:
        module.fail_json(msg='Error while deleting subaccount: {0}'.format(exc))


def update_subaccount(module, storagebox_id, subaccount, update):
    url = "{0}/v1/storage_boxes/{1}/subaccounts/{2}".format(API_BASE_URL, storagebox_id, subaccount['id'])
    headers = {"Content-type": "application/json"}
    result, dummy, dummy2 = api_fetch_url_json(
        module,
        url,
        method='PUT',
        data=module.jsonify(update),
        headers=headers,
    )
    return result['subaccount']


def update_access_settings(module, storagebox_id, subaccount, access_settings):
    action_url = "{0}/v1/storage_boxes/{1}/subaccounts/{2}/actions/update_access_settings".format(API_BASE_URL, storagebox_id, subaccount['id'])
    try:
        api_apply_action(
            module,
            action_url,
            access_settings,
            lambda action_id: "{0}/v1/storage_boxes/actions/{1}".format(API_BASE_URL, action_id),
            check_done_delay=1,
            check_done_timeout=120,
        )
    except ApplyActionError as exc:
        module.fail_json(msg='Error while updating access settings: {0}'.format(exc))


def update_subaccount_password(module, storagebox_id, subaccount, new_password):
    action_url = "{0}/v1/storage_boxes/{1}/subaccounts/{2}/actions/reset_subaccount_password".format(API_BASE_URL, storagebox_id, subaccount['id'])
    action = {
        'password': new_password,
    }
    try:
        api_apply_action(
            module,
            action_url,
            action,
            lambda action_id: "{0}/v1/storage_boxes/actions/{1}".format(API_BASE_URL, action_id),
            check_done_delay=1,
            check_done_timeout=120,
        )
    except ApplyActionError as exc:
        module.fail_json(msg='Error while updating password: {0}'.format(exc))


def update_subaccount_home_directory(module, storagebox_id, subaccount, new_home_directory):
    action_url = "{0}/v1/storage_boxes/{1}/subaccounts/{2}/actions/change_home_directory".format(API_BASE_URL, storagebox_id, subaccount['id'])
    action = {
        'home_directory': new_home_directory,
    }
    try:
        api_apply_action(
            module,
            action_url,
            action,
            lambda action_id: "{0}/v1/storage_boxes/actions/{1}".format(API_BASE_URL, action_id),
            check_done_delay=1,
            check_done_timeout=120,
        )
    except ApplyActionError as exc:
        module.fail_json(msg='Error while updating home directory: {0}'.format(exc))


def get_subaccounts(module, storagebox_id, username=None):
    url = "{0}/v1/storage_boxes/{1}/subaccounts".format(API_BASE_URL, storagebox_id)
    if username is not None:
        url = "{0}?{1}".format(url, urlencode({'username': username}))
    result, dummy, error = api_fetch_url_json(module, url, accept_errors=['not_found'])
    if error:
        module.fail_json(msg='Storagebox with ID {0} does not exist'.format(storagebox_id))
    return result['subaccounts']


def get_value_opt(dictionary, path):
    for key in path[:-1]:
        if key not in dictionary:
            return None, False
        dictionary = dictionary[key]
    if path[-1] not in dictionary:
        return None, False
    return dictionary.get(path[-1]), True


def adjust_legacy(subaccount):
    result = dict(subaccount)
    for key, path in {
        'homedirectory': ['home_directory'],
        'samba': ['access_settings', 'samba_enabled'],
        'ssh': ['access_settings', 'ssh_enabled'],
        'webdav': ['access_settings', 'webdav_enabled'],
        'external_reachability': ['access_settings', 'reachable_externally'],
        'readonly': ['access_settings', 'readonly'],
        'createtime': ['created'],
        'comment': ['description'],
    }.items():
        value, exists = get_value_opt(subaccount, path)
        if exists:
            result[key] = deprecate_value(
                value,
                "The return value `{0}` is deprecated; use `{1}` instead.".format(key, ".".join(path)),
                version="3.0.0",
            )
    return result


def main():
    argument_spec = dict(
        storagebox_id=dict(type="int", required=True),
        password_mode=dict(
            type="str",
            no_log=False,
            choices=["update-if-provided", "ignore-if-exists", "set-to-random"],
            default="update-if-provided",
        ),
        state=dict(type="str", choices=["present", "absent"], default="present"),
        username=dict(type="str"),
        password=dict(type="str", no_log=True),
        homedirectory=dict(type="str"),
        samba=dict(type="bool"),
        ssh=dict(type="bool"),
        external_reachability=dict(type="bool"),
        webdav=dict(type="bool"),
        readonly=dict(type="bool"),
        comment=dict(type="str"),
        idempotence=dict(type="str", choices=["username", "comment"], default="username"),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    argument_spec.update(_ROBOT_DEFAULT_ARGUMENT_SPEC_COMPAT_DEPRECATED)
    argument_spec.update(API_DEFAULT_ARGUMENT_SPEC)
    argument_spec.update(_API_DEFAULT_ARGUMENT_SPEC_COMPAT)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    check_mode = module.check_mode
    storagebox_id = module.params["storagebox_id"]
    password_mode = module.params["password_mode"]
    state = module.params["state"]
    idempotence = module.params["idempotence"]
    subaccount = {
        "username": module.params["username"],
        "password": module.params["password"],
        "homedirectory": module.params["homedirectory"],
        "samba": module.params["samba"],
        "ssh": module.params["ssh"],
        "external_reachability": module.params["external_reachability"],
        "webdav": module.params["webdav"],
        "readonly": module.params["readonly"],
        "comment": module.params["comment"],
    }
    account_identifier = subaccount[idempotence]

    if password_mode == 'set-to-random':
        module.deprecate(
            "password_mode=set-to-random is deprecated and will be removed in community.hrobot 3.0.0.",
            collection_name="community.hrobot",
            version="3.0.0",
        )

    if module.params["hetzner_user"] is not None:
        module.deprecate(
            "The hetzner_token parameter will be required from community.hrobot 3.0.0 on.",
            collection_name="community.hrobot",
            version="3.0.0",
        )
        # DEPRECATED: old API

        existing_subaccounts = legacy_get_subaccounts(module, storagebox_id)

        matches = [
            sa for sa in existing_subaccounts
            if sa[idempotence] == account_identifier
        ]
        if len(matches) > 1:
            module.fail_json(msg="More than one subaccount matched the idempotence criteria.")

        existing = matches[0] if matches else None

        created = deleted = updated = password_updated = False

        if state == "absent":
            if existing:
                if not check_mode:
                    legacy_delete_subaccount(module, storagebox_id, existing)
                deleted = True
        elif state == "present" and existing:
            # Set the found username in case user used comment as idempotence
            subaccount["username"] = existing["username"]

            if (
                password_mode == "set-to-random" or
                (password_mode == "update-if-provided" and subaccount["password"])
            ):
                if password_mode == "set-to-random":
                    subaccount["password"] = None
                if not check_mode:
                    new_password = legacy_update_subaccount_password(module, storagebox_id, subaccount)
                    subaccount["password"] = new_password
                password_updated = True

            if legacy_is_subaccount_updated(existing, subaccount):
                if not check_mode:
                    legacy_update_subaccount(module, storagebox_id, subaccount)
                updated = True
        else:  # state 'present' without pre-existing account
            if not subaccount["homedirectory"]:
                module.fail_json(msg="homedirectory is required when creating a new subaccount")
            if password_mode == "set-to-random":
                subaccount["password"] = None

            del subaccount["username"]  # username cannot be choosen
            if not check_mode:
                # not necessary, allows us to get additional infos (created time etc...)
                existing = legacy_create_subaccount(module, storagebox_id, subaccount)
            created = True

        return_data = legacy_merge_subaccounts_infos(existing or {}, subaccount)

        module.exit_json(
            changed=any([created, deleted, updated, password_updated]),
            created=created,
            deleted=deleted,
            updated=updated,
            password_updated=password_updated,
            subaccount=return_data if state != "absent" else None,
        )

    else:
        # NEW API!

        if password_mode == 'set-to-random':
            module.fail_json(msg="The new Hetzner API does not support password_mode=set-to-random")
        if idempotence == 'comment':
            idempotence = 'description'

        existing_subaccounts = get_subaccounts(module, storagebox_id, username=account_identifier if idempotence == "username" else None)

        matches = [
            sa for sa in existing_subaccounts
            if sa[idempotence] == account_identifier
        ]
        if len(matches) > 1:
            module.fail_json(msg="More than one subaccount matched the idempotence criteria.")

        existing = matches[0] if matches else None

        created = deleted = updated = password_updated = homedir_updated = False

        if state == "absent":
            if existing:
                if not check_mode:
                    delete_subaccount(module, storagebox_id, existing)
                deleted = True
        elif state == "present" and existing:
            # Set the found username in case user used comment as idempotence
            subaccount["username"] = existing["username"]

            if (
                password_mode == "update-if-provided" and subaccount["password"]
            ):
                if not check_mode:
                    update_subaccount_password(module, storagebox_id, existing, subaccount["password"])
                password_updated = True

            if subaccount["homedirectory"] is not None:
                # Hetzner likes to strip leading '/' from the home directory
                current_home_dir = existing["home_directory"]
                if current_home_dir is not None:
                    current_home_dir = current_home_dir.lstrip("/")
                home_dir = subaccount["homedirectory"].lstrip("/")
                if current_home_dir != home_dir:
                    if not check_mode:
                        update_subaccount_home_directory(module, storagebox_id, existing, home_dir)
                    homedir_updated = True

            update, access_settings = get_subaccount_updates(existing, subaccount)
            if update:
                if not check_mode:
                    update_subaccount(module, storagebox_id, existing, update)
                updated = True
            if access_settings:
                if not check_mode:
                    update_access_settings(module, storagebox_id, existing, access_settings)
                updated = True
        else:  # state 'present' without pre-existing account
            if not subaccount["homedirectory"]:
                module.fail_json(msg="homedirectory is required when creating a new subaccount")
            if not subaccount["password"]:
                module.fail_json(msg="password is required when creating a new subaccount")

            del subaccount["username"]  # username cannot be choosen
            if not check_mode:
                new_subaccount_id = create_subaccount(module, storagebox_id, subaccount)
                # Retrieve created subaccount
                # (not necessary, allows us to get additional infos (created time etc...))
                url = "{0}/v1/storage_boxes/{1}/subaccounts/{2}".format(API_BASE_URL, storagebox_id, new_subaccount_id)
                existing = api_fetch_url_json(module, url, method='GET')[0]["subaccount"]
            created = True

        return_data = merge_subaccounts_infos(existing or {}, subaccount)

        module.exit_json(
            changed=any([created, deleted, updated, password_updated, homedir_updated]),
            created=created,
            deleted=deleted,
            updated=updated or homedir_updated,
            password_updated=password_updated,
            subaccount=adjust_legacy(return_data) if state != "absent" else None,
        )


if __name__ == "__main__":  # pragma: no cover
    main()  # pragma: no cover
