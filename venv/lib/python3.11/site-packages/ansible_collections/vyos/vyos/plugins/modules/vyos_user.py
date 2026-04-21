#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function


__metaclass__ = type

# (c) 2017, Ansible by Red Hat, inc
#
# This file is part of Ansible by Red Hat
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#


DOCUMENTATION = """
module: vyos_user
author: Trishna Guha (@trishnaguha)
short_description: Manage the collection of local users on VyOS device
description:
- This module provides declarative management of the local usernames configured on
  network devices. It allows playbooks to manage either individual usernames or the
  collection of usernames in the current running config. It also supports purging
  usernames from the configuration that are not explicitly defined.
version_added: 1.0.0
extends_documentation_fragment:
- vyos.vyos.vyos
notes:
- Tested against VyOS 1.3.8, 1.4.2, the upcoming 1.5, and the rolling release of spring 2025.
- This module works with connection C(ansible.netcommon.network_cli). See L(the VyOS OS Platform Options,../network/user_guide/platform_vyos.html).
options:
  aggregate:
    description:
    - The set of username objects to be configured on the remote VyOS device. The
      list entries can either be the username or a hash of username and properties.
      This argument is mutually exclusive with the C(name) argument.
    aliases:
    - users
    - collection
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The username to be configured on the VyOS device. This argument accepts a string
          value and is mutually exclusive with the C(aggregate) argument.
        required: True
        type: str
      full_name:
        description:
        - The C(full_name) argument provides the full name of the user account to be created
          on the remote device. This argument accepts any text string value.
        type: str
      encrypted_password:
        description:
        - The encrypted password of the user account on the remote device. Note that unlike
          the C(configured_password) argument, this argument ignores the C(update_password)
          and updates if the value is different from the one in the device running config.
        type: str
      configured_password:
        description:
        - The password to be configured on the VyOS device. The password needs to be provided
          in clear and it will be encrypted on the device.
        type: str
      update_password:
        description:
        - Since passwords are encrypted in the device running config, this argument will
          instruct the module when to change the password.  When set to C(always), the
          password will always be updated in the device and when set to C(on_create) the
          password will be updated only if the username is created.
        type: str
        choices:
        - on_create
        - always
      state:
        description:
        - Configures the state of the username definition as it relates to the device
          operational configuration. When set to I(present), the username(s) should be
          configured in the device active configuration and when set to I(absent) the
          username(s) should not be in the device active configuration
        type: str
        choices:
        - present
        - absent
      public_keys: &public_keys
        description:
        - Public keys for authentiction over SSH.
        type: list
        elements: dict
        suboptions:
          name:
            description: Name of the key (usually in the form of user@hostname)
            required: true
            type: str
          key:
            description: Public key string (base64 encoded)
            required: true
            type: str
          type:
            description: Type of the key
            required: true
            type: str
            choices:
            - ssh-dss
            - ssh-rsa
            - ecdsa-sha2-nistp256
            - ecdsa-sha2-nistp384
            - ssh-ed25519
            - ecdsa-sha2-nistp521

  name:
    description:
    - The username to be configured on the VyOS device. This argument accepts a string
      value and is mutually exclusive with the C(aggregate) argument.
    type: str
  full_name:
    description:
    - The C(full_name) argument provides the full name of the user account to be created
      on the remote device. This argument accepts any text string value.
    type: str
  encrypted_password:
    description:
    - The encrypted password of the user account on the remote device. Note that unlike
      the C(configured_password) argument, this argument ignores the C(update_password)
      and updates if the value is different from the one in the device running config.
    type: str
  configured_password:
    description:
    - The password to be configured on the VyOS device. The password needs to be provided
      in clear and it will be encrypted on the device.
    type: str
  update_password:
    description:
    - Since passwords are encrypted in the device running config, this argument will
      instruct the module when to change the password.  When set to C(always), the
      password will always be updated in the device and when set to C(on_create) the
      password will be updated only if the username is created.
    default: always
    type: str
    choices:
    - on_create
    - always
  public_keys: *public_keys
  purge:
    description:
    - Instructs the module to consider the resource definition absolute. It will remove
      any previously configured usernames on the device with the exception of the
      `admin` user (the current defined set of users).
    type: bool
    default: false
  state:
    description:
    - Configures the state of the username definition as it relates to the device
      operational configuration. When set to I(present), the username(s) should be
      configured in the device active configuration and when set to I(absent) the
      username(s) should not be in the device active configuration
    type: str
    default: present
    choices:
    - present
    - absent
"""

EXAMPLES = """
- name: create a new user
  vyos.vyos.vyos_user:
    name: ansible
    configured_password: password
    state: present
- name: remove all users except admin
  vyos.vyos.vyos_user:
    purge: true
- name: set multiple users to level operator
  vyos.vyos.vyos_user:
    aggregate:
      - name: netop
      - name: netend
    state: present
- name: Change Password for User netop
  vyos.vyos.vyos_user:
    name: netop
    configured_password: '{{ new_password }}'
    update_password: always
    state: present
"""

RETURN = """
commands:
  description: The list of configuration mode commands to send to the device
  returned: always
  type: list
  sample:
    - set system login user authentication plaintext-password password
"""

import re

from copy import deepcopy
from functools import partial

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_default_spec,
)

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.vyos import (
    get_config,
    load_config,
)


def spec_to_commands(updates, module):
    commands = list()
    update_password = module.params["update_password"]

    def needs_update(want, have, x):
        return want.get(x) and (want.get(x) != have.get(x))

    def add(command, want, x):
        command.append("set system login user %s %s" % (want["name"], x))

    for update in updates:
        want, have = update

        if want["state"] == "absent":
            commands.append("delete system login user %s" % want["name"])
            continue

        if needs_update(want, have, "full_name"):
            add(commands, want, "full-name '%s'" % want["full_name"])

        # look both ways for public_keys to handle replacement
        want_keys = want.get("public_keys") or dict()
        have_keys = have.get("public_keys") or dict()
        for key_name in want_keys:
            key = want_keys[key_name]
            if key_name not in have_keys or key != have_keys[key_name]:
                add(
                    commands,
                    want,
                    "authentication public-keys %s key '%s'" % (key["name"], key["key"]),
                )
                add(
                    commands,
                    want,
                    "authentication public-keys %s type '%s'" % (key["name"], key["type"]),
                )

        for key_name in have_keys:
            if key_name not in want_keys:
                commands.append(
                    "delete system login user %s authentication public-keys %s"
                    % (want["name"], key_name),
                )

        if needs_update(want, have, "encrypted_password"):
            add(
                commands,
                want,
                "authentication encrypted-password '%s'" % want["encrypted_password"],
            )

        if needs_update(want, have, "configured_password"):
            if update_password == "always" or not have:
                add(
                    commands,
                    want,
                    "authentication plaintext-password %s" % want["configured_password"],
                )

    return commands


def parse_full_name(data):
    match = re.search(r"full-name '(\S+)'", data, re.M)
    if match:
        full_name = match.group(1)[1:-1]
        return full_name


def parse_key(data):
    match = re.search(r"key '(\S+)'", data, re.M)
    if match:
        key = match.group(1)
        return key


def parse_key_type(data):
    match = re.search(r"type '(\S+)'", data, re.M)
    if match:
        key_type = match.group(1)
        return key_type


def parse_public_keys(data):
    """
    Parse public keys from the configuration
    returning dictionary of dictionaries indexed by key name
    """
    match = re.findall(r"public-keys (\S+)", data, re.M)
    if not match:
        return dict()

    keys = dict()
    for key in set(match):
        regex = r" %s .+$" % key
        cfg = re.findall(regex, data, re.M)
        cfg = "\n".join(cfg)
        obj = {
            "name": key,
            "key": parse_key(cfg),
            "type": parse_key_type(cfg),
        }
        keys[key] = obj
    return keys


def parse_encrypted_password(data):
    match = re.search(r"authentication encrypted-password '(\S+)'", data, re.M)
    if match:
        encrypted_password = match.group(1)
        return encrypted_password


def config_to_dict(module):
    data = get_config(module)

    match = re.findall(r"^set system login user (\S+)", data, re.M)
    if not match:
        return list()

    instances = list()

    for user in set(match):
        regex = r" %s .+$" % user
        cfg = re.findall(regex, data, re.M)
        cfg = "\n".join(cfg)
        obj = {
            "name": user,
            "state": "present",
            "configured_password": None,
            "full_name": parse_full_name(cfg),
            "encrypted_password": parse_encrypted_password(cfg),
            "public_keys": parse_public_keys(cfg),
        }
        instances.append(obj)

    return instances


def get_param_value(key, item, module):
    # if key doesn't exist in the item, get it from module.params
    if not item.get(key):
        value = module.params[key]

    # validate the param value (if validator func exists)
    validator = globals().get("validate_%s" % key)
    if all((value, validator)):
        validator(value, module)

    return value


def map_key_params_to_dict(keys):
    """
    Map the list of keys to a dictionary of dictionaries
    indexed by key name
    """
    all_keys = dict()
    if keys is None:
        return all_keys

    for key in keys:
        key_name = key["name"]
        all_keys[key_name] = key
    return all_keys


def map_params_to_obj(module):
    aggregate = module.params["aggregate"]
    if not aggregate:
        if not module.params["name"] and module.params["purge"]:
            return list()
        else:
            users = [{"name": module.params["name"]}]
    else:
        users = list()
        for item in aggregate:
            if not isinstance(item, dict):
                users.append({"name": item})
            else:
                users.append(item)

    objects = list()

    for item in users:
        get_value = partial(get_param_value, item=item, module=module)
        item["configured_password"] = get_value("configured_password")
        item["encrypted_password"] = get_value("encrypted_password")
        item["full_name"] = get_value("full_name")
        item["state"] = get_value("state")
        item["public_keys"] = map_key_params_to_dict(get_value("public_keys"))
        objects.append(item)

    return objects


def update_objects(want, have):
    updates = list()
    for entry in want:
        item = next((i for i in have if i["name"] == entry["name"]), None)
        if item is None:
            updates.append((entry, {}))
        elif item:
            for key, value in iteritems(entry):
                if value and value != item[key]:
                    updates.append((entry, item))
    return updates


def main():
    """main entry point for module execution"""
    public_key_spec = dict(
        name=dict(required=True, type="str"),
        key=dict(required=True, type="str", no_log=False),
        type=dict(
            required=True,
            type="str",
            choices=[
                "ssh-dss",
                "ssh-rsa",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ssh-ed25519",
                "ecdsa-sha2-nistp521",
            ],
        ),
    )
    element_spec = dict(
        name=dict(),
        full_name=dict(),
        configured_password=dict(no_log=True),
        encrypted_password=dict(no_log=False),
        update_password=dict(default="always", choices=["on_create", "always"]),
        state=dict(default="present", choices=["present", "absent"]),
        public_keys=dict(type="list", elements="dict", options=public_key_spec),
    )

    aggregate_spec = deepcopy(element_spec)
    aggregate_spec["name"] = dict(required=True)

    # remove default in aggregate spec, to handle common arguments
    remove_default_spec(aggregate_spec)

    argument_spec = dict(
        aggregate=dict(
            type="list",
            elements="dict",
            options=aggregate_spec,
            aliases=["users", "collection"],
        ),
        purge=dict(type="bool", default=False),
    )

    argument_spec.update(element_spec)

    mutually_exclusive = [
        ("name", "aggregate"),
        ("encrypted_password", "configured_password"),
    ]

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=mutually_exclusive,
        supports_check_mode=True,
    )

    warnings = list()
    result = {"changed": False, "warnings": warnings}

    want = map_params_to_obj(module)
    have = config_to_dict(module)
    commands = spec_to_commands(update_objects(want, have), module)

    if module.params["purge"]:
        want_users = [x["name"] for x in want]
        have_users = [x["name"] for x in have]
        for item in set(have_users).difference(want_users):
            commands.append("delete system login user %s" % item)

    result["commands"] = commands

    if commands:
        commit = not module.check_mode
        load_config(module, commands, commit=commit)
        result["changed"] = True

    module.exit_json(**result)


if __name__ == "__main__":
    main()
