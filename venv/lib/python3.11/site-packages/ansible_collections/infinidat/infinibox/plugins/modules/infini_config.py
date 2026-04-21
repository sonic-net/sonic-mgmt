#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-dict-literal,too-many-branches,too-many-locals,line-too-long,wrong-import-position

"""This module Modifies config on Infinibox."""

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: infini_config
version_added: 2.13.0
short_description:  Modify config on Infinibox
description:
    - This module modifies system config on Infinibox.
author: Wei Wang (@wwang)
options:
  config_group:
    description:
      - Config group
    type: str
    required: true
    choices: [ "core", "ip_config", "iscsi", "limits", "mgmt", "ndoe_interfaces", "overriders", "security", "ssh" ]
  key:
    description:
      - Name of the config
    type: str
    required: true
  value:
    description:
      - Value of the config key
    type: str
    required: false
  state:
    description:
      - Query or modifies config when.
    type: str
    required: false
    default: present
    choices: [ "stat", "present" ]

extends_documentation_fragment:
    - infinibox
"""

EXAMPLES = r"""
- name: Set compression setting to true
  infini_config:
    config_group: "mgmt"
    key: "pool.compression_enabled_default"
    value: false
    state: "present"
    user: "{{ user }}"
    password: "{{ password }}"
    system: "{{ system }}"
"""

# RETURN = r''' # '''

# -*- coding: utf-8 -*-
from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    HAS_INFINISDK,
    api_wrapper,
    infinibox_argument_spec,
    get_system,
)

try:
    from infinisdk.core.exceptions import APICommandFailed
except ImportError:
    pass  # Handled by HAS_INFINISDK from module_utils


@api_wrapper
def get_config(module, disable_fail=False):
    """
    Find and return config setting value
    Use disable_fail when we are looking for config
    and it may or may not exist and neither case is an error.
    """
    system = get_system(module)
    config_group = module.params["config_group"]
    key = module.params["key"]
    result = None

    path = f"config/{config_group}/{key}"
    try:
        api_response = system.api.get(path=path)
    except APICommandFailed as err:
        module.fail_json(msg=f"Cannot {config_group} key {key}: {err}")

    if api_response:
        result = api_response.get_result()
        good_status = api_response.response.status_code == 200
        if not disable_fail and not good_status:
            msg = f"Configuration for {config_group} with key {key} failed"
            module.fail_json(msg=msg)
        elif disable_fail and not good_status:
            return None
    return result


def handle_stat(module):
    """Return config stat"""

    config_group = module.params["config_group"]
    key = module.params["key"]
    value = get_config(module)

    result = {
        "changed": False,
        "object_type": config_group,
        "key": key,
        "value": value,
    }
    module.exit_json(**result)


@api_wrapper
def set_config(module):
    """
    Find and return config setting value
    Use disable_fail when we are looking for config
    and it may or may not exist and neither case is an error.
    """
    system = get_system(module)
    config_group = module.params["config_group"]
    key = module.params["key"]
    value = module.params["value"]

    path = f"config/{config_group}/{key}"

    if value.lower() == "true":
        data = True
    elif value.lower() == "false":
        data = False

    try:
        system.api.put(path=path, data=data)
    except APICommandFailed as err:
        module.fail_json(msg=f"Cannot set config group {config_group} key {key} to value {value}: {err}")
    # Variable 'changed' not returned by design


def handle_present(module):
    """Make config present"""
    changed = False
    msg = "Config unchanged"
    if not module.check_mode:
        old_config = get_config(module, disable_fail=True)
        set_config(module)
        new_config = get_config(module)
        changed = new_config != old_config
        if changed:
            msg = "Config changed"
        else:
            msg = "Config unchanged since the value is the same as the existing config"
    module.exit_json(changed=changed, msg=msg)


def execute_state(module):
    """Determine which state function to execute and do so"""
    state = module.params["state"]
    try:
        if state == "stat":
            handle_stat(module)
        elif state == "present":
            handle_present(module)
        else:
            module.fail_json(msg=f"Internal handler error. Invalid state: {state}")
    finally:
        system = get_system(module)
        system.logout()


def check_options(module):
    """Verify module options are sane"""
    state = module.params["state"]
    config_group = module.params["config_group"]
    key = module.params["key"]
    value = module.params["value"]
    vtype = type(value)

    groups = [
        "core",
        "ip_config",
        "iscsi",
        "limits",
        "mgmt",
        "ndoe_interfaces",
        "overriders",
        "security",
        "ssh",
    ]

    if state == "present" and key == "pool.compression_enabled_default":
        if not isinstance(value, str):  # isvalue.lower() not in values:
            module.fail_json(
                f"Value must be of type {type(str())}. Invalid value: {value} of {vtype}."
            )
    if config_group not in groups:
        module.fail_json(
            f"Config_group must be one of {groups}"
        )


def main():
    """Main module function"""
    argument_spec = infinibox_argument_spec()

    argument_spec.update(
        {
            "config_group": {"required": True, "choices": ["core", "ip_config", "iscsi", "limits", "mgmt", "ndoe_interfaces", "overriders", "security", "ssh"]},
            "key": {"required": True, "no_log": False},
            "value": {"required": False, "default": None},
            "state": {"required": False, "default": "present", "choices": ["stat", "present"]},
        }
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib("infinisdk"))

    check_options(module)
    execute_state(module)


if __name__ == '__main__':
    main()
