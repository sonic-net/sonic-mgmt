#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Manage switch names on Infinibox """

# pylint: disable=invalid-name,use-dict-literal,line-too-long,wrong-import-position

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: infini_fibre_channel_switch
version_added: 2.16.0
short_description: Manage Infinibox FC switch names
description:
    - This module renames FC switch names (rename state) or shows information about FC switches (stat state)
author: David Ohlemacher (@ohlemacher)
options:
  switch_name:
    description:
      - Current name of an existing fibre channel switch.
    type: str
    required: true
  new_switch_name:
    description:
      - New name for an existing fibre channel switch.
    type: str
    required: false
  state:
    description:
      - Rename an FC switch name, when using state rename.
      - States present and absent are not implemented.
      - State stat shows the existing FC switch details.
    type: str
    required: false
    default: rename
    choices: [ "stat", "rename" ]
extends_documentation_fragment:
    - infinibox
"""

EXAMPLES = r"""
- name: Rename fibre channel switch
  infini_fibre_channel:
    switch_name: VSAN 100
    state: rename
    user: admin
    password: secret
    system: ibox001

- name: Get information about fibre channel switch
  infini_fibre_channel:
    switch_name: VSAN 2000
    state: stat
    user: admin
    password: secret
    system: ibox001
"""

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    merge_two_dicts,
    get_system,
    infinibox_argument_spec,
)

try:
    from infinisdk.core.exceptions import APICommandFailed
except ImportError:
    pass  # Handled by HAS_INFINISDK from module_utils


def find_switch_by_name(module):
    """ Find switch by name """
    switch = module.params['switch_name']
    path = f"fc/switches?name={switch}"
    system = get_system(module)
    try:
        switch_result = system.api.get(path=path).get_result()
        if not switch_result:
            msg = f"Cannot find switch {switch}"
            module.exit_json(msg=msg)
    except APICommandFailed as err:
        msg = f"Cannot find switch {switch}: {err}"
        module.exit_json(msg=msg)
    return switch_result[0]


def handle_stat(module):
    """ Handle stat state """
    switch_name = module.params['switch_name']
    switch_result = find_switch_by_name(module)
    result = dict(
        changed=False,
        msg=f"Switch stat {switch_name} found"
    )
    result = merge_two_dicts(result, switch_result)
    module.exit_json(**result)


def handle_rename(module):
    """ Handle rename state """
    switch_name = module.params['switch_name']
    new_switch_name = module.params['new_switch_name']

    switch_result = find_switch_by_name(module)
    switch_id = switch_result['id']

    path = f"fc/switches/{switch_id}"
    data = {
        "name": new_switch_name,
    }
    try:
        system = get_system(module)
        rename_result = system.api.put(path=path, data=data).get_result()
    except APICommandFailed as err:
        msg = f"Cannot rename fc switch {switch_name}: {err}"
        module.exit_json(msg=msg)

    result = dict(
        changed=True,
        msg=f"FC switch renamed from {switch_name} to {new_switch_name}"
    )
    result = merge_two_dicts(result, rename_result)
    module.exit_json(**result)


def execute_state(module):
    """Handle states"""
    state = module.params["state"]
    try:
        if state == "stat":
            handle_stat(module)
        elif state == "rename":
            handle_rename(module)
        else:
            module.exit_json(msg=f"Internal handler error. Invalid state: {state}")
    finally:
        system = get_system(module)
        system.logout()


def check_options(module):
    """Verify module options are sane"""
    new_switch_name = module.params["new_switch_name"]
    state = module.params["state"]

    if state in ["rename"]:
        if not new_switch_name:
            msg = "New switch name parameter must be provided"
            module.exit_json(msg=msg)


def main():
    """ Main """
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            switch_name=dict(required=True, type="str"),
            new_switch_name=dict(required=False, type="str"),
            state=dict(default="rename", choices=["stat", "rename"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    check_options(module)
    execute_state(module)


if __name__ == "__main__":
    main()
