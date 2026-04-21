#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025 Deutsche Telekom MMS GmbH
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: icinga_dependency_template
short_description: Manage dependency templates in Icinga2
description:
  - Add or remove a dependency template to Icinga2 through the director API.
author: Gianmarco Mameli (@gianmarco-mameli)
extends_documentation_fragment:
  - ansible.builtin.url
  - telekom_mms.icinga_director.common_options
notes:
  - This module supports check mode.
options:
  state:
    description:
      - Apply feature state.
    choices: [ "present", "absent" ]
    default: present
    type: str
  object_name:
    description:
      - Name for the Icinga dependency apply rule.
    aliases: ['name']
    required: true
    type: str
  parent_host:
    description:
      - The parent host.
    type: str
  parent_service:
    description:
      - The parent service. If omitted this dependency object is treated as host dependency.
    type: str
  disable_checks:
    description:
      - Whether to disable checks when this dependency fails.
    required: false
    type: "bool"
    choices: [true, false]
  disable_notifications:
    description:
      - Whether to disable notifications when this dependency fails.
    required: false
    type: "bool"
    choices: [true, false]
  ignore_soft_states:
    description:
      - Whether to ignore soft states for the reachability calculation.
    required: false
    type: "bool"
    choices: [true, false]
  period:
    description:
      - The name of a time period which determines when this notification should be triggered.
    required: false
    type: str
  zone:
    description:
      - Icinga cluster zone.
    required: false
    type: str
  states:
    description:
      - The host/service states you want to get notifications for.
    choices: [ "Critical", "Down", "OK", "Unknown", "Up", "Warning" ]
    required: false
    type: list
    elements: str
    default: []
  append:
    description:
      - Do not overwrite the whole object but instead append the defined properties.
      - Note - Appending to existing vars, imports or any other list/dict is not possible. You have to overwrite the complete list/dict.
      - Note - Variables that are set by default will also be applied, even if not set.
    type: bool
    choices: [true, false]
"""

EXAMPLES = """
- name: Add dependency template to icinga
  telekom_mms.icinga_director.icinga_dependency_template:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: footdependencytemplate
    period: "24/7"

- name: Add dependency template to icinga with customization
  telekom_mms.icinga_director.icinga_dependency_template:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: footdependencytemplatecustom
    disable_checks: true
    disable_notifications: true
    ignore_soft_states: false
    period: "24/7"
    zone: master
    states:
      - Warning
      - Critical

- name: Update dependency template with ignore_soft_states
  telekom_mms.icinga_director.icinga_dependency_template:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: footdependencytemplateappend
    ignore_soft_states: true
    append: true
"""

RETURN = r""" # """

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
from ansible_collections.telekom_mms.icinga_director.plugins.module_utils.icinga import (
    Icinga2APIObject,
)

# ===========================================
# Module execution.
#


def main():
    # use the predefined argument spec for url
    argument_spec = url_argument_spec()
    # add our own arguments
    argument_spec.update(
        state=dict(default="present", choices=["absent", "present"]),
        url=dict(required=True),
        append=dict(type="bool", choices=[True, False]),
        object_name=dict(required=True, aliases=["name"]),
        parent_host=dict(required=False, type="str"),
        parent_service=dict(required=False, type="str"),
        disable_checks=dict(required=False, type="bool", choices=[True, False]),
        disable_notifications=dict(required=False, type="bool", choices=[True, False]),
        ignore_soft_states=dict(required=False, type="bool", choices=[True, False]),
        period=dict(required=False, type="str"),
        zone=dict(required=False, type="str"),
        states=dict(
            type="list",
            elements="str",
            default=[],
            required=False,
            choices=["Critical", "Down", "OK", "Unknown", "Up", "Warning"]
        ),
        api_timeout=dict(required=False, default=10, type="int"),
    )

    # Define the main module
    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )

    data_keys = [
        "object_name",
        "parent_host",
        "parent_service",
        "disable_checks",
        "disable_notifications",
        "ignore_soft_states",
        "period",
        "zone",
        "states",
    ]

    data = {}

    if module.params["append"]:
        for k in data_keys:
            if module.params[k]:
                data[k] = module.params[k]
    else:
        for k in data_keys:
            data[k] = module.params[k]

    data["object_type"] = "template"

    icinga_object = Icinga2APIObject(
        module=module, path="/dependency", data=data
    )

    changed, diff = icinga_object.update(module.params["state"])
    module.exit_json(
        changed=changed,
        diff=diff,
    )


# import module snippets
if __name__ == "__main__":
    main()
