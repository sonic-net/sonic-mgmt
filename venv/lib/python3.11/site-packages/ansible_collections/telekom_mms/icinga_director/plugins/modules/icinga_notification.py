#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 T-Systems Multimedia Solutions GmbH
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
module: icinga_notification
short_description: Manage notifications in Icinga2
description:
   - Add or remove a notification to Icinga2 through the director API.
author: Sebastian Gumprich (@rndmh3ro) / Sebastian Gruber (sgruber94)
extends_documentation_fragment:
  - ansible.builtin.url
  - telekom_mms.icinga_director.common_options
version_added: '1.0.0'
notes:
  - This module supports check mode.
options:
  state:
    description:
      - Apply feature state.
    choices: [ "present", "absent" ]
    default: present
    type: "str"
  object_name:
    description:
      - Name of the notification.
    aliases: ['name']
    required: true
    type: "str"
  notification_interval:
    description:
      - The notification interval (in seconds). This interval is used for active notifications.
      - Defaults to 30 minutes. If set to 0, re-notifications are disabled.
    type: "int"
  types:
    description:
      - The state transition types you want to get notifications for.
    type: "list"
    elements: str
  users:
    description:
      - Users that should be notified by this notification.
    type: "list"
    elements: str
  states:
    description:
      - The host or service states you want to get notifications for.
    type: "list"
    elements: str
    version_added: "1.9.0"
  apply_to:
    description:
      - Whether this notification should affect hosts or services.
      - Required if I(state) is C(present).
    type: "str"
    choices: ["host", "service"]
  assign_filter:
    description:
      - The filter where the notification will take effect.
    type: "str"
  imports:
    description:
      - Importable templates, add as many as you want. Required when state is C(present).
      - Please note that order matters when importing properties from multiple templates - last one wins.
      - Required if I(state) is C(present).
    type: "list"
    elements: str
  disabled:
    description:
      - Disabled objects will not be deployed.
    type: bool
    default: false
    choices: [true, false]
    version_added: "1.9.0"
  vars:
    description:
      - Custom properties of the notification.
    type: "dict"
    version_added: "1.9.0"
    default: {}
  period:
    description:
      - The name of a time period which determines when this notification should be triggered.
    type: "str"
    aliases: ['time_period']
    version_added: "1.15.0"
  times_begin:
    description:
      - First notification delay.
      - Delay unless the first notification should be sent.
    type: "int"
    version_added: "1.15.0"
  times_end:
    description:
      - Last notification.
      - When the last notification should be sent.
    type: "int"
    version_added: "1.15.0"
  user_groups:
    description:
      - User Groups that should be notified by this notification.
    type: "list"
    elements: str
    default: []
    version_added: '1.16.0'
  append:
    description:
      - Do not overwrite the whole object but instead append the defined properties.
      - Note - Appending to existing vars, imports or any other list/dict is not possible. You have to overwrite the complete list/dict.
      - Note - Variables that are set by default will also be applied, even if not set.
    type: "bool"
    choices: [true, false]
    version_added: '1.25.0'
"""

EXAMPLES = """
- name: Create notification
  telekom_mms.icinga_director.icinga_notification:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    apply_to: host
    assign_filter: 'host.name="foohost"'
    imports:
      - foonotificationtemplate
    notification_interval: 0
    object_name: E-Mail_host
    states:
      - Up
      - Down
    types:
      - Problem
      - Recovery
    users:
      - rb
    user_groups:
      - OnCall
    disabled: false
    time_period: "24/7"
    times_begin: 20
    times_end: 120

- name: Create another notification
  telekom_mms.icinga_director.icinga_notification:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    apply_to: host
    assign_filter: 'host.name="foohost"'
    imports:
      - foonotificationtemplate
    notification_interval: 0
    object_name: E-Mail_host
    states:
      - Up
      - Down
    types:
      - Problem
      - Recovery
    users:
      - rb
    time_period: "24/7"

- name: Update notification
  telekom_mms.icinga_director.icinga_notification:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: E-Mail_host
    vars:
      foo: bar
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
        imports=dict(type="list", elements="str", required=False),
        apply_to=dict(choices=["service", "host"]),
        assign_filter=dict(required=False),
        disabled=dict(
            type="bool", required=False, default=False, choices=[True, False]
        ),
        notification_interval=dict(type="int", required=False),
        states=dict(type="list", elements="str", required=False),
        users=dict(type="list", elements="str", required=False),
        user_groups=dict(type="list", elements="str", default=[], required=False),
        types=dict(type="list", elements="str", required=False),
        vars=dict(type="dict", default={}, required=False),
        period=dict(required=False, aliases=["time_period"]),
        times_begin=dict(type="int", required=False),
        times_end=dict(type="int", required=False),
        api_timeout=dict(required=False, default=10, type="int"),
    )

    # Define the main module
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # When deleting objects, only the name is necessary, so we cannot use
    # required=True in the argument_spec. Instead we define here what is
    # necessary when state is present and we do not append to an existing object
    # We cannot use "required_if" here, because we rely on module.params.
    # These are defined at the same time we'd define the required_if arguments.
    if (
        module.params["state"] == "present"
        and not module.params["append"]
        and not (module.params["apply_to"] and module.params["imports"])
    ):
        module.fail_json(msg="missing required arguments: imports.")

    data_keys = [
        "object_name",
        "imports",
        "apply_to",
        "disabled",
        "assign_filter",
        "notification_interval",
        "states",
        "users",
        "user_groups",
        "types",
        "vars",
        "period",
        "times_begin",
        "times_end",
    ]

    data = {}

    if module.params["append"]:
        for k in data_keys:
            if module.params[k]:
                data[k] = module.params[k]
    else:
        for k in data_keys:
            data[k] = module.params[k]

    data["object_type"] = "apply"

    icinga_object = Icinga2APIObject(
        module=module, path="/notification", data=data
    )

    changed, diff = icinga_object.update(module.params["state"])
    module.exit_json(
        changed=changed,
        diff=diff,
    )


# import module snippets
if __name__ == "__main__":
    main()
