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
module: icinga_notification_template
short_description: Manage notification templates in Icinga2
description:
   - Add or remove a notification template to Icinga2 through the director API.
author: Sebastian Gumprich (@rndmh3ro) / Sebastian Gruber (sgruber94)
extends_documentation_fragment:
  - ansible.builtin.url
  - telekom_mms.icinga_director.common_options
version_added: "1.9.0"
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
      - Name of the notification template.
    aliases: ['name']
    required: true
    type: str
  notification_interval:
    description:
      - The notification interval (in seconds). This interval is used for active notifications.
      - Defaults to 30 minutes. If set to 0, re-notifications are disabled.
    type: str
  types:
    description:
      - The state transition types you want to get notifications for.
    type: "list"
    elements: str
  states:
    description:
      - The host or service states you want to get notifications for.
    type: "list"
    elements: str
  times_begin:
    description:
      - First notification delay.
      - Delay unless the first notification should be sent.
    type: "int"
  times_end:
    description:
      - Last notification.
      - When the last notification should be sent.
    type: "int"
  zone:
    description:
      - Set the zone.
    type: str
  period:
    description:
      - The name of a time period which determines when this notification should be triggered.
    type: "str"
    aliases: ['time_period']
    version_added: "1.15.0"
  command:
    description:
      - Check command definition
    type: "str"
    aliases: ['notification_command']
    version_added: "1.15.0"
  users:
    description:
      - Users that should be notified by this notification
    type: "list"
    elements: str
    version_added: "1.15.0"
  user_groups:
    description:
      - User Groups that should be notified by this notification.
    type: "list"
    elements: str
    version_added: '1.16.0'
  append:
    description:
      - Do not overwrite the whole object but instead append the defined properties.
      - Note - Appending to existing vars, imports or any other list/dict is not possible. You have to overwrite the complete list/dict.
      - Note - Variables that are set by default will also be applied, even if not set.
    type: bool
    choices: [true, false]
    version_added: '1.25.0'
  imports:
    description:
      - Importable templates, add as many as you want. Required when state is C(present).
      - Please note that order matters when importing properties from multiple templates - last one wins.
      - Required if I(state) is C(present).
    type: "list"
    elements: str
  vars:
    description:
      - Custom properties of the notification.
    type: "dict"
    default: {}
"""

EXAMPLES = """
- name: Create notification template
  telekom_mms.icinga_director.icinga_notification_template:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: foonotificationtemplate
    states:
      - Up
      - Down
    types:
      - Problem
      - Recovery
    times_begin: 20
    times_end: 120
    time_period: "24/7"
    notification_command: "mail-host-notification"
    users:
      - "rb"
    user_groups:
      - "OnCall"
    vars:
      foo: bar
    zone: "foozone"

- name: Update notification template
  telekom_mms.icinga_director.icinga_notification_template:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: foonotificationtemplate
    notification_interval: '0'
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
        notification_interval=dict(required=False),
        states=dict(type="list", elements="str", required=False),
        times_begin=dict(type="int", required=False),
        times_end=dict(type="int", required=False),
        types=dict(type="list", elements="str", required=False),
        zone=dict(required=False, default=None),
        period=dict(required=False, aliases=["time_period"]),
        command=dict(required=False, aliases=["notification_command"]),
        users=dict(type="list", elements="str", required=False),
        user_groups=dict(type="list", elements="str", required=False),
        vars=dict(type="dict", default={}, required=False),
        api_timeout=dict(required=False, default=10, type="int"),
    )

    # Define the main module
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    data_keys = [
        "object_name",
        "imports",
        "notification_interval",
        "states",
        "times_begin",
        "times_end",
        "types",
        "zone",
        "period",
        "command",
        "users",
        "user_groups",
        "vars"
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
