#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 T-Systems Multimedia Solutions GmbH
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
module: icinga_timeperiod_template
short_description: Manage timeperiod templates in Icinga2
description:
   - Add or remove a timeperiod template to Icinga2 through the director API.
author: Sebastian Gumprich (@rndmh3ro)
extends_documentation_fragment:
  - ansible.builtin.url
  - telekom_mms.icinga_director.common_options
version_added: '1.17.0'
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
      - Name of the time period.
    aliases: ['name']
    required: true
    type: str
  display_name:
    description:
      - Alternative name for this timeperiod template.
    type: str
  disabled:
    description:
      - Disabled objects will not be deployed.
    type: bool
    default: false
    choices: [true, false]
  imports:
    description:
      - Importable templates, add as many as you want.
      - Please note that order matters when importing properties from multiple templates - last one wins.
    type: list
    elements: str
    default: []
  includes:
    description:
      - Include other time periods into this.
    type: list
    elements: str
    aliases: ["include_period"]
    default: []
  excludes:
    description:
      - Exclude other time periods from this.
    type: list
    elements: str
    aliases: ["exclude_period"]
    default: []
  prefer_includes:
    description:
      - Whether to prefer timeperiods includes or excludes. Default to true.
    type: bool
    default: true
    choices: [true, false]
  ranges:
    description:
      - A dict of days and timeperiods.
    type: dict
  zone:
    description:
      - Set the zone.
    type: str
  update_method:
    description:
      - Define the update method.
    type: str
    default: "LegacyTimePeriod"
  append:
    description:
      - Do not overwrite the whole object but instead append the defined properties.
      - Note - Appending to existing vars, imports or any other list/dict is not possible. You have to overwrite the complete list/dict.
      - Note - Variables that are set by default will also be applied, even if not set.
    type: bool
    choices: [true, false]
    version_added: '1.25.0'
"""

EXAMPLES = """
- name: Create timeperiod template
  telekom_mms.icinga_director.icinga_timeperiod_template:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: "timeperiod_template"
    imports: []
    disabled: false
    prefer_includes: false
    ranges:
      monday: "00:00-23:59"
      tuesday: "00:00-23:59"
      wednesday: "00:00-23:59"
      thursday: "00:00-23:59"
      friday: "00:00-23:59"
      saturday: "00:00-23:59"
      sunday: "00:00-23:59"
    update_method: "LegacyTimePeriod"

- name: Update timeperiod template
  telekom_mms.icinga_director.icinga_timeperiod_template:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: "timeperiod_template"
    display_name: "timeperiod template"
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
        display_name=dict(required=False),
        disabled=dict(type="bool", default=False, choices=[True, False]),
        zone=dict(required=False, default=None),
        imports=dict(type="list", elements="str", default=[], required=False),
        ranges=dict(type="dict", required=False),
        prefer_includes=dict(type="bool", default=True, choices=[True, False]),
        excludes=dict(
            type="list",
            elements="str",
            default=[],
            required=False,
            aliases=["exclude_period"],
        ),
        includes=dict(
            type="list",
            elements="str",
            default=[],
            required=False,
            aliases=["include_period"],
        ),
        update_method=dict(required=False, default="LegacyTimePeriod"),
        api_timeout=dict(required=False, default=10, type="int"),
    )

    # Define the main module
    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )

    data_keys = [
        "object_name",
        "display_name",
        "disabled",
        "zone",
        "imports",
        "ranges",
        "prefer_includes",
        "excludes",
        "includes",
        "update_method",
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
        module=module, path="/timeperiod", data=data
    )

    changed, diff = icinga_object.update(module.params["state"])
    module.exit_json(
        changed=changed,
        diff=diff,
    )


# import module snippets
if __name__ == "__main__":
    main()
