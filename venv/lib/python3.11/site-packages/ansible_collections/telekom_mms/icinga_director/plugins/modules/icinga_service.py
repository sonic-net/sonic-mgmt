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
module: icinga_service
short_description: Manage services in Icinga2
description:
   - Add or remove a service to Icinga2 through the director API.
author: Sebastian Gumprich (@rndmh3ro)
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
    type: str
  object_name:
    description:
      - Name of the service.
    aliases: ['name']
    required: true
    type: str
  check_command:
    description:
      - Check command definition.
    type: str
  check_interval:
    description:
      - Your regular check interval.
    type: str
  check_period:
    description:
      - The name of a time period which determines when this object should be monitored. Not limited by default.
    type: str
  check_timeout:
    description:
      - Check command timeout in seconds. Overrides the CheckCommand's timeout attribute.
    type: str
  display_name:
    description:
      - Alternative name for this service.
    type: str
  enable_active_checks:
    description:
      - Whether to actively check this object.
    type: "bool"
  enable_event_handler:
    description:
      - Whether to enable event handlers this object.
    type: "bool"
  enable_flapping:
    description:
      - Whether flap detection is enabled on this object.
    type: bool
  enable_notifications:
    description:
      - Whether to send notifications for this object.
    type: "bool"
  enable_passive_checks:
    description:
      - Whether to accept passive check results for this object.
    type: "bool"
  enable_perfdata:
    description:
      - Whether to process performance data provided by this object.
    type: "bool"
  event_command:
    description:
      - Event command for service which gets called on every check execution if one of these conditions matches
      - The service is in a soft state
      - The service state changes into a hard state
      - The service state recovers from a soft or hard state to OK/Up
    type: "str"
  flapping_threshold_high:
    description:
      - Flapping upper bound in percent for a service to be considered flapping
    type: str
  flapping_threshold_low:
    description:
      - Flapping lower bound in percent for a service to be considered not flapping
    type: str
  groups:
    description:
      - Service groups that should be directly assigned to this service.
      - Servicegroups can be useful for various reasons.
      - They are helpful to provided service-type specific view in Icinga Web 2, either for custom dashboards or as an instrument to enforce restrictions.
      - Service groups can be directly assigned to single services or to service templates.
    type: "list"
    elements: "str"
    default: []
  icon_image:
    description:
      - An URL pointing to an icon for this object.
      - Try "tux.png" for icons relative to public/img/icons or "cloud" (no extension) for items from the Icinga icon font
    type: str
  icon_image_alt:
    description:
      - Alternative text to be shown in case above icon is missing
    type: str
  host:
    description:
      - Choose the host this single service should be assigned to.
      - This field will be required when `service_set` is not defined.
    required: false
    type: "str"
  imports:
    description:
      - Importable templates, add as many as you want.
      - Please note that order matters when importing properties from multiple templates - last one wins.
    type: "list"
    elements: "str"
    default: []
  max_check_attempts:
    description:
      - Defines after how many check attempts a new hard state is reached.
    type: str
  notes:
    description:
      - Additional notes for this object.
    type: str
    version_added: '1.8.0'
  notes_url:
    description:
      - An URL pointing to additional notes for this object.
      - Separate multiple urls like this "'http://url1' 'http://url2'".
      - Maximum length is 255 characters.
    type: str
    version_added: '1.8.0'
  retry_interval:
    description:
      - Retry interval, will be applied after a state change unless the next hard state is reached.
    type: str
  use_agent:
    description:
      - Whether the check command for this service should be executed on the Icinga agent.
    type: "bool"
  vars:
    description:
      - Custom properties of the service.
    type: "dict"
    default: {}
  volatile:
    description:
      - Whether this check is volatile.
    type: "bool"
  disabled:
    description:
      - Disabled objects will not be deployed.
    type: bool
    default: false
    choices: [true, false]
  append:
    description:
      - Do not overwrite the whole object but instead append the defined properties.
      - Note - Appending to existing vars, imports or any other list/dict is not possible. You have to overwrite the complete list/dict.
      - Note - Variables that are set by default will also be applied, even if not set.
    type: bool
    choices: [true, false]
    version_added: '1.25.0'
  service_set:
    description:
      - Choose the service set name this single service should be assigned to.
      - This field will be required when `host` is not defined.
    type: str
    version_added: '1.29.0'
"""

EXAMPLES = """
- name: Create service
  tags: service
  telekom_mms.icinga_director.icinga_service:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: "foo service"
    display_name: "foo service"
    check_command: hostalive
    use_agent: false
    host: foohost
    vars:
      procs_argument: consul
      procs_critical: '1:'
      procs_warning: '1:'

- name: Update service
  tags: service
  telekom_mms.icinga_director.icinga_service:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: "foo service"
    display_name: "foo service"
    host: foohost
    notes: "example note"
    notes_url: "'http://url1' 'http://url2'"
    append: true

- name: Create serviceset service
  telekom_mms.icinga_director.icinga_service:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: "foo service serviceset"
    service_set: "foo_serviceset"
"""

RETURN = r""" # """

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.six.moves.urllib.parse import quote as urlquote
from ansible_collections.telekom_mms.icinga_director.plugins.module_utils.icinga import (
    Icinga2APIObject,
)
import json
from collections import defaultdict


class IcingaServiceObject(Icinga2APIObject):
    module = None

    def __init__(self, module, path, data):
        super(IcingaServiceObject, self).__init__(module, path, data)
        self.module = module
        self.params = module.params
        self.path = path
        self.data = data
        self.object_id = None
        param_service_type = ""
        param_service_type_filter = ""
        # set url parameters when service is assigned to a host
        if "host" in self.data:
            if self.data["host"]:
                param_service_type = "host="
                param_service_type_filter = to_text(urlquote(self.data["host"]))
        # set url parameters when service is assigned to a serviceset
        if "service_set" in self.data:
            if self.data["service_set"]:
                param_service_type = "set="
                param_service_type_filter = to_text(
                    urlquote(self.data["service_set"])
                )

        self.url = (
            "/service"
            + "?"
            + "name="
            + to_text(urlquote(self.data["object_name"]))
            + "&"
            + param_service_type
            + param_service_type_filter
        )

    def exists(self, find_by="name"):
        ret = super(IcingaServiceObject, self).call_url(path=self.url)
        self.object_id = to_text(urlquote(self.data["object_name"]))
        if ret["code"] == 200:
            return True
        return False

    def delete(self, find_by="name"):
        return super(IcingaServiceObject, self).call_url(
            path=self.url,
            method="DELETE",
        )

    def modify(self, find_by="name"):
        return super(IcingaServiceObject, self).call_url(
            path=self.url,
            data=self.module.jsonify(self.data),
            method="POST",
        )

    def diff(self, find_by="name"):
        ret = super(IcingaServiceObject, self).call_url(
            path=self.url,
            method="GET",
        )

        data_from_director = json.loads(self.module.jsonify(ret["data"]))
        data_from_task = json.loads(self.module.jsonify(self.data))

        diff = defaultdict(dict)
        for key, value in data_from_director.items():
            value = self.scrub_diff_value(value)
            if key in data_from_task.keys() and value != data_from_task[key]:
                diff["before"][key] = "{val}".format(val=value)
                diff["after"][key] = "{val}".format(val=data_from_task[key])

        return diff


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
        disabled=dict(type="bool", default=False, choices=[True, False]),
        check_command=dict(required=False),
        check_interval=dict(required=False),
        check_period=dict(required=False),
        check_timeout=dict(required=False),
        display_name=dict(required=False),
        enable_active_checks=dict(type="bool", required=False),
        enable_event_handler=dict(type="bool", required=False),
        enable_flapping=dict(type="bool", required=False),
        enable_notifications=dict(type="bool", required=False),
        enable_passive_checks=dict(type="bool", required=False),
        enable_perfdata=dict(type="bool", required=False),
        event_command=dict(type="str", required=False),
        flapping_threshold_high=dict(type="str", required=False),
        flapping_threshold_low=dict(type="str", required=False),
        host=dict(type="str", required=False),
        groups=dict(type="list", elements="str", default=[], required=False),
        icon_image_alt=dict(type="str", required=False),
        icon_image=dict(type="str", required=False),
        imports=dict(type="list", elements="str", default=[], required=False),
        max_check_attempts=dict(required=False),
        notes=dict(type="str", required=False),
        notes_url=dict(type="str", required=False),
        retry_interval=dict(required=False),
        service_set=dict(type="str", required=False),
        use_agent=dict(type="bool", required=False),
        vars=dict(type="dict", default={}, required=False),
        volatile=dict(type="bool", required=False),
        api_timeout=dict(required=False, default=10, type="int"),
    )

    # Define the main module
    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )

    data_keys = [
        "object_name",
        "disabled",
        "check_command",
        "check_interval",
        "check_period",
        "check_timeout",
        "display_name",
        "enable_active_checks",
        "enable_event_handler",
        "enable_flapping",
        "enable_notifications",
        "enable_passive_checks",
        "enable_perfdata",
        "event_command",
        "flapping_threshold_high",
        "flapping_threshold_low",
        "groups",
        "icon_image_alt",
        "icon_image",
        "host",
        "imports",
        "max_check_attempts",
        "notes",
        "notes_url",
        "retry_interval",
        "service_set",
        "use_agent",
        "vars",
        "volatile",
    ]

    data = {}

    if module.params["append"]:
        for k in data_keys:
            if module.params[k]:
                data[k] = module.params[k]
    else:
        for k in data_keys:
            data[k] = module.params[k]

    data["object_type"] = "object"

    # Only one of "service_set" or "host" needs to be present at the
    # same time so we cannot use required=True in the argument_spec.
    # Instead we define here that only one of the two parameters is defined at the same time.
    if (
        module.params["state"] == "present"
        and not module.params["append"]
        and module.params["host"]
        and module.params["service_set"]
    ):
        module.fail_json(
            msg="Only one of the properties host or service_set can be defined within the same object."
        )

    if (
        module.params["state"] == "present"
        and not module.params["append"]
        and not module.params["host"]
        and not module.params["service_set"]
    ):
        module.fail_json(
            msg="One of the properties host or service_set is required."
        )

    icinga_object = IcingaServiceObject(
        module=module, path="/service", data=data
    )

    changed, diff = icinga_object.update(module.params["state"])
    module.exit_json(
        changed=changed,
        diff=diff,
    )


# import module snippets
if __name__ == "__main__":
    main()
