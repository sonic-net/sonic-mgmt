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
module: icinga_service_apply
short_description: Manage service apply rules in Icinga2
description:
   - Add or remove a service apply rule to Icinga2 through the director API.
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
      - Name for the Icinga service apply rule.
    aliases: ['name']
    required: true
    type: str
  display_name:
    description:
      - Alternative displayed name of the service apply rule.
    type: str
  check_command:
    description:
      - Check command definition.
    type: str
    version_added: '1.7.0'
  check_interval:
    description:
      - Your regular check interval.
    required: false
    type: str
  check_period:
    description:
      - The name of a time period which determines when this object should be monitored. Not limited by default.
    required: false
    type: str
  check_timeout:
    description:
      - Check command timeout in seconds. Overrides the CheckCommand's timeout attribute.
    required: false
    type: str
  enable_active_checks:
    description:
      - Whether to actively check this object.
    required: false
    type: "bool"
  enable_event_handler:
    description:
      - Whether to enable event handlers this object.
    required: false
    type: "bool"
  enable_notifications:
    description:
      - Whether to send notifications for this object.
    required: false
    type: "bool"
  enable_passive_checks:
    description:
      - Whether to accept passive check results for this object.
    required: false
    type: "bool"
  enable_perfdata:
    description:
      - Whether to process performance data provided by this object.
    required: false
    type: "bool"
  event_command:
    description:
      - Event command for service which gets called on every check execution if one of these conditions matches
      - The service is in a soft state
      - The service state changes into a hard state
      - The service state recovers from a soft or hard state to OK/Up
    required: false
    type: str
  max_check_attempts:
    description:
      - Defines after how many check attempts a new hard state is reached.
    required: false
    type: str
  retry_interval:
    description:
      - Retry interval, will be applied after a state change unless the next hard state is reached.
    required: false
    type: str
  groups:
    description:
      - Service groups that should be directly assigned to this service.
      - Servicegroups can be useful for various reasons.
      - They are helpful to provided service-type specific view in Icinga Web 2, either for custom dashboards or as an instrument to enforce restrictions.
      - Service groups can be directly assigned to single services or to service templates.
    type: "list"
    elements: str
    default: []
  apply_for:
    description:
      - Evaluates the apply for rule for all objects with the custom attribute specified.
      - For example selecting "host.vars.custom_attr" will generate "for (config in host.vars.array_var)" where "config" will be accessible through "$config$".
      - Note - only custom variables of type "Array" are eligible.
    type: str
  assign_filter:
    description:
      - The filter where the service apply rule will take effect.
    type: str
  command_endpoint:
    description:
      - The host where the service should be executed on.
    type: str
  imports:
    description:
      - Importable templates, add as many as you want.
      - Please note that order matters when importing properties from multiple templates - last one wins.
    type: "list"
    elements: str
  vars:
    description:
      - Custom properties of the service apply rule.
    type: "dict"
    default: {}
  notes:
    description:
      - Additional notes for this object.
    type: str
  notes_url:
    description:
      - An URL pointing to additional notes for this object.
      - Separate multiple urls like this "'http://url1' 'http://url2'".
      - Maximum length is 255 characters.
    type: str
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
- name: Add service apply rule to icinga
  telekom_mms.icinga_director.icinga_service_apply:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: "SERVICE_dummy"
    assign_filter: 'host.name="foohost"'
    check_command: hostalive
    display_name: "dummy process"
    check_interval: "10m"
    check_period: "24/7"
    check_timeout: "1m"
    enable_active_checks: true
    enable_event_handler: true
    enable_notifications: true
    enable_passive_checks: false
    enable_perfdata: false
    event_command: restart_httpd
    max_check_attempts: "5"
    retry_interval: "3m"
    imports:
      - fooservicetemplate
    groups:
      - fooservicegroup
    vars:
      http_address: "$address$"
      http_port: "9080"
      http_uri: "/ready"
      http_string: "Ready"
      http_expect: "Yes"

- name: Add service apply rule with command_endpoint
  telekom_mms.icinga_director.icinga_service_apply:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: "SERVICE_dummy"
    assign_filter: 'host.name="foohost"'
    check_command: hostalive
    display_name: "dummy process"
    check_interval: "10m"
    check_period: "24/7"
    check_timeout: "1m"
    enable_active_checks: true
    enable_event_handler: true
    enable_notifications: true
    enable_passive_checks: false
    event_command: restart_httpd
    max_check_attempts: "5"
    retry_interval: "3m"
    command_endpoint: "fooendpoint"
    imports:
      - fooservicetemplate
    groups:
      - fooservicegroup

- name: Update service apply rule with command_endpoint
  telekom_mms.icinga_director.icinga_service_apply:
    state: present
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    object_name: "SERVICE_dummy"
    enable_perfdata: true
    append: true
"""

RETURN = r""" # """

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
from ansible_collections.telekom_mms.icinga_director.plugins.module_utils.icinga import (
    Icinga2APIObject,
)


# ===========================================
# Icinga2 API class
#
class ServiceApplyRule(Icinga2APIObject):
    find_by_parameter = None

    def __init__(self, module, data):
        path = "/service"
        super(ServiceApplyRule, self).__init__(module, path, data)

    def exists(self):
        ret = self.call_url(path="/serviceapplyrules")
        if ret["code"] == 200:
            for existing_rule in ret["data"]["objects"]:
                if existing_rule["object_name"] == self.data["object_name"]:
                    if "uuid" in existing_rule and existing_rule["uuid"] is not None:
                        self.find_by_parameter = "uuid"
                    else:
                        self.find_by_parameter = "id"
                    self.object_id = existing_rule[self.find_by_parameter]
                    return self.object_id
        return False

    def delete(self):
        return super(ServiceApplyRule, self).delete(find_by=self.find_by_parameter)

    def modify(self):
        return super(ServiceApplyRule, self).modify(find_by=self.find_by_parameter)

    def diff(self):
        return super(ServiceApplyRule, self).diff(find_by=self.find_by_parameter)


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
        check_command=dict(required=False),
        check_interval=dict(required=False),
        check_period=dict(required=False),
        check_timeout=dict(required=False),
        enable_active_checks=dict(type="bool", required=False),
        enable_event_handler=dict(type="bool", required=False),
        enable_notifications=dict(type="bool", required=False),
        enable_passive_checks=dict(type="bool", required=False),
        enable_perfdata=dict(type="bool", required=False),
        event_command=dict(type="str", required=False),
        max_check_attempts=dict(required=False),
        retry_interval=dict(required=False),
        apply_for=dict(required=False),
        assign_filter=dict(required=False),
        command_endpoint=dict(required=False),
        imports=dict(type="list", elements="str", required=False),
        groups=dict(type="list", elements="str", default=[], required=False),
        vars=dict(type="dict", default={}),
        notes=dict(type="str", required=False),
        notes_url=dict(type="str", required=False),
        api_timeout=dict(required=False, default=10, type="int"),
    )

    # Define the main module
    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )

    data_keys = [
        "object_name",
        "display_name",
        "apply_for",
        "check_command",
        "check_interval",
        "check_period",
        "check_timeout",
        "enable_active_checks",
        "enable_event_handler",
        "enable_notifications",
        "enable_passive_checks",
        "enable_perfdata",
        "event_command",
        "max_check_attempts",
        "retry_interval",
        "command_endpoint",
        "assign_filter",
        "imports",
        "groups",
        "vars",
        "notes",
        "notes_url",
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

    icinga_object = ServiceApplyRule(module=module, data=data)

    changed, diff = icinga_object.update(module.params["state"])
    module.exit_json(
        changed=changed,
        diff=diff,
    )


# import module snippets
if __name__ == "__main__":
    main()
