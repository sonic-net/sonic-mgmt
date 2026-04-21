#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage Check Point Firewall (c) 2019
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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: cp_mgmt_access_rules
short_description: Manages access-rules objects on Check Point over Web Services API
description:
  - Manages access-rules objects on Check Point devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R80 management version.
version_added: "2.2.0"
author: "Shiran Golzar (@chkp-shirango)"
options:
  layer:
    description:
      - Layer that the rule belongs to identified by the name or UID.
    type: str
    required: true
  rules:
    description:
      - List of rules.
    type: list
    elements: dict
    required: true
    suboptions:
      name:
        description:
          - Object name.
        type: str
        required: True
      action:
        description:
          - a "Accept", "Drop", "Ask", "Inform", "Reject", "User Auth", "Client Auth", "Apply Layer".
        type: str
      action_settings:
        description:
          - Action settings.
        type: dict
        suboptions:
          enable_identity_captive_portal:
            description:
              - N/A
            type: bool
          limit:
            description:
              - N/A
            type: str
      content:
        description:
          - List of processed file types that this rule applies on.
        type: list
        elements: dict
      content_direction:
        description:
          - On which direction the file types processing is applied.
        type: str
        choices: ['any', 'up', 'down']
      content_negate:
        description:
          - True if negate is set for data.
        type: bool
      custom_fields:
        description:
          - Custom fields.
        type: dict
        suboptions:
          field_1:
            description:
              - First custom field.
            type: str
          field_2:
            description:
              - Second custom field.
            type: str
          field_3:
            description:
              - Third custom field.
            type: str
      destination:
        description:
          - Collection of Network objects identified by the name or UID.
        type: list
        elements: str
      destination_negate:
        description:
          - True if negate is set for destination.
        type: bool
      enabled:
        description:
          - Enable/Disable the rule.
        type: bool
      inline_layer:
        description:
          - Inline Layer identified by the name or UID. Relevant only if "Action" was set to "Apply Layer".
        type: str
      install_on:
        description:
          - Which Gateways identified by the name or UID to install the policy on.
        type: list
        elements: str
      service:
        description:
          - Collection of Network objects identified by the name or UID.
        type: list
        elements: str
      service_negate:
        description:
          - True if negate is set for service.
        type: bool
      source:
        description:
          - Collection of Network objects identified by the name or UID.
        type: list
        elements: str
      source_negate:
        description:
          - True if negate is set for source.
        type: bool
      time:
        description:
          - List of time objects. For example, "Weekend", "Off-Work", "Every-Day".
        type: list
        elements: str
      track:
        description:
          - Track Settings.
        type: dict
        suboptions:
          accounting:
            description:
              - Turns accounting for track on and off.
            type: bool
          alert:
            description:
              - Type of alert for the track.
            type: str
            choices: ['none', 'alert', 'snmp', 'mail', 'user alert 1', 'user alert 2', 'user alert 3']
          enable_firewall_session:
            description:
              - Determine whether to generate session log to firewall only connections.
            type: bool
          per_connection:
            description:
              - Determines whether to perform the log per connection.
            type: bool
          per_session:
            description:
              - Determines whether to perform the log per session.
            type: bool
          type:
            description:
              - a "Log", "Extended Log", "Detailed  Log", "None".
            type: str
      user_check:
        description:
          - User check settings.
        type: dict
        suboptions:
          confirm:
            description:
              - N/A
            type: str
            choices: ['per rule', 'per category', 'per application/site', 'per data type']
          custom_frequency:
            description:
              - N/A
            type: dict
            suboptions:
              every:
                description:
                  - N/A
                type: int
              unit:
                description:
                  - N/A
                type: str
                choices: ['hours', 'days', 'weeks', 'months']
          frequency:
            description:
              - N/A
            type: str
            choices: ['once a day', 'once a week', 'once a month', 'custom frequency...']
          interaction:
            description:
              - N/A
            type: str
      vpn_list:
        description:
          - Communities or Directional.
        type: list
        elements: dict
        suboptions:
          community:
            description:
              - List of community name or UID.
            type: list
            elements: str
          directional:
            description:
              - Communities directional match condition.
            type: list
            elements: dict
            suboptions:
              from:
                description:
                  - From community name or UID.
                type: str
              to:
                description:
                  - To community name or UID.
                type: str
      vpn:
        description:
          - Any or All_GwToGw.
        type: str
        choices: ['Any', 'All_GwToGw']
      comments:
        description:
          - Comments string.
        type: str
      details_level:
        description:
          - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
            representation of the object.
        type: str
        choices: ['uid', 'standard', 'full']
      ignore_warnings:
        description:
          - Apply changes ignoring warnings.
        type: bool
      ignore_errors:
        description:
          - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
        type: bool
      state:
        description:
          - State of the access rule (present or absent). Defaults to present.
        type: str
        default: present
        choices:
          - 'present'
          - 'absent'
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
extends_documentation_fragment: check_point.mgmt.checkpoint_objects_action_module
"""

EXAMPLES = """
- name: add-access-rules
  cp_mgmt_access_rules:
    rules:
      - name: Rule 1
        service:
          - SMTP
          - AOL
        state: present
      - name: Rule 2
        service:
          - SMTP
        state: present
    layer: Network
    auto_publish_session: true
"""

RETURN = """
cp_mgmt_access_rules:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_action_module,
)


def main():
    argument_spec = dict(
        rules=dict(
            type="list",
            required=True,
            elements="dict",
            options=dict(
                name=dict(type="str", required=True),
                action=dict(type="str"),
                action_settings=dict(
                    type="dict",
                    options=dict(
                        enable_identity_captive_portal=dict(type="bool"),
                        limit=dict(type="str"),
                    ),
                ),
                content=dict(type="list", elements="dict"),
                content_direction=dict(
                    type="str", choices=["any", "up", "down"]
                ),
                content_negate=dict(type="bool"),
                custom_fields=dict(
                    type="dict",
                    options=dict(
                        field_1=dict(type="str"),
                        field_2=dict(type="str"),
                        field_3=dict(type="str"),
                    ),
                ),
                destination=dict(type="list", elements="str"),
                destination_negate=dict(type="bool"),
                enabled=dict(type="bool"),
                inline_layer=dict(type="str"),
                install_on=dict(type="list", elements="str"),
                service=dict(type="list", elements="str"),
                service_negate=dict(type="bool"),
                source=dict(type="list", elements="str"),
                source_negate=dict(type="bool"),
                time=dict(type="list", elements="str"),
                track=dict(
                    type="dict",
                    options=dict(
                        accounting=dict(type="bool"),
                        alert=dict(
                            type="str",
                            choices=[
                                "none",
                                "alert",
                                "snmp",
                                "mail",
                                "user alert 1",
                                "user alert 2",
                                "user alert 3",
                            ],
                        ),
                        enable_firewall_session=dict(type="bool"),
                        per_connection=dict(type="bool"),
                        per_session=dict(type="bool"),
                        type=dict(type="str"),
                    ),
                ),
                user_check=dict(
                    type="dict",
                    options=dict(
                        confirm=dict(
                            type="str",
                            choices=[
                                "per rule",
                                "per category",
                                "per application/site",
                                "per data type",
                            ],
                        ),
                        custom_frequency=dict(
                            type="dict",
                            options=dict(
                                every=dict(type="int"),
                                unit=dict(
                                    type="str",
                                    choices=[
                                        "hours",
                                        "days",
                                        "weeks",
                                        "months",
                                    ],
                                ),
                            ),
                        ),
                        frequency=dict(
                            type="str",
                            choices=[
                                "once a day",
                                "once a week",
                                "once a month",
                                "custom frequency...",
                            ],
                        ),
                        interaction=dict(type="str"),
                    ),
                ),
                vpn_list=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        community=dict(type="list", elements="str"),
                        directional=dict(
                            type="list",
                            elements="dict",
                            options=dict(to=dict(type="str")),
                        ),
                    ),
                ),
                vpn=dict(type="str", choices=["Any", "All_GwToGw"]),
                comments=dict(type="str"),
                details_level=dict(
                    type="str", choices=["uid", "standard", "full"]
                ),
                ignore_warnings=dict(type="bool"),
                ignore_errors=dict(type="bool"),
                state=dict(
                    type="str",
                    choices=["present", "absent"],
                    default="present",
                ),
            ),
        ),
        layer=dict(type="str", required=True),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
    )

    argument_spec["rules"]["options"]["vpn_list"]["options"]["directional"][
        "options"
    ]["from"] = dict(type="str")
    argument_spec.update(checkpoint_argument_spec_for_action_module)

    module = AnsibleModule(argument_spec=argument_spec)

    module.exit_json()


if __name__ == "__main__":
    main()
