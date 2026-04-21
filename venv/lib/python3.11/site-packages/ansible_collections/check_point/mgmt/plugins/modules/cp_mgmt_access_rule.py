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
module: cp_mgmt_access_rule
short_description: Manages access-rule objects on Check Point over Web Services API
description:
  - Manages access-rule objects on Check Point devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R80 management version.
version_added: "1.0.0"
author: "Or Soffer (@chkp-orso)"
options:
  layer:
    description:
      - Layer that the rule belongs to identified by the name or UID.
    type: str
  position:
    description:
      - Position in the rulebase. The use of values "top" and "bottom" may not be idempotent.
    type: str
  relative_position:
    description:
      - Position in the rulebase.
      - Use of this field may not be idempotent.
    type: dict
    suboptions:
      below:
        description:
          - Add rule below specific rule/section identified by name (limited to 50 rules if
            search_entire_rulebase is False).
        type: str
      above:
        description:
          - Add rule above specific rule/section identified by name (limited to 50 rules if
            search_entire_rulebase is False).
        type: str
      top:
        description:
          - Add rule to the top of a specific section identified by name (limited to 50 rules if
            search_entire_rulebase is False).
        type: str
      bottom:
        description:
          - Add rule to the bottom of a specific section identified by name (limited to 50 rules if
            search_entire_rulebase is False).
        type: str
  search_entire_rulebase:
    description:
      - Whether to search the entire rulebase for a rule that's been edited in its relative_position field to make sure
        there indeed has been a change in its position or the section it might be in.
    type: bool
    default: False
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
      - Available from R80.10 management version.
    type: list
    elements: dict
  content_direction:
    description:
      - On which direction the file types processing is applied.
      - Available from R80.10 management version.
    type: str
    choices: ['any', 'up', 'down']
  content_negate:
    description:
      - True if negate is set for data.
      - Available from R80.10 management version.
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
      - Available from R80.10 management version.
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
          - Available from R80.20 management version.
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
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-access-rule
  cp_mgmt_access_rule:
    layer: Network
    name: Rule 1
    position: 1
    service:
      - SMTP
      - AOL
    vpn: All_GwToGw
    state: present

- name: set-access-rule
  cp_mgmt_access_rule:
    action: Ask
    action_settings:
      enable_identity_captive_portal: true
      limit: Upload_1Gbps
    layer: Network
    name: Rule 1
    state: present

- name: delete-access-rule
  cp_mgmt_access_rule:
    layer: Network
    name: Rule 2
    state: absent
"""

RETURN = """
cp_mgmt_access_rule:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_objects,
    api_call,
    api_call_for_rule,
)


def main():
    argument_spec = dict(
        layer=dict(type="str"),
        position=dict(type="str"),
        relative_position=dict(
            type="dict",
            options=dict(
                below=dict(type="str"),
                above=dict(type="str"),
                top=dict(type="str"),
                bottom=dict(type="str"),
            ),
        ),
        search_entire_rulebase=dict(type="bool", default=False),
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
        content_direction=dict(type="str", choices=["any", "up", "down"]),
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
                            choices=["hours", "days", "weeks", "months"],
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
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
        ignore_warnings=dict(type="bool"),
        ignore_errors=dict(type="bool"),
    )
    argument_spec["vpn_list"]["options"]["directional"]["options"][
        "from"
    ] = dict(type="str")
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )
    api_call_object = "access-rule"

    if module.params["vpn_list"] is not None:
        if module.params["vpn"] is not None:
            raise AssertionError(
                "The use of both 'vpn_list' and 'vpn' arguments isn't allowed"
            )
        module.params["vpn"] = module.params["vpn_list"]
    module.params.pop("vpn_list")

    if module.params["relative_position"] is not None:
        if module.params["position"] is not None:
            raise AssertionError(
                "The use of both 'relative_position' and 'position' arguments isn't allowed"
            )
        module.params["position"] = module.params["relative_position"]
    module.params.pop("relative_position")

    if module.params["action"] is None and module.params["position"] is None:
        module.params.pop("search_entire_rulebase")
        result = api_call(module, api_call_object)
    else:
        result = api_call_for_rule(module, api_call_object)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
