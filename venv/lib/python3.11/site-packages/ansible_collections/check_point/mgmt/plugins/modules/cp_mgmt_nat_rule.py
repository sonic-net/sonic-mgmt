#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
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

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: cp_mgmt_nat_rule
short_description: Manages nat-rule objects on Checkpoint over Web Services API.
description:
  - Manages nat-rule objects on Checkpoint devices including creating, updating and removing objects.
  -  Minimum version required is 1.7.1 and JHF with PMTR-88097.
  - All operations are performed over Web Services API.
  - Available from R80 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  package:
    description:
      - Name of the package.
      - Available from R80.10 management version.
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
      - Rule name.
      - Available from R81 management version.
    type: str
    required: True
  enabled:
    description:
      - Enable/Disable the rule.
    type: bool
  install_on:
    description:
      - Which Gateways identified by the name or UID to install the policy on.
    type: list
    elements: str
  method:
    description:
      - Nat method.
    type: str
    choices: ['static', 'hide', 'nat64', 'nat46', 'cgnat']
  original_destination:
    description:
      - Original destination.
    type: str
  original_service:
    description:
      - Original service.
    type: str
  original_source:
    description:
      - Original source.
    type: str
  translated_destination:
    description:
      - Translated  destination.
    type: str
  translated_service:
    description:
      - Translated  service.
    type: str
  translated_source:
    description:
      - Translated  source.
    type: str
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
- name: add-nat-rule
  cp_mgmt_nat_rule:
    name: nat_rule1
    comments: comment example1 nat999
    enabled: false
    install_on:
      - Policy Targets
    original_destination: All_Internet
    original_source: Any
    package: standard
    position: 1
    state: present

- name: set-nat-rule
  cp_mgmt_nat_rule:
    name: nat_rule1
    comments: rule for RND members  RNDNetwork-> RND to Internal Network
    enabled: false
    original_service: ssh_version_2
    original_source: Any
    package: standard
    state: present

- name: delete-nat-rule
  cp_mgmt_nat_rule:
    name: nat_rule1
    package: standard
    state: absent
"""

RETURN = """
cp_mgmt_nat_rule:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call_for_rule


def main():
    argument_spec = dict(
        package=dict(type='str'),
        position=dict(type='str'),
        relative_position=dict(type='dict', options=dict(
            below=dict(type='str'),
            above=dict(type='str'),
            top=dict(type='str'),
            bottom=dict(type='str')
        )),
        search_entire_rulebase=dict(type='bool', default=False),
        name=dict(type='str', required=True),
        enabled=dict(type='bool'),
        install_on=dict(type='list', elements='str'),
        method=dict(type='str', choices=['static', 'hide', 'nat64', 'nat46', 'cgnat']),
        original_destination=dict(type='str'),
        original_service=dict(type='str'),
        original_source=dict(type='str'),
        translated_destination=dict(type='str'),
        translated_service=dict(type='str'),
        translated_source=dict(type='str'),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'nat-rule'

    if module.params["relative_position"] is not None:
        if module.params["position"] is not None:
            raise AssertionError("The use of both 'relative_position' and 'position' arguments isn't allowed")
        module.params["position"] = module.params["relative_position"]
    module.params.pop("relative_position")

    result = api_call_for_rule(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
