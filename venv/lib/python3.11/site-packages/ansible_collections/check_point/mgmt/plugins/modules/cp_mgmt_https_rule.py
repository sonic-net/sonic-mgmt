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
module: cp_mgmt_https_rule
short_description: Manages https-rule objects on Checkpoint over Web Services API
description:
  - Manages https-rule objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R80.40 management version.
version_added: "6.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  position:
    description:
      - Position in the rulebase.
    type: str
  layer:
    description:
      - Layer that holds the Object. Identified by the Name or UID.
    type: str
  name:
    description:
      - Rule name.
    type: str
    required: True
  destination:
    description:
      - Collection of Network objects identified by Name or UID that represents connection destination.
    type: list
    elements: str
  service:
    description:
      - Collection of Network objects identified by Name or UID that represents connection service.
    type: list
    elements: str
  source:
    description:
      - Collection of Network objects identified by Name or UID that represents connection source.
    type: list
    elements: str
  action:
    description:
      - Rule inspect level. "Bypass" or "Inspect".
    type: str
  blade:
    description:
      - Blades for HTTPS Inspection. Identified by Name or UID of the blade.
    type: list
    elements: str
  certificate:
    description:
      - Internal Server Certificate identified by Name or UID, otherwise, "Outbound Certificate" is a default value.
    type: str
  destination_negate:
    description:
      - TRUE if "negate" value is set for Destination.
    type: bool
  enabled:
    description:
      - Enable/Disable the rule.
    type: bool
  install_on:
    description:
      - Which Gateways identified by the name or UID to install the policy on.
    type: list
    elements: str
  service_negate:
    description:
      - TRUE if "negate" value is set for Service.
    type: bool
  site_category:
    description:
      - Collection of Site Categories objects identified by the name or UID.
    type: list
    elements: str
  site_category_negate:
    description:
      - TRUE if "negate" value is set for Site Category.
    type: bool
  source_negate:
    description:
      - TRUE if "negate" value is set for Source.
    type: bool
  tags:
    description:
      - Collection of tag identifiers.
      - Available from R81.20 JHF management version.
    type: list
    elements: str
  track:
    description:
      - a "None","Log","Alert","Mail","SNMP trap","Mail","User Alert 1", "User Alert 2", "User Alert 3".
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
- name: add-https-rule
  cp_mgmt_https_rule:
    layer: Default Outbound Layer
    name: FirstRule
    position: 1
    state: present

- name: set-https-rule
  cp_mgmt_https_rule:
    name: FirstRule
    position: 2
    layer: Default Outbound Layer
    state: present

- name: delete-https-rule
  cp_mgmt_https_rule:
    name: FirstRule
    layer: Default Outbound Layer
    state: absent
"""

RETURN = """
cp_mgmt_https_rule:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call, api_call_for_rule


def main():
    argument_spec = dict(
        position=dict(type='str'),
        layer=dict(type='str'),
        name=dict(type='str', required=True),
        destination=dict(type='list', elements='str'),
        service=dict(type='list', elements='str'),
        source=dict(type='list', elements='str'),
        action=dict(type='str'),
        blade=dict(type='list', elements='str'),
        certificate=dict(type='str'),
        destination_negate=dict(type='bool'),
        enabled=dict(type='bool'),
        install_on=dict(type='list', elements='str'),
        service_negate=dict(type='bool'),
        site_category=dict(type='list', elements='str'),
        site_category_negate=dict(type='bool'),
        source_negate=dict(type='bool'),
        tags=dict(type='list', elements='str'),
        track=dict(type='str'),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'https-rule'

    if module.params["position"] is None:
        result = api_call(module, api_call_object)
    else:
        result = api_call_for_rule(module, api_call_object)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
