#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2023 Evgeni Golov <evgeni@golov.de>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: smart_class_parameter_override_value
version_added: 3.14.0
short_description: Manage Smart Class Parameter Override Values
description:
  - Manage Smart Class Parameter Override Values
author:
  - "Evgeni Golov (@evgeni)"
options:
  puppetclass:
    description:
    - Puppet Class the Smart Class Parameter belongs to
    type: str
    required: true
    aliases:
      - puppetclass_name
  smart_class_parameter:
    description:
    - Smart Class Parameter the Override Value belongs to
    required: true
    type: str
    aliases:
      - parameter
  match:
    description:
    - Override match
    required: true
    type: str
  omit:
    description:
    - Foreman will not send this parameter in classification output
    required: false
    type: bool
  value:
    description:
    - Override value, required if omit is false
    required: false
    type: raw

extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.entity_state
'''

EXAMPLES = '''
- name: Set ntp::servers override value
  theforeman.foreman.smart_class_parameter_override_value:
    server_url: "https://foreman.example.com"
    username: "admin"
    password: "changeme"
    puppetclass: ntp
    smart_class_parameter: servers
    match: domain=example.org
    value:
      - ntp1.example.org
      - ntp2.example.org
    state: present
'''

RETURN = '''
entity:
  description: Final state of the affected entities grouped by their type.
  returned: success
  type: dict
  contains:
    override_values:
      description: List of override_values.
      type: list
      elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import ForemanEntityAnsibleModule, parameter_value_to_str


class ForemanOverrideValueModule(ForemanEntityAnsibleModule):
    pass


def main():
    module = ForemanOverrideValueModule(
        foreman_spec=dict(
            puppetclass=dict(required=True, type='entity', ensure=False, aliases=['puppetclass_name']),
            smart_class_parameter=dict(required=True, type='entity', scope=['puppetclass'], search_by='parameter', aliases=['parameter']),
            match=dict(required=True, type='str'),
            value=dict(required=False, type='raw'),
            omit=dict(required=False, type='bool'),
        ),
    )

    module_params = module.foreman_params

    with module.api_connection():
        scp = module.lookup_entity('smart_class_parameter')
        parameter_type = scp.get('parameter_type', 'string')
        scope = {'smart_class_parameter_id': scp['id']}
        override_values = module.list_resource('override_values', params=scope)
        entity = next((ov for ov in override_values if ov['match'] == module_params['match']), None)
        if entity is not None:
            # this is a hack, otherwise update_entity() tries to update that
            entity['smart_class_parameter_id'] = scp['id']
            entity['value'] = parameter_value_to_str(entity['value'], parameter_type)
        module.set_entity('entity', entity)
        if 'value' in module_params:
            module_params['value'] = parameter_value_to_str(module_params['value'], parameter_type)
        module.ensure_entity('override_values', module_params, entity, params=scope)


if __name__ == '__main__':
    main()
