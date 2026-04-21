#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2022, Jeffrey van Pelt <jeff@vanpelt.one>
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
module: discovery_rule
version_added: 3.5.0
short_description: Manage Host Discovery Rules
description:
  - Manage Host Discovery Rules
author:
  - "Jeffrey van Pelt (@Thulium-Drake)"
options:
  name:
    description:
      - Name of the Discovery Rule
    required: true
    type: str
  search:
    description:
      - Expression to match newly discovered hosts with
      - Required if I(state=present)
    type: str
  hostgroup:
    description:
      - Hostgroup to assign hosts to
      - Required if I(state=present)
    type: str
  hostname:
    description:
      - Hostname to assign to discovered host(s)
      - When matching multiple hosts, must provide unique hostnames for each of the discovered hosts
    type: str
  enabled:
    description:
      - Enable or disable the rule
    type: bool
  priority:
    description:
      - Priority of the rule
    type: int
  max_count:
    description:
      - Maximum amount of hosts to provision with the rule
      - 0 means no limit
    type: int
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.entity_state
  - theforeman.foreman.foreman.taxonomy
'''

EXAMPLES = '''
- name: 'Ensure Discovery Rule'
  theforeman.foreman.discovery_rule:
    username: 'admin'
    password: 'secret_password'
    server_url: 'https://foreman.example.com'
    name: 'my-first-disco'
    search: 'mac = bb:bb:bb:bb:bb:bb'
    hostgroup: 'RedHat7-Base'
    hostname: 'servera'
    max_count: 1
    organizations:
      - 'MyOrg'
    locations:
      - 'DC1'

- name: 'Remove Discovery Rule'
  theforeman.foreman.discovery_rule:
    username: 'admin'
    password: 'secret_password'
    server_url: 'https://foreman.example.com'
    name: 'my-first-disco'
    state: 'absent'
'''

RETURN = '''
entity:
  description: Final state of the affected entities grouped by their type.
  returned: success
  type: dict
  contains:
    discovery_rules:
      description: List of discovery rules.
      type: list
      elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import ForemanTaxonomicEntityAnsibleModule


class ForemanDiscoveryRuleModule(ForemanTaxonomicEntityAnsibleModule):
    pass


def main():
    module = ForemanDiscoveryRuleModule(
        foreman_spec=dict(
            name=dict(required=True),
            search=dict(),
            hostgroup=dict(type='entity'),
            hostname=dict(),
            max_count=dict(type='int'),
            hosts_limit=dict(type='int', invisible=True, flat_name='max_count'),
            priority=dict(type='int'),
            enabled=dict(type='bool'),
        ),
        required_if=[
            ['state', 'present', ['hostgroup', 'search']],
        ],
        required_plugins=[('discovery', ['*'])],
    )

    with module.api_connection():
        entity = module.lookup_entity('entity')

        # workround the fact that the API expects `max_count` when modifying the entity
        # but uses `hosts_limit` when showing one
        if entity and 'hosts_limit' in entity:
            entity['max_count'] = entity.pop('hosts_limit')

        module.run()


if __name__ == '__main__':
    main()
