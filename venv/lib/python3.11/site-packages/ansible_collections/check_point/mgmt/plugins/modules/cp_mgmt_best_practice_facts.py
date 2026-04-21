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
module: cp_mgmt_best_practice_facts
short_description: Get best-practice objects facts on Checkpoint over Web Services API
description:
  - Get best-practice objects facts on Checkpoint devices.
  - All operations are performed over Web Services API.
  - This module handles both operations, get a specific object and get several objects,
    For getting a specific object use the parameter 'name' or 'best_practice_id'.
  - Available from R82.10 management version.
version_added: "6.7.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  best_practice_id:
    description:
      - Best Practice ID.
    type: str
  name:
    description:
      - Best Practice Name.
        This parameter is relevant only for getting a specific object.
    type: str
  show_regulations:
    description:
      - Show the applicable regulations of the Best Practice.
    type: bool
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  blade:
    description:
      - Returns all the relevant Best Practices of the selected Software Blades. When empty will return all the Best Practices.
    type: list
    elements: str
    choices: ['firewall', 'gaia-os', 'anti-bot', 'anti-spam-and-mail', 'anti-virus', 'application-control', 'data-loss-prevention',
             'identity-awareness', 'ips', 'ipsec-vpn', 'mobile-access', 'threat-emulation', 'url-filtering', 'threat-prevention']
  limit:
    description:
      - The maximal number of returned results.
        This parameter is relevant only for getting few objects.
      - Valid values are between 1 and 500.
    type: int
  offset:
    description:
      - Number of the results to initially skip.
        This parameter is relevant only for getting few objects.
    type: int
  status:
    description:
      - Returns all the relevant best practices with the selected statuses. When empty will return all best practices.
    type: list
    elements: str
    choices: ['secure', 'good', 'medium', 'poor', 'n/a']
  gateway_name:
    description:
      - Returns all the relevant Best Practices of the selected Security Gateway object.
    type: str
  defined_by:
    description:
      - Returns all the relevant Best Practices of the selected type.
    type: str
    choices: ['user-defined', 'system-defined', 'any']
  show_only_local_domain:
    description:
      - Indicates whether the query should return only objects from the current local domain. This parameter is only valid for local domain.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_facts
"""

EXAMPLES = """
- name: show-best-practice
  cp_mgmt_best_practice_facts:
    best_practice_id: FW183

- name: show-best-practices
  cp_mgmt_best_practice_facts:
    limit: '5'
"""

RETURN = """
ansible_facts:
  description: The checkpoint object facts.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_facts, api_call_facts


def main():
    argument_spec = dict(
        best_practice_id=dict(type='str'),
        name=dict(type='str'),
        show_regulations=dict(type='bool'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        blade=dict(type='list', elements='str', choices=['firewall', 'gaia-os', 'anti-bot', 'anti-spam-and-mail', 'anti-virus',
                                                         'application-control', 'data-loss-prevention', 'identity-awareness', 'ips',
                                                         'ipsec-vpn', 'mobile-access', 'threat-emulation', 'url-filtering', 'threat-prevention']),
        limit=dict(type='int'),
        offset=dict(type='int'),
        status=dict(type='list', elements='str', choices=['secure', 'good', 'medium', 'poor', 'n/a']),
        gateway_name=dict(type='str'),
        defined_by=dict(type='str', choices=['user-defined', 'system-defined', 'any']),
        show_only_local_domain=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_facts)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    api_call_object = "best-practice"
    api_call_object_plural_version = "best-practices"

    result = api_call_facts(module, api_call_object, api_call_object_plural_version)
    module.exit_json(ansible_facts=result)


if __name__ == '__main__':
    main()
