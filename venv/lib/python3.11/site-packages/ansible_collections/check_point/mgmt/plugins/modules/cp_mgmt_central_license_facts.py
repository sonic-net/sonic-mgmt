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
module: cp_mgmt_central_license_facts
short_description: Get central-license objects facts on Checkpoint over Web Services API
description:
  - Get central-license objects facts on Checkpoint devices.
  - All operations are performed over Web Services API.
  - This module handles both operations, get a specific object and get several objects,
    For getting a specific object use the parameter 'signature'.
  - Available from R81.20 JHF management version.
version_added: "5.2.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  signature:
    description:
      - The license's signature. This parameter is relevant only for getting a specific object.
    type: str
extends_documentation_fragment: checkpoint_facts
"""

EXAMPLES = """
- name: show-central-license
  cp_mgmt_central_license_facts:
    signature: dLLLLL-WWWWWW-ZZZZZZ-QQQQQQ

- name: show-central-licenses
  cp_mgmt_show_central_licenses:
"""

RETURN = """
ansible_facts:
  description: The checkpoint object facts.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_facts,
    api_call_facts,
)


def main():
    argument_spec = dict(
        signature=dict(type='str')
    )
    argument_spec.update(checkpoint_argument_spec_for_facts)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    api_call_object = "central-license"
    api_call_object_plural_version = "central-licenses"

    result = api_call_facts(module, api_call_object, api_call_object_plural_version)
    module.exit_json(ansible_facts=result)


if __name__ == '__main__':
    main()
