#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: intersight_wwn_pool
short_description: WWNN/WWPN Pool configuration for Cisco Intersight
description:
  - WWNN/WWPN Pool configuration for Cisco Intersight.
  - Used to configure WWN pools settings on Cisco Intersight managed devices.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs).
extends_documentation_fragment: intersight
options:
  state:
    description:
      - If C(present), will verify the resource is present and will create if needed.
      - If C(absent), will verify the resource is absent and will delete if needed.
    type: str
    choices: [present, absent]
    default: present
  organization:
    description:
      - The name of the Organization this resource is assigned to.
      - Profiles, Policies, and Pools that are created within a Custom Organization are applicable only to devices in the same Organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the WWNN/WWPN Pool.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
      - Two pools WWNN and WWNP can have the same name.
    type: str
    required: true
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  description:
    description:
      - The user-defined description of the WWNN/WWPN Pool.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  pool_purpose:
    description:
      - The pool type WWNN or WWPN.
      - Required also for C(absent) - Two pools WWNN and WWNP can have the same name.
    type: str
    required: true
  id_blocks:
    description:
      - WWN Blocks
      - Block of WWNN/WWPN Identifiers.
    type: list
    elements: dict
    suboptions:
      wwn_from:
        description:
          - Starting WWN identifier of the block must be in hexadecimal format xx:xx:xx:xx:xx:xx:xx:xx.
          - Allowed ranges are 20:00:00:00:00:00:00:00 to 20:FF:FF:FF:FF:FF:FF:FF
          - Or from 50:00:00:00:00:00:00:00 to 5F:FF:FF:FF:FF:FF:FF:FF.
          - To ensure uniqueness of WWN's in the SAN fabric, you are strongly encouraged to use the following WWN prefix; 20:00:00:25:B5:xx:xx:xx.
        type: str
        required: true
      size:
        description:
          - Number of identifiers this block can hold.
          - This value must be an integer between 1 and 1024, inclusive.
        type: int
        required: true
author:
  - Shahar Golshani (@sgolshan)
'''

EXAMPLES = r'''
- name: Create WWNN pool
  cisco.intersight.intersight_wwn_pool:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: wwn_pool_1
    description: "Test WWNN pool description"
    tags:
      - "Key": "Site"
        "Value": "tag1"
    pool_purpose: "WWNN"
    id_blocks:
      - "wwn_from": "20:00:00:25:B5:00:00:00"
        "size": 100
      - "wwn_from": "20:00:00:25:B5:FF:00:00"
        "size": 100

- name: Create WWPN pool
  cisco.intersight.intersight_wwn_pool:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: wwn_pool_2
    description: "Test WWPN pool description"
    tags:
      - "Key": "Site"
        "Value": "tag2"
    pool_purpose: "WWPN"
    id_blocks:
      - "wwn_from": "20:00:00:25:B5:00:FF:00"
        "size": 200
      - "wwn_from": "20:00:00:25:B5:FF:FF:00"
        "size": 200

- name: Delete WWN pool
  cisco.intersight.intersight_wwn_pool:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: wwn_pool_1
    pool_purpose: "WWPN"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "wwn_pool_1",
        "ObjectType": "fcpool.Pool",
        "Tags": [
            {
                "Key": "Site",
                "Value": "tag1"
            },
            {
                "Key": "Site2",
                "Value": "tag2"
            }
        ],
        "IdBlocks": [
            {
                "ClassId": "fcpool.Block",
                "ObjectType": "fcpool.Block",
                "Size": 100,
                "From": "20:00:00:25:B5:00:00:00",
                "To": "20:00:00:25:B5:00:00:63"
            },
            {
                "ClassId": "fcpool.Block",
                "ObjectType": "fcpool.Block",
                "Size": 100,
                "From": "20:00:00:25:B5:FF:00:00",
                "To": "20:00:00:25:B5:FF:00:63"
            }
        ],
        "PoolPurpose": "WWNN  ",
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        pool_purpose=dict(type='str', required=True),
        id_blocks=dict(
            type='list',
            elements='dict',
            options=dict(
                wwn_from=dict(type='str', required=True),
                size=dict(type='int', required=True)
            )
        )
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''
    # Resource path used to configure policy
    resource_path = '/fcpool/Pools'
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
    }
    id_blocks_dict = []
    if module.params['state'] == 'present':
        intersight.set_tags_and_description()
        # Validate that required parameters were passed. We don't mark it as required in order to support absent.
        if not intersight.module.params['id_blocks']:
            module.fail_json(msg="wwn id_blocks parameter must be provided and contain at least one block when state is 'present'.")
        for id_block in intersight.module.params['id_blocks']:
            id_blocks_dict.append({
                "From": id_block['wwn_from'],
                "Size": id_block['size']
            })
        intersight.api_body['IdBlocks'] = id_blocks_dict
        intersight.api_body['PoolPurpose'] = intersight.module.params['pool_purpose']

    intersight.configure_policy_or_profile(resource_path=resource_path, filter_key="PoolPurpose", filter_value=intersight.module.params['pool_purpose'])
    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
