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
module: intersight_mac_pool
short_description: MAC Pool configuration for Cisco Intersight
description:
  - MAC Pool configuration for Cisco Intersight.
  - Used to configure MAC pools settings on Cisco Intersight managed devices.
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
      - The name assigned to the MAC Pool.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  description:
    description:
      - The user-defined description of the MAC Pool.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  mac_blocks:
    description:
      - List of the MAC blocks.
      - Should include the address_from and size per block.
    type: list
    elements: dict
    suboptions:
      address_from:
        description:
          - Starting address of the block must be in hexadecimal format xx:xx:xx:xx:xx:xx.
          - To ensure uniqueness of MACs in the LAN fabric, you are strongly encouraged to use the following MAC prefix 00:25:B5:xx:xx:xx.
        type: str
        required: true
      size:
        description:
          - Number of identifiers this block can hold.
          - This value must be an integer between 1 and 1024, inclusive.
        type: int
        required: true
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create mac pool
  cisco.intersight.intersight_mac_pool:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: mac_pool_1
    description: "Test mac pool description"
    tags:
      - "Key": "Site"
        "Value": "tag1"
      - "Key": "Site2"
        "Value": "tag2"
    mac_blocks:
      - "address_from": "00:25:B5:00:00:00"
        "size": 20
- name: Delete mac pool
  cisco.intersight.intersight_mac_pool:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: mac_pool_1
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "mac_pool_1",
        "ObjectType": "macpool.Pool",
        "Tags": [
            {
                "Key": "Site",
                "Value": "tag1"
            },
            {
                "Key": "Site2",
                "Value": "tag2"
            }
        ]
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
        mac_blocks=dict(
            type='list',
            elements='dict',
            options=dict(
                address_from=dict(type='str', required=True),
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
    resource_path = '/macpool/Pools'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
    }
    mac_blocks_dict = []
    if module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Validate that mac_blocks was passed. We don't mark it as required in order to support absent.
        if not intersight.module.params['mac_blocks']:
            module.fail_json(msg="mac_blocks parameter must be provided and contain at least one block when state is 'present'.")

        for mac_block in intersight.module.params['mac_blocks']:
            mac_blocks_dict.append({
                "From": mac_block['address_from'],
                "Size": mac_block['size']
            })
        intersight.api_body['MacBlocks'] = mac_blocks_dict

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
