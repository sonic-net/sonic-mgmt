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
module: intersight_iqn_pool
short_description: IQN Pool configuration for Cisco Intersight
description:
  - IQN Pool configuration for Cisco Intersight.
  - Used to configure IQN pools settings on Cisco Intersight managed devices.
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
      - The name assigned to the IQN Pool.
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
      - The user-defined description of the IQN Pool.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  prefix:
    description:
      - The prefix for any IQN blocks created for this pool.
      - IQN Prefix must have the following format "iqn.yyyy-mm.naming-authority"
      - naming-authority is usually the reverse syntax of the Internet domain name of the naming authority.
    type: str
    required: false
  iqn_suffix_blocks:
    description:
      - List of the IQN blocks.
      - Should include the suffix, iqn_from and size per block.
    type: list
    elements: dict
    suboptions:
      suffix:
        description:
          - The suffix for this block of IQNs.
        type: str
        required: true
      iqn_from:
        description:
          - The first suffix number in the block >= 0.
        type: int
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
- name: Create iqn pool
  cisco.intersight.intersight_iqn_pool:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: iqn_pool_1
    description: "Test iqn pool description"
    tags:
      - "Key": "Site"
        "Value": "tag1"
    prefix: "iqn.2025-08.com.cisco"
    iqn_suffix_blocks:
      - "suffix": "iqn"
        "iqn_from": 1
        "size": 20
      - "suffix": "iscsi"
        "iqn_from": 21
        "size": 40
- name: Delete iqn pool
  cisco.intersight.intersight_iqn_pool:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: iqn_pool_1
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "iqn_pool_1",
        "ObjectType": "iqnpool.Pool",
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
        prefix=dict(type='str'),
        iqn_suffix_blocks=dict(
            type='list',
            elements='dict',
            options=dict(
                suffix=dict(type='str', required=True),
                iqn_from=dict(type='int', required=True),
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
    resource_path = '/iqnpool/Pools'
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
    }
    iqn_suffix_blocks_dict = []
    if module.params['state'] == 'present':
        intersight.set_tags_and_description()
        # Validate that iqn_suffix_blocks was passed. We don't mark it as required in order to support absent.
        if not intersight.module.params['iqn_suffix_blocks']:
            module.fail_json(msg="iqn_suffix_blocks parameter must be provided and contain at least one block when state is 'present'.")
        if not intersight.module.params['prefix']:
            module.fail_json(msg="prefix parameter must be provided when state is 'present'.")
        for iqn_suffix_block in intersight.module.params['iqn_suffix_blocks']:
            iqn_suffix_blocks_dict.append({
                "Suffix": iqn_suffix_block['suffix'],
                "From": iqn_suffix_block['iqn_from'],
                "Size": iqn_suffix_block['size']
            })
        intersight.api_body['IqnSuffixBlocks'] = iqn_suffix_blocks_dict
        intersight.api_body['Prefix'] = intersight.module.params['prefix']

    intersight.configure_policy_or_profile(resource_path=resource_path)
    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
