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
module: intersight_uuid_pool
short_description: UUID Pool configuration for Cisco Intersight
description:
  - UUID Pool configuration for Cisco Intersight.
  - Used to configure UUID pools settings on Cisco Intersight managed devices.
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
      - The name assigned to the UUID Pool.
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
      - The user-defined description of the UUID Pool.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  prefix:
    description:
      - The UUID prefix used for all UUID suffix blocks.
      - UUID must be in uppercase in order to support idempotency.
      - The prefix must be in the format XXXXXXXX-XXXX-XXXX (8-4-4) where X is a hexadecimal character (0-9, A-F).
      - This prefix will be combined with the suffix blocks to form complete UUIDs.
      - Required for C(state=present)
    type: str
  uuid_suffix_blocks:
    description:
      - List of UUID suffix blocks that define the range of UUIDs available in the pool.
      - Each block defines a starting suffix and the number of consecutive UUIDs in that block.
      - Required for C(state=present)
    type: list
    elements: dict
    suboptions:
      from:
        description:
          - The starting UUID suffix for this block.
          - UUID must be in uppercase in order to support idempotency.
          - The suffix must be in the format XXXX-XXXXXXXXXXXX (4-12) where X is a hexadecimal character (0-9, A-F).
          - This suffix will be combined with the pool prefix to form complete UUIDs.
        type: str
      size:
        description:
          - The number of consecutive UUIDs in this block.
          - Must be a positive integer representing how many UUIDs are available starting from the 'from' suffix.
        type: int
author:
  - Shahar Golshani (@sgolshan)
'''

EXAMPLES = r'''
- name: Configure UUID Pool
  cisco.intersight.intersight_uuid_pool:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: lab-uuid-pool
    description: UUID Pool for lab use
    prefix: "550E8400-E29B-41D4"
    uuid_suffix_blocks:
      - from: "A716-446655440000"
        size: 100
      - from: "A716-446655441000"
        size: 200
    tags:
      - Key: Site
        Value: RCDN

- name: Delete UUID Pool
  cisco.intersight.intersight_uuid_pool:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: lab-uuid-pool
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "AccountMoid": "",
        "Ancestors": [],
        "Assigned": 0,
        "AssignmentOrder": "sequential",
        "ClassId": "uuidpool.Pool",
        "CreateTime": "",
        "Description": "UUID Pool for lab use",
        "DomainGroupMoid": "",
        "ModTime": "",
        "Moid": "",
        "Name": "lab-uuid-pool",
        "ObjectType": "uuidpool.Pool",
        "Organization": {},
        "Owners": [],
        "PermissionResources": [],
        "Prefix": "550E8400-E29B-41D4",
        "Reservations": [],
        "Reserved": 0,
        "ShadowPools": [],
        "SharedScope": "",
        "Size": 300,
        "Tags": [
            {
                "Key": "Site",
                "Value": "RCDN"
            }
        ],
        "UuidSuffixBlocks": [
            {
                "From": "A716-446655440000",
                "Size": 100
            },
            {
                "From": "A716-446655441000",
                "Size": 200
            }
        ]
    }
'''


import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def validate_uuid_format(uuid_string, field_sizes):
    """
    Validate UUID format with flexible field sizes
    where x represents a hexadecimal character (0-9, A-F)
    Args:
        uuid_string (str): The UUID string to validate
        field_sizes (list): List of integers representing the size of each field
                           (e.g., [4, 4, 8] for XXXX-XXXX-XXXXXXXX format)
    Returns:
        bool: True if valid, False otherwise
    """
    if not uuid_string or not field_sizes:
        return False

    # Build pattern dynamically based on field sizes
    pattern_parts = []
    for size in field_sizes:
        pattern_parts.append(f'[0-9A-F]{{{size}}}')

    pattern = f'^{"-".join(pattern_parts)}$'
    return bool(re.match(pattern, uuid_string))


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        prefix=dict(type='str'),
        uuid_suffix_blocks=dict(type='list', elements='dict'),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
        required_if=[
            ('state', 'present', ['prefix', 'uuid_suffix_blocks']),
        ],
    )

    # Validate UUID prefix format (xxxx-xxxx-xxxxxxxx)
    if module.params['prefix'] and not validate_uuid_format(module.params['prefix'], [8, 4, 4]):
        module.fail_json(msg="Invalid UUID prefix format. Expected: XXXXXXXX-XXXX-XXXX (where X is a hexadecimal character)")

    # Validate UUID suffix blocks (xxxx-xxxxxxxxxxxx)
    if module.params['uuid_suffix_blocks']:
        for uuid_block in module.params['uuid_suffix_blocks']:
            if 'from' in uuid_block and uuid_block['from'] and not validate_uuid_format(uuid_block['from'], [4, 12]):
                module.fail_json(msg="Invalid UUID suffix format in uuid_suffix_blocks. Expected: XXXX-XXXXXXXXXXXX (where X is a hexadecimal character)")

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure pool
    resource_path = '/uuidpool/Pools'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],

    }
    if module.params['state'] == 'present':
        intersight.set_tags_and_description()
        intersight.api_body['Prefix'] = intersight.module.params['prefix']
        UuidSuffixBlocks = []
        for uuid_block in intersight.module.params['uuid_suffix_blocks']:
            block = {}
            block['From'] = uuid_block['from']
            block['Size'] = uuid_block['size']
            UuidSuffixBlocks.append(block)
        intersight.api_body['UuidSuffixBlocks'] = UuidSuffixBlocks

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
