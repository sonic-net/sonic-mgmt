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
module: intersight_uuid_pool_info
short_description: Gather information about UUID Pool in Cisco Intersight
description:
  - Gather information about UUID Pool in L(Cisco Intersight,https://intersight.com).
  - Information can be filtered using Organization and Name. if none is passed all information regarding existing
    uuid pools will be fetched.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization that will have information gathered from.
    type: str
  name:
    description:
      - The name of the UUID Pool that will have information gathered from.
    type: str
author:
  - Shahar Golshani (@sgolshan)
'''

EXAMPLES = r'''
- name: Fetch uuid pool information by name
  cisco.intersight.intersight_uuid_pool_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: lab-uuid-pool

- name: Fetch all uuid pool information
  cisco.intersight.intersight_uuid_pool_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": [
    {
        "Name": "lab-uuid-pool",
        "ObjectType": "uuidpool.Pool",
        "Description": "UUID Pool for lab use",
        "Prefix": "550E8400-E29B-41D4",
        "UuidSuffixBlocks": [
            {
                "From": "A716-446655440000",
                "Size": 100
            },
            {
                "From": "A716-446655441000",
                "Size": 200
            }
        ],
        "Size": 300,
        "Assigned": 0,
        "Reserved": 0,
        "Tags": [
            {
                "Key": "Site",
                "Value": "RCDN"
            }
        ]
    }
  ]
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        organization=dict(type='str'),
        name=dict(type='str')
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to fetch info
    resource_path = '/uuidpool/Pools'

    query_params = intersight.set_query_params()

    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
