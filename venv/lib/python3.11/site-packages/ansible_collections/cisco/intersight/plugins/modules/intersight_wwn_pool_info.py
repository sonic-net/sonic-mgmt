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
module: intersight_wwn_pool_info
short_description: Gather information about WWN Pool in Cisco Intersight
description:
  - Gather information about WWNN/WWPN Pool in L(Cisco Intersight,https://intersight.com).
  - Information can be filtered using Organization, Name and PoolPurpose. if none is passed all information regarding existing
    WWN pools will be fetched.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization that will have information gathered from.
    type: str
  name:
    description:
      - The name of the WWNN/WWPN Pool that will have information gathered from.
    type: str
  pool_purpose:
    description:
      - The pool type WWNN or WWPN.
      - WWNN and WWPN pools can have the same name. if none is passed all information regardless of pool purpose will be fetched.
    type: str
author:
  - Shahar Golshani (@sgolshan)
'''

EXAMPLES = r'''
- name: Fetch wwn pool information by name
  cisco.intersight.intersight_wwn_pool_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: wwn_pool_1

- name: Fetch all wwn pool information
  cisco.intersight.intersight_wwn_pool_info:
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
          "Name": "wwn_pool_1",
          "ObjectType": "fcpool.Pool",
          "Tags": [
              {
                  "Key": "Site",
                  "Value": "tag1"
              }
          ],
          "IdBlocks": [
              {
                  "ClassId": "fcpool.Block",
                  "From": "20:00:00:25:B5:00:00:00",
                  "ObjectType": "fcpool.Block",
                  "Size": 100,
                  "To": "20:00:00:25:B5:00:00:63"
              }
          ],
          "PoolPurpose": "WWPN"
      }
    ]
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        organization=dict(type='str'),
        name=dict(type='str'),
        pool_purpose=dict(type='str')
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to fetch info
    resource_path = '/fcpool/Pools'

    query_params = intersight.set_query_params(filter_key="PoolPurpose", filter_value=intersight.module.params['pool_purpose'])
    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
