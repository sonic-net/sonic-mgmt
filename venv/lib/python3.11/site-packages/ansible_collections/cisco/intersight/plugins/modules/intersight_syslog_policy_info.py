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
module: intersight_syslog_policy_info
short_description: Gather information about Syslog Policies in Cisco Intersight
description:
  - Gathers information about existing Syslog Policies in L(Cisco Intersight,https://intersight.com).
  - You can filter policies by O(organization) and O(name).
  - If no filters are provided, the module returns all available Syslog Policies.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization to which the Syslog Policy belongs.
    type: str
  name:
    description:
      - The name of the specific Syslog Policy to retrieve.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Fetch a specific Syslog Policy by name
  cisco.intersight.intersight_syslog_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Syslog-Policy-PROD"

- name: Fetch all Syslog Policies
  cisco.intersight.intersight_syslog_policy_info:
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
    },
    {
        "Name": "mac_pool_2",
        "ObjectType": "macpool.Pool",
        "Tags": [
            {
                "Key": "Site1",
                "Value": "tag1"
            },
            {
                "Key": "Site2",
                "Value": "tag2"
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
    resource_path = '/syslog/Policies'

    query_params = intersight.set_query_params()

    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
