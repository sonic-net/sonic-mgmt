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
module: intersight_ethernet_network_group_policy_info
short_description: Gather information about Ethernet Network Group Policies in Cisco Intersight
description:
  - Gather information about Ethernet Network Group Policies in L(Cisco Intersight,https://intersight.com).
  - Information can be filtered by O(organization) and O(name).
  - If no filters are passed, all Ethernet Network Group Policies will be returned.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization the Ethernet Network Group Policy belongs to.
    type: str
  name:
    description:
      - The name of the Ethernet Network Group Policy to gather information from.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Fetch a specific Ethernet Network Group Policy by name
  cisco.intersight.intersight_ethernet_network_group_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "qinq-policy"

- name: Fetch all Ethernet Network Group Policies in a specific Organization
  cisco.intersight.intersight_ethernet_network_group_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"

- name: Fetch all Ethernet Network Group Policies
  cisco.intersight.intersight_ethernet_network_group_policy_info:
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
        "Name": "regular-vlans-policy",
        "ObjectType": "fabric.EthNetworkGroupPolicy",
        "VlanSettings": {
            "QinqEnabled": false,
            "AllowedVlans": "1-8,12,16"
        },
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Production"
            }
        ]
    },
    {
        "Name": "qinq-policy",
        "ObjectType": "fabric.EthNetworkGroupPolicy",
        "VlanSettings": {
            "QinqEnabled": true,
            "QinqVlan": 4,
            "NativeVlan": 1
        },
        "Tags": [
            {
                "Key": "Site",
                "Value": "DataCenter-A"
            },
            {
                "Key": "Application",
                "Value": "Database"
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

    resource_path = '/fabric/EthNetworkGroupPolicies'

    query_params = intersight.set_query_params()

    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
