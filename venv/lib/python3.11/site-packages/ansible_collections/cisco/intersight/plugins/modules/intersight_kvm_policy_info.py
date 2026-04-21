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
module: intersight_kvm_policy_info
short_description: Gather information about KVM Policies in Cisco Intersight
description:
  - Gather information about KVM Policies in L(Cisco Intersight,https://intersight.com).
  - Information can be filtered by O(organization) and O(name).
  - If no filters are passed, all KVM Policies will be returned.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization the KVM Policy belongs to.
    type: str
  name:
    description:
      - The name of the KVM Policy to gather information from.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Fetch a specific KVM Policy by name
  cisco.intersight.intersight_kvm_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Custom-KVM-Policy"

- name: Fetch all KVM Policies in a specific Organization
  cisco.intersight.intersight_kvm_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"

- name: Fetch all KVM Policies
  cisco.intersight.intersight_kvm_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: list
  sample:
    "api_response": [
    {
        "Name": "Custom-KVM-Policy",
        "ObjectType": "kvm.Policy",
        "Enabled": true,
        "MaximumSessions": 2,
        "RemotePort": 3000,
        "EnableVideoEncryption": true,
        "EnableLocalServerVideo": false,
        "TunneledKvmEnabled": true,
        "Tags": [
            {
                "Key": "Owner",
                "Value": "DevOps"
            }
        ]
    },
    {
        "Name": "Disabled-KVM-Policy",
        "ObjectType": "kvm.Policy",
        "Enabled": false,
        "Tags": [
            {
                "Key": "Security",
                "Value": "Disabled"
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
    resource_path = '/kvm/Policies'

    query_params = intersight.set_query_params()

    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
