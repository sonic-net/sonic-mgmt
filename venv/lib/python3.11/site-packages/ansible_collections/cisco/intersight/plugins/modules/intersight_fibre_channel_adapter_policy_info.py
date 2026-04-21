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
module: intersight_fibre_channel_adapter_policy_info
short_description: Gather information about Fibre Channel Adapter Policies in Cisco Intersight
description:
  - Retrieve information about Fibre Channel Adapter Policies from L(Cisco Intersight,https://intersight.com).
  - Query policies by organization or policy name.
  - Returns structured data with policy metadata and Fibre Channel Adapter configuration details.
  - If no filters are provided, all Fibre Channel Adapter Policies will be returned.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization to filter Fibre Channel Adapter Policies by.
      - Use 'default' for the default organization.
      - When specified, only policies from this organization will be returned.
    type: str
  name:
    description:
      - The exact name of the Fibre Channel Adapter Policy to retrieve information from.
      - When specified, only the matching policy will be returned.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
# Basic Usage Examples
- name: Fetch all Fibre Channel Adapter Policies from all organizations
  cisco.intersight.intersight_fibre_channel_adapter_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
  register: all_fc_adapter_policies

# Organization-specific Examples
- name: Fetch all Fibre Channel Adapter Policies from the default organization
  cisco.intersight.intersight_fibre_channel_adapter_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
  register: default_org_policies

- name: Fetch all Fibre Channel Adapter Policies from a custom organization
  cisco.intersight.intersight_fibre_channel_adapter_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
  register: engineering_policies

# Specific Policy Examples
- name: Fetch a specific Fibre Channel Adapter Policy by name
  cisco.intersight.intersight_fibre_channel_adapter_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "fc-adapter-policy-01"
  register: specific_policy

- name: Fetch a specific policy from a specific organization
  cisco.intersight.intersight_fibre_channel_adapter_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Production"
    name: "fc-adapter-policy-prod"
  register: specific_org_policy
'''

RETURN = r'''
api_response:
  description:
    - The API response containing Fibre Channel Adapter Policy information.
    - Returns a list.
  returned: always
  type: list
  sample:
    [
      {
        "Name": "fc-adapter-policy-01",
        "ObjectType": "vnic.FcAdapterPolicy",
        "Moid": "1234567890abcdef12345678",
        "Description": "Fibre Channel Adapter policy for production servers",
        "ErrorRecoverySettings": {
          "Enabled": true,
          "PortDownTimeout": 5000,
          "LinkDownTimeout": 20000,
          "IoRetryTimeout": 8,
          "IoRetryCount": 10
        },
        "ErrorDetectionTimeout": 5000,
        "ResourceAllocationTimeout": 15000,
        "FlogiSettings": {
          "Retries": 12,
          "Timeout": 8000
        },
        "PlogiSettings": {
          "Retries": 12,
          "Timeout": 30000
        },
        "InterruptSettings": {
          "Mode": "MSIx"
        },
        "IoThrottleCount": 1024,
        "LunCount": 4096,
        "LunQueueDepth": 254,
        "RxQueueSettings": {
          "RingSize": 128
        },
        "TxQueueSettings": {
          "RingSize": 128
        },
        "ScsiQueueSettings": {
          "Count": 8,
          "RingSize": 512
        },
        "Organization": {
          "Name": "default",
          "ObjectType": "organization.Organization",
          "Moid": "abcdef1234567890abcdef12"
        },
        "Tags": [
          {
            "Key": "Environment",
            "Value": "Production"
          },
          {
            "Key": "Owner",
            "Value": "Storage-Team"
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

    # Resource path used to fetch policy info
    resource_path = '/vnic/FcAdapterPolicies'

    # Get query parameters for policies
    query_params = intersight.set_query_params()

    # Get Fibre Channel Adapter policies
    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )
    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
