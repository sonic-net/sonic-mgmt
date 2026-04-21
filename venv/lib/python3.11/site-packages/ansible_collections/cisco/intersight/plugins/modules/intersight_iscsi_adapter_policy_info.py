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
module: intersight_iscsi_adapter_policy_info
short_description: Gather information about iSCSI Adapter Policies in Cisco Intersight
description:
  - Retrieve information about iSCSI Adapter Policies from L(Cisco Intersight,https://intersight.com).
  - Query policies by organization or policy name.
  - Returns structured data with policy metadata and iSCSI adapter configuration details.
  - If no filters are provided, all iSCSI Adapter Policies will be returned.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization to filter iSCSI Adapter Policies by.
      - Use 'default' for the default organization.
      - When specified, only policies from this organization will be returned.
    type: str
  name:
    description:
      - The exact name of the iSCSI Adapter Policy to retrieve information from.
      - When specified, only the matching policy will be returned.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
# Basic Usage Examples
- name: Fetch all iSCSI Adapter Policies from all organizations
  cisco.intersight.intersight_iscsi_adapter_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
  register: all_iscsi_adapter_policies

# Organization-specific Examples
- name: Fetch all iSCSI Adapter Policies from the default organization
  cisco.intersight.intersight_iscsi_adapter_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
  register: default_org_policies

- name: Fetch all iSCSI Adapter Policies from a custom organization
  cisco.intersight.intersight_iscsi_adapter_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
  register: engineering_policies

# Specific Policy Examples
- name: Fetch a specific iSCSI Adapter Policy by name
  cisco.intersight.intersight_iscsi_adapter_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "iscsi-adapter-policy-01"
  register: specific_policy

- name: Fetch a specific policy from a specific organization
  cisco.intersight.intersight_iscsi_adapter_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Production"
    name: "iscsi-adapter-policy-prod"
  register: specific_org_policy
'''

RETURN = r'''
api_response:
  description:
    - The API response containing iSCSI Adapter Policy information.
    - Returns a list.
  returned: always
  type: list
  sample:
    [
      {
        "Name": "iscsi-adapter-policy-01",
        "ObjectType": "vnic.IscsiAdapterPolicy",
        "Moid": "1234567890abcdef12345678",
        "Description": "iSCSI adapter policy for production servers",
        "ConnectionTimeOut": 30,
        "DhcpTimeout": 120,
        "LunBusyRetryCount": 30,
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
    resource_path = '/vnic/IscsiAdapterPolicies'
    # Get query parameters for policies
    query_params = intersight.set_query_params()
    # Get iSCSI Adapter policies
    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )
    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
