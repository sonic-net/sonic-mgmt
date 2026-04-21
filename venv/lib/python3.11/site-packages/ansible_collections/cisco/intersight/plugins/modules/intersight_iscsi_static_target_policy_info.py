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
module: intersight_iscsi_static_target_policy_info
short_description: Gather information about iSCSI Static Target Policies in Cisco Intersight
description:
  - Retrieve information about iSCSI Static Target Policies from L(Cisco Intersight,https://intersight.com).
  - Query policies by organization or policy name.
  - Returns structured data with policy metadata and iSCSI target configuration details.
  - If no filters are provided, all iSCSI Static Target Policies will be returned.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization to filter iSCSI Static Target Policies by.
      - Use 'default' for the default organization.
      - When specified, only policies from this organization will be returned.
    type: str
  name:
    description:
      - The exact name of the iSCSI Static Target Policy to retrieve information from.
      - When specified, only the matching policy will be returned.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
# Basic Usage Examples
- name: Fetch all iSCSI Static Target Policies from all organizations
  cisco.intersight.intersight_iscsi_static_target_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
  register: all_iscsi_policies

# Organization-specific Examples
- name: Fetch all iSCSI Static Target Policies from the default organization
  cisco.intersight.intersight_iscsi_static_target_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
  register: default_org_policies

- name: Fetch all iSCSI Static Target Policies from a custom organization
  cisco.intersight.intersight_iscsi_static_target_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
  register: engineering_policies

# Specific Policy Examples
- name: Fetch a specific iSCSI Static Target Policy by name
  cisco.intersight.intersight_iscsi_static_target_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "iscsi-static-target-policy-01"
  register: specific_policy

- name: Fetch a specific policy from a specific organization
  cisco.intersight.intersight_iscsi_static_target_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Production"
    name: "iscsi-static-target-policy-prod"
  register: specific_org_policy
'''

RETURN = r'''
api_response:
  description:
    - The API response containing iSCSI Static Target Policy information.
    - Returns a dictionary when querying a single policy or no policies found.
    - Returns a list when multiple policies are found.
  returned: always
  type: dict
  sample:
    # Single policy response (when name parameter is used or only one policy found)
    Name: "iscsi-static-target-policy-01"
    ObjectType: "vnic.IscsiStaticTargetPolicy"
    Moid: "1234567890abcdef12345678"
    Description: "iSCSI static target policy for production servers"
    TargetName: "iqn.1991-05.com.microsoft:winclient1"
    Port: 3260
    Lun:
      LunId: 0
    IscsiIpType: "IPv4"
    IpAddress: "192.168.10.100"
    Organization:
      Name: "default"
      ObjectType: "organization.Organization"
      Moid: "abcdef1234567890abcdef12"
    Tags:
      - Key: "Environment"
        Value: "Production"
      - Key: "Owner"
        Value: "Storage-Team"
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

    # Resource path used to fetch policy info
    resource_path = '/vnic/IscsiStaticTargetPolicies'

    # Get query parameters for policies
    query_params = intersight.set_query_params()

    # Reset api_response before the API call to avoid previous responses
    intersight.result['api_response'] = {}

    # Get iSCSI Static Target policies
    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    policies = intersight.result.get('api_response', [])

    # Create final response structure
    final_api_response = None

    # Ensure policies is always a list for iteration, even if a single dict is returned
    if isinstance(policies, dict):
        policies = [policies]
    elif not isinstance(policies, list):
        policies = []

    # Set final response based on number of policies found
    if len(policies) == 1:
        # Single policy - return as dict
        final_api_response = policies[0]
    elif len(policies) > 1:
        # Multiple policies - return as list
        final_api_response = policies
    else:
        # No policies found - return empty structure
        final_api_response = {}

    # Use intersight.result and update api_response directly
    intersight.result['api_response'] = final_api_response

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
