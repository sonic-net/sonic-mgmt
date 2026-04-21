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
module: intersight_vsan_policy_info
short_description: Gather information about VSAN Policies and their VSANs in Cisco Intersight
description:
  - Retrieve information about VSAN (Virtual Storage Area Network) Policies and their associated VSANs from L(Cisco Intersight,https://intersight.com).
  - Query policies by organization, policy name, or filter VSANs by name patterns.
  - Returns structured data combining policy metadata with detailed VSAN configurations.
  - Supports filtering by organization, policy name, and VSAN name.
  - If no filters are provided, all VSAN Policies and their VSANs will be returned.
  - Returns structured data with both policy information and associated VSAN details.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization to filter VSAN Policies by.
      - Use 'default' for the default organization.
      - When specified, only policies from this organization will be returned.
    type: str
  name:
    description:
      - The exact name of the VSAN Policy to retrieve information from.
      - When specified, only the matching policy and its VSANs will be returned.
      - Can be combined with vsan_name filter to get specific VSANs from a specific policy.
    type: str
  vsan_name:
    description:
      - Filter VSANs by name within the policies.
      - Can be used with or without policy name filtering.
      - Supports exact matching (e.g., "vsan_uplink_100" will match only "vsan_uplink_100").
      - When combined with policy name, filters VSANs within that specific policy.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
# Basic Usage Examples
- name: Fetch all VSAN Policies and their VSANs from all organizations
  cisco.intersight.intersight_vsan_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
  register: all_vsan_policies

# Organization-specific Examples
- name: Fetch all VSAN Policies from the default organization
  cisco.intersight.intersight_vsan_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
  register: default_org_policies

- name: Fetch all VSAN Policies from a custom organization
  cisco.intersight.intersight_vsan_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
  register: engineering_policies

# Specific Policy Examples
- name: Fetch a specific VSAN Policy by name with all its VSANs
  cisco.intersight.intersight_vsan_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "datacenter-vsan-policy"
  register: specific_policy

# VSAN Filtering Examples
- name: Find all policies containing a specific VSAN
  cisco.intersight.intersight_vsan_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    vsan_name: "vsan_uplink_100"
  register: policies_with_vsan_100

- name: Find specific VSAN in a specific policy
  cisco.intersight.intersight_vsan_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "datacenter-vsan-policy"
    vsan_name: "vsan_storage_200"
  register: specific_vsan_in_policy
'''

RETURN = r'''
api_response:
  description:
    - The API response containing policy and VSAN information.
    - Returns a dictionary when querying a single policy or no policies found.
    - Returns a list when multiple policies are found.
  returned: always
  type: dict
  sample:
    # Single policy response (when name parameter is used or only one policy found)
    Name: "datacenter-vsan-policy"
    ObjectType: "fabric.FcNetworkPolicy"
    Moid: "12345678901234567890abcd"
    Description: "VSAN policy for datacenter SAN infrastructure"
    EnableTrunking: false
    Organization:
      Name: "default"
      ObjectType: "organization.Organization"
    Tags:
      - Key: "Site"
        Value: "DataCenter-A"
      - Key: "Environment"
        Value: "Production"
    vsans:
      - Name: "vsan_uplink_100"
        ObjectType: "fabric.Vsan"
        Moid: "vsan12345678901234567890"
        VsanId: 100
        FcoeVlan: 100
        VsanScope: "Uplink"
        FcNetworkPolicy:
          Moid: "12345678901234567890abcd"
          ObjectType: "fabric.FcNetworkPolicy"
      - Name: "vsan_storage_200"
        ObjectType: "fabric.Vsan"
        Moid: "vsan09876543210987654321"
        VsanId: 200
        FcoeVlan: 200
        VsanScope: "Storage"
        FcNetworkPolicy:
          Moid: "12345678901234567890abcd"
          ObjectType: "fabric.FcNetworkPolicy"
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def get_vsans_for_policy(intersight, policy_moid, vsan_name_filter=None):
    """
    Get all VSANs associated with a specific policy.

    Args:
        intersight: IntersightModule instance
        policy_moid: MOID of the policy to get VSANs for
        vsan_name_filter: Optional filter for VSAN names

    Returns:
        List of VSAN objects associated with the policy
    """
    # Build filter for VSANs associated with this policy
    filter_conditions = [f"FcNetworkPolicy.Moid eq '{policy_moid}'"]

    # Add VSAN name filter if provided (exact match only)
    if vsan_name_filter:
        filter_conditions.append(f"Name eq '{vsan_name_filter}'")

    query_params = {
        '$filter': ' and '.join(filter_conditions)
    }

    # Reset api_response before the API call to avoid previous responses
    intersight.result['api_response'] = {}

    # Get VSANs for this policy
    intersight.get_resource(
        resource_path='/fabric/Vsans',
        query_params=query_params,
        return_list=True
    )

    # Capture the response immediately before it gets overwritten
    vsans_response = intersight.result.get('api_response', [])

    # Ensure we return a list
    if isinstance(vsans_response, list):
        return vsans_response
    elif isinstance(vsans_response, dict):
        return [vsans_response]
    else:
        return []


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        organization=dict(type='str'),
        name=dict(type='str'),
        vsan_name=dict(type='str')
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)

    # Resource path used to fetch policy info
    resource_path = '/fabric/FcNetworkPolicies'

    # Get query parameters for policies
    query_params = intersight.set_query_params()

    # Reset api_response before the API call to avoid previous responses
    intersight.result['api_response'] = {}

    # Get VSAN policies
    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    policies = intersight.result.get('api_response', [])
    vsan_name_filter = module.params.get('vsan_name')

    # Build structured response
    structured_results = []

    # Ensure policies is always a list for iteration, even if a single dict is returned
    if isinstance(policies, dict):
        policies = [policies]
    elif not isinstance(policies, list):
        policies = []

    for policy in policies:
        policy_moid = policy.get('Moid')
        if not policy_moid:
            continue

        # Get VSANs for this policy
        vsans = get_vsans_for_policy(intersight, policy_moid, vsan_name_filter)

        # Embed VSANs in the policy response
        if vsans:
            policy['vsans'] = vsans

        structured_results.append(policy)

    # Create final response structure
    final_api_response = None

    # Set final response based on number of policies found
    if len(structured_results) == 1:
        # Single policy - return as dict
        final_api_response = structured_results[0]
    elif len(structured_results) > 1:
        # Multiple policies - return as list
        final_api_response = structured_results
    else:
        # No policies found - return empty structure
        final_api_response = {}

    # Use intersight.result and update api_response directly
    intersight.result['api_response'] = final_api_response
    final_result = intersight.result

    module.exit_json(**final_result)


if __name__ == '__main__':
    main()
