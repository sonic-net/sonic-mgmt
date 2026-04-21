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
module: intersight_vlan_policy_info
short_description: Gather information about VLAN Policies and their VLANs in Cisco Intersight
description:
  - Retrieve comprehensive information about VLAN Policies and their associated VLANs from L(Cisco Intersight,https://intersight.com).
  - Query policies by organization, policy name, or filter VLANs by name patterns.
  - Returns structured data combining policy metadata with detailed VLAN configurations.
  - Supports filtering by organization, policy name, and VLAN name.
  - If no filters are provided, all VLAN Policies and their VLANs will be returned.
  - Returns structured data with both policy information and associated VLAN details.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization to filter VLAN Policies by.
      - Use 'default' for the default organization.
      - When specified, only policies from this organization will be returned.
    type: str
  name:
    description:
      - The exact name of the VLAN Policy to retrieve information from.
      - When specified, only the matching policy and its VLANs will be returned.
      - Can be combined with vlan_name filter to get specific VLANs from a specific policy.
    type: str
  vlan_name:
    description:
      - Filter VLANs by name within the policies.
      - Can be used with or without policy name filtering.
      - Supports exact matching (e.g., "prod_100" will match only "prod_100").
      - When combined with policy name, filters VLANs within that specific policy.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
# Basic Usage Examples
- name: Fetch all VLAN Policies and their VLANs from all organizations
  cisco.intersight.intersight_vlan_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
  register: all_vlan_policies

# Organization-specific Examples
- name: Fetch all VLAN Policies from the default organization
  cisco.intersight.intersight_vlan_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
  register: default_org_policies

- name: Fetch all VLAN Policies from a custom organization
  cisco.intersight.intersight_vlan_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
  register: engineering_policies

# Specific Policy Examples
- name: Fetch a specific VLAN Policy by name with all its VLANs
  cisco.intersight.intersight_vlan_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "datacenter-vlan-policy"
  register: specific_policy

- name: Display policy details
  debug:
    msg: "Policy {{ specific_policy.api_response.policy.Name }} has {{ specific_policy.api_response.vlans | length }} VLANs"

# VLAN Filtering Examples
- name: Find all policies containing a specific VLAN
  cisco.intersight.intersight_vlan_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    vlan_name: "prod_100"
  register: policies_with_prod_100

- name: Find specific VLAN in a specific policy
  cisco.intersight.intersight_vlan_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "datacenter-vlan-policy"
    vlan_name: "mgmt_300"
  register: specific_vlan_in_policy
'''

RETURN = r'''
api_response:
  description:
    - The API response containing policy and VLAN information.
    - Returns a dictionary when querying a single policy or no policies found.
    - Returns a list when multiple policies are found.
  returned: always
  type: dict
  contains:
    vlan_policy:
      description: VLAN policy information
      type: dict
      returned: always
    vlans:
      description: List of VLANs associated with the policy
      type: list
      returned: always
  sample:
    # Single policy response (when name parameter is used or only one policy found)
    vlan_policy:
      Name: "datacenter-vlan-policy"
      ObjectType: "fabric.EthNetworkPolicy"
      Moid: "12345678901234567890abcd"
      Description: "VLAN policy for datacenter infrastructure"
      Organization:
        Name: "default"
        ObjectType: "organization.Organization"
      Tags:
        - Key: "Site"
          Value: "DataCenter-A"
        - Key: "Environment"
          Value: "Production"
    vlans:
      - Name: "prod_100"
        ObjectType: "fabric.Vlan"
        Moid: "vlan12345678901234567890"
        VlanId: 100
        AutoAllowOnUplinks: true
        IsNative: false
        SharingType: "None"
        MulticastPolicy:
          Name: "default-multicast-policy"
          ObjectType: "fabric.MulticastPolicy"
      - Name: "dmz_primary_50"
        ObjectType: "fabric.Vlan"
        Moid: "vlan09876543210987654321"
        VlanId: 50
        AutoAllowOnUplinks: true
        IsNative: false
        SharingType: "Primary"
        PrimaryVlanId: 0
      - Name: "dmz_isolated_51"
        ObjectType: "fabric.Vlan"
        Moid: "vlanabcdef1234567890123456"
        VlanId: 51
        AutoAllowOnUplinks: true
        IsNative: false
        SharingType: "Isolated"
        PrimaryVlanId: 50
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def get_vlans_for_policy(intersight, policy_moid, vlan_name_filter=None):
    """
    Get all VLANs associated with a specific policy.

    Args:
        intersight: IntersightModule instance
        policy_moid: MOID of the policy to get VLANs for
        vlan_name_filter: Optional filter for VLAN names

    Returns:
        List of VLAN objects associated with the policy
    """
    # Build filter for VLANs associated with this policy
    filter_conditions = [f"EthNetworkPolicy.Moid eq '{policy_moid}'"]

    # Add VLAN name filter if provided (exact match only)
    if vlan_name_filter:
        filter_conditions.append(f"Name eq '{vlan_name_filter}'")

    query_params = {
        '$filter': ' and '.join(filter_conditions)
    }

    # Reset api_response before the API call to avoid previous responses
    intersight.result['api_response'] = {}

    # Get VLANs for this policy
    intersight.get_resource(
        resource_path='/fabric/Vlans',
        query_params=query_params,
        return_list=True
    )

    # Capture the response immediately before it gets overwritten
    vlans_response = intersight.result.get('api_response', [])

    # Ensure we return a list
    if isinstance(vlans_response, list):
        return vlans_response
    elif isinstance(vlans_response, dict):
        return [vlans_response]
    else:
        return []


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        organization=dict(type='str'),
        name=dict(type='str'),
        vlan_name=dict(type='str')
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)

    # Resource path used to fetch policy info
    resource_path = '/fabric/EthNetworkPolicies'

    # Get query parameters for policies
    query_params = intersight.set_query_params()

    # Reset api_response before the API call to avoid previous responses
    intersight.result['api_response'] = {}

    # Get VLAN policies
    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    policies = intersight.result.get('api_response', [])
    vlan_name_filter = module.params.get('vlan_name')

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

        # Get VLANs for this policy
        vlans = get_vlans_for_policy(intersight, policy_moid, vlan_name_filter)

        # Create structured response for this policy
        policy_result = {
            'vlan_policy': policy,
            'vlans': vlans
        }

        structured_results.append(policy_result)

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
        final_api_response = {
            'vlan_policy': {},
            'vlans': []
        }

    # Use intersight.result and update api_response directly
    intersight.result['api_response'] = final_api_response
    final_result = intersight.result

    module.exit_json(**final_result)


if __name__ == '__main__':
    main()
