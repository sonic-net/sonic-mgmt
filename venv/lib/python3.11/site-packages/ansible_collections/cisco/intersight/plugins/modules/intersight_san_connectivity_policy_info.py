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
module: intersight_san_connectivity_policy_info
short_description: Gather information about SAN Connectivity Policies and their vHBAs in Cisco Intersight
description:
  - Retrieve information about SAN Connectivity Policies and their associated vHBAs from L(Cisco Intersight,https://intersight.com).
  - Query policies by organization, policy name, or filter vHBAs by name patterns.
  - Returns structured data combining policy metadata with detailed vHBA configurations.
  - Supports filtering by organization, policy name, and vHBA name.
  - If no filters are provided, all SAN Connectivity Policies and their vHBAs will be returned.
  - Returns structured data with both policy information and associated vHBA details.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization to filter SAN Connectivity Policies by.
      - Use 'default' for the default organization.
      - When specified, only policies from this organization will be returned.
    type: str
  name:
    description:
      - The exact name of the SAN Connectivity Policy to retrieve information from.
      - When specified, only the matching policy and its vHBAs will be returned.
      - Can be combined with vhba_name filter to get specific vHBAs from a specific policy.
    type: str
  vhba_name:
    description:
      - Filter vHBAs by name within the policies.
      - Can be used with or without policy name filtering.
      - Supports exact matching (e.g., "vhba-a" will match only "vhba-a").
      - When combined with policy name, filters vHBAs within that specific policy.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
# Basic Usage Examples
- name: Fetch all SAN Connectivity Policies and their vHBAs from all organizations
  cisco.intersight.intersight_san_connectivity_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
  register: all_san_policies

# Organization-specific Examples
- name: Fetch all SAN Connectivity Policies from the default organization
  cisco.intersight.intersight_san_connectivity_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
  register: default_org_policies

- name: Fetch all SAN Connectivity Policies from a custom organization
  cisco.intersight.intersight_san_connectivity_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
  register: engineering_policies

# Specific Policy Examples
- name: Fetch a specific SAN Connectivity Policy by name with all its vHBAs
  cisco.intersight.intersight_san_connectivity_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "fi-attached-san-policy"
  register: specific_policy

# vHBA Filtering Examples
- name: Find all policies containing a specific vHBA
  cisco.intersight.intersight_san_connectivity_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    vhba_name: "vhba-a"
  register: policies_with_vhba_a

- name: Find specific vHBA in a specific policy
  cisco.intersight.intersight_san_connectivity_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "fi-attached-san-policy"
    vhba_name: "vhba-b"
  register: specific_vhba_in_policy
'''

RETURN = r'''
api_response:
  description:
    - The API response containing policy and vHBA information.
    - Returns a dictionary when querying a single policy or no policies found.
    - Returns a list when multiple policies are found.
  returned: always
  type: dict
  sample:
    # Single policy response (when name parameter is used or only one policy found)
    Name: "fi-attached-san-policy"
    ObjectType: "vnic.SanConnectivityPolicy"
    Moid: "12345678901234567890abcd"
    Description: "SAN connectivity policy for FI-attached servers"
    TargetPlatform: "FIAttached"
    WwnnAddressType: "POOL"
    PlacementMode: "custom"
    Organization:
      Name: "default"
      ObjectType: "organization.Organization"
      Moid: "abcdef1234567890abcdef12"
    Tags:
      - Key: "Environment"
        Value: "Production"
    WwnnPool:
      Moid: "fedcba0987654321fedcba09"
      ObjectType: "fcpool.Pool"
    vhbas:
      - Name: "vhba-a"
        ObjectType: "vnic.FcIf"
        Moid: "vhba12345678901234567890"
        Order: 0
        PersistentBindings: true
        Type: "fc-initiator"
        Placement:
          SwitchId: "A"
          PciLink: 0
        WwpnAddressType: "POOL"
        SanConnectivityPolicy:
          Moid: "12345678901234567890abcd"
          ObjectType: "vnic.SanConnectivityPolicy"
      - Name: "vhba-b"
        ObjectType: "vnic.FcIf"
        Moid: "vhba09876543210987654321"
        Order: 1
        PersistentBindings: true
        Type: "fc-initiator"
        Placement:
          SwitchId: "B"
          PciLink: 0
        WwpnAddressType: "POOL"
        SanConnectivityPolicy:
          Moid: "12345678901234567890abcd"
          ObjectType: "vnic.SanConnectivityPolicy"
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def get_vhbas_for_policy(intersight, policy_moid, vhba_name_filter=None):
    """
    Get all vHBAs associated with a specific policy.
    """

    # Build filter for vHBAs associated with this policy
    filter_conditions = [f"SanConnectivityPolicy.Moid eq '{policy_moid}'"]

    # Add vHBA name filter if provided (exact match only)
    if vhba_name_filter:
        filter_conditions.append(f"Name eq '{vhba_name_filter}'")

    query_params = {
        '$filter': ' and '.join(filter_conditions)
    }

    # Reset api_response before the API call to avoid previous responses
    intersight.result['api_response'] = {}

    # Get vHBAs for this policy
    intersight.get_resource(
        resource_path='/vnic/FcIfs',
        query_params=query_params,
        return_list=True
    )

    # Capture the response immediately before it gets overwritten
    vhbas_response = intersight.result.get('api_response', [])

    # Ensure we return a list
    if isinstance(vhbas_response, list):
        return vhbas_response
    elif isinstance(vhbas_response, dict):
        return [vhbas_response]
    else:
        return []


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        organization=dict(type='str'),
        name=dict(type='str'),
        vhba_name=dict(type='str')
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)

    # Resource path used to fetch policy info
    resource_path = '/vnic/SanConnectivityPolicies'

    # Get query parameters for policies
    query_params = intersight.set_query_params()

    # Reset api_response before the API call to avoid previous responses
    intersight.result['api_response'] = {}

    # Get SAN Connectivity policies
    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    policies = intersight.result.get('api_response', [])
    vhba_name_filter = module.params.get('vhba_name')

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

        # Get vHBAs for this policy
        vhbas = get_vhbas_for_policy(intersight, policy_moid, vhba_name_filter)

        # Embed vHBAs in the policy response
        if vhbas:
            policy['vhbas'] = vhbas

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
