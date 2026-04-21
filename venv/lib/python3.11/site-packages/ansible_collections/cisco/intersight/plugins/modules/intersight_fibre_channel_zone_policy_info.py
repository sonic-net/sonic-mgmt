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
module: intersight_fibre_channel_zone_policy_info
short_description: Gather information about Fibre Channel Zone Policies in Cisco Intersight
description:
  - Retrieve comprehensive information about Fibre Channel Zone Policies from L(Cisco Intersight,https://intersight.com).
  - Query policies by organization or policy name.
  - FC target members are embedded in the policy object as FcTargetMembers array.
  - If no filters are provided, all FC Zone Policies will be returned.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization to filter FC Zone Policies by.
      - Use 'default' for the default organization.
      - When specified, only policies from this organization will be returned.
    type: str
  name:
    description:
      - The exact name of the FC Zone Policy to retrieve information from.
      - When specified, only the matching policy will be returned.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
# Basic Usage Examples
- name: Fetch all FC Zone Policies from all organizations
  cisco.intersight.intersight_fibre_channel_zone_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
  register: all_fc_zone_policies

- name: Display all policies
  debug:
    msg: "Found {{ all_fc_zone_policies.api_response | length }} FC Zone Policies"

# Organization-specific Examples
- name: Fetch all FC Zone Policies from the default organization
  cisco.intersight.intersight_fibre_channel_zone_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
  register: default_org_policies

- name: Fetch all FC Zone Policies from a custom organization
  cisco.intersight.intersight_fibre_channel_zone_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
  register: engineering_policies

# Specific Policy Examples
- name: Fetch a specific FC Zone Policy by name
  cisco.intersight.intersight_fibre_channel_zone_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "fc-zone-policy-simt"
  register: specific_policy
'''

RETURN = r'''
api_response:
  description:
    - The API response containing policy information including embedded FC target members.
    - Returns a dictionary when querying a single policy.
    - Returns a list when multiple policies are found.
  returned: always
  type: dict
  sample:
    Name: "fc-zone-policy-simt"
    ObjectType: "fabric.FcZonePolicy"
    Moid: "12345678901234567890abcd"
    Description: "FC Zone policy with SIMT zoning"
    FcTargetZoningType: "SIMT"
    FcTargetMembers:
      - Name: "target1"
        Wwpn: "21:00:00:e0:8b:05:05:04"
        SwitchId: "A"
        VsanId: 100
      - Name: "target2"
        Wwpn: "21:00:00:e0:8b:05:05:03"
        SwitchId: "B"
        VsanId: 100
    Organization:
      Name: "default"
      ObjectType: "organization.Organization"
    Tags:
      - Key: "Environment"
        Value: "Production"
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
    resource_path = '/fabric/FcZonePolicies'

    # Get query parameters for policies
    query_params = intersight.set_query_params()

    # Get FC Zone policies
    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
