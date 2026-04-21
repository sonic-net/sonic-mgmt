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
module: intersight_system_qos_policy_info
short_description: Gather information about System QoS Policies in Cisco Intersight
description:
  - Retrieve comprehensive information about System QoS Policies and their configured classes from L(Cisco Intersight,https://intersight.com).
  - Query policies by organization, policy name, or filter by specific criteria.
  - Returns structured data combining policy metadata with detailed QoS class configurations.
  - Each policy includes all six QoS classes (Bronze, Silver, Gold, Platinum, Best Effort, FC) with their current settings.
  - Supports filtering by organization and policy name.
  - If no filters are provided, all System QoS Policies will be returned.
  - Returns structured data with both policy information and associated QoS class details.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization to filter System QoS Policies by.
      - Use 'default' for the default organization.
      - When specified, only policies from this organization will be returned.
    type: str
  name:
    description:
      - The exact name of the System QoS Policy to retrieve information from.
      - When specified, only the matching policy and its classes will be returned.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
# Basic Usage Examples

- name: Get all System QoS Policies
  cisco.intersight.intersight_system_qos_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
  register: all_qos_policies

- name: Get System QoS Policies from specific organization
  cisco.intersight.intersight_system_qos_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
  register: devnet_qos_policies

- name: Get specific System QoS Policy by name
  cisco.intersight.intersight_system_qos_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: lab-system-qos
  register: specific_qos_policy

- name: Display QoS classes from retrieved policy
  ansible.builtin.debug:
    msg: "Policy {{ item.Name }} has {{ item.Classes | length }} QoS classes configured"
  loop: "{{ specific_qos_policy.intersight_system_qos_policies }}"

# Advanced filtering and conditional tasks

- name: Get all System QoS policies and show enabled classes
  cisco.intersight.intersight_system_qos_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
  register: qos_policies

- name: Show enabled QoS classes for each policy
  ansible.builtin.debug:
    msg: |
      Policy: {{ item.Name }}
      Enabled Classes: {{ item.Classes | selectattr('AdminState', 'equalto', 'Enabled') | map(attribute='Name') | list }}
  loop: "{{ qos_policies.intersight_system_qos_policies }}"

- name: Check if specific policy exists
  cisco.intersight.intersight_system_qos_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: production-qos
  register: policy_check

- name: Fail if production policy doesn't exist
  ansible.builtin.fail:
    msg: "Production QoS policy not found!"
  when: policy_check.intersight_system_qos_policies | length == 0
'''

RETURN = r'''
intersight_system_qos_policies:
  description: A list of System QoS Policies with their configurations
  returned: always
  type: list
  elements: dict
  sample:
    - Name: "lab-system-qos"
      Description: "System QoS policy for lab use"
      Organization:
        ObjectType: "organization.Organization"
        Moid: "675450ee69726530014753e2"
      Tags:
        - Key: "Site"
          Value: "RCDN"
      Classes:
        - Name: "Bronze"
          AdminState: "Disabled"
          Cos: 1
          Mtu: 1500
          PacketDrop: true
          Weight: 7
        - Name: "Silver"
          AdminState: "Disabled"
          Cos: 2
          Mtu: 1500
          PacketDrop: true
          Weight: 8
        - Name: "Gold"
          AdminState: "Enabled"
          Cos: 4
          Mtu: 1500
          PacketDrop: true
          Weight: 9
        - Name: "Platinum"
          AdminState: "Enabled"
          Cos: 5
          Mtu: 1500
          PacketDrop: true
          Weight: 10
        - Name: "Best Effort"
          AdminState: "Enabled"
          Cos: 255
          Mtu: 1500
          PacketDrop: true
          Weight: 5
        - Name: "FC"
          AdminState: "Enabled"
          Cos: 3
          Mtu: 2240
          PacketDrop: false
          Weight: 5
      CreateTime: "2023-05-15T10:30:45.123Z"
      ModTime: "2023-05-15T10:30:45.123Z"
      Moid: "64620ac769726530014a1234"
      ObjectType: "fabric.SystemQosPolicy"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        organization=dict(type='str'),
        name=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)

    # Resource path for System QoS Policies
    resource_path = '/fabric/SystemQosPolicies'

    query_params = intersight.set_query_params()

    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
