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
module: intersight_vhba_template_info
short_description: Gather information about vHBA Templates in Cisco Intersight
description:
  - Retrieve comprehensive information about vHBA Templates from L(Cisco Intersight,https://intersight.com).
  - Query templates by organization, template name, or other filters.
  - Returns structured data with template metadata and policy associations.
  - If no filters are provided, all vHBA Templates will be returned.
  - vHBA Templates are used to define standardized fibre channel interface configurations for FI-Attached deployments.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization to filter vHBA Templates by.
      - Use 'default' for the default organization.
      - When specified, only templates from this organization will be returned.
    type: str
  name:
    description:
      - The exact name of the vHBA Template to retrieve information from.
      - When specified, only the matching template will be returned.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
# Basic Usage Examples
- name: Fetch all vHBA Templates from all organizations
  cisco.intersight.intersight_vhba_template_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
  register: all_vhba_templates

- name: Display all template names
  debug:
    msg: "Template: {{ item.Name }}"
  loop: "{{ all_vhba_templates.api_response }}"
  when: all_vhba_templates.api_response is iterable

# Organization-specific Examples
- name: Fetch all vHBA Templates from the default organization
  cisco.intersight.intersight_vhba_template_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
  register: default_org_templates

- name: Fetch all vHBA Templates from a custom organization
  cisco.intersight.intersight_vhba_template_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
  register: engineering_templates

# Name-specific Example
- name: Fetch a specific vHBA Template
  cisco.intersight.intersight_vhba_template_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "production-vhba-template"
  register: specific_template
'''

RETURN = r'''
api_response:
  description:
    - The API response containing vHBA Template information.
    - Returns a dictionary when querying a single template or no templates found.
    - Returns a list when multiple templates are found.
  returned: always
  type: dict
  sample:
    Name: "production-vhba-template"
    ObjectType: "vnic.VhbaTemplate"
    Moid: "12345678901234567890abcd"
    Description: "Production vHBA template for FI-attached servers"
    EnableOverride: false
    Type: "fc-initiator"
    SwitchId: "A"
    PersistentBindings: false
    WwpnAddressType: "POOL"
    WwpnPool:
      Name: "default-wwpn-pool"
      ObjectType: "fcpool.Pool"
      Moid: "wwpnpool12345678901234567890"
    FcNetworkPolicy:
      Name: "fc-network-policy"
      ObjectType: "vnic.FcNetworkPolicy"
      Moid: "fcnetwork12345678901234567890"
    FcQosPolicy:
      Name: "fc-qos-policy"
      ObjectType: "vnic.FcQosPolicy"
      Moid: "fcqos12345678901234567890"
    FcAdapterPolicy:
      Name: "fc-adapter-policy"
      ObjectType: "vnic.FcAdapterPolicy"
      Moid: "fcadapter12345678901234567890"
    FcZonePolicies:
      - Name: "fc-zone-policy-1"
        ObjectType: "fabric.FcZonePolicy"
        Moid: "fczone12345678901234567890"
    Organization:
      Name: "default"
      ObjectType: "organization.Organization"
      Moid: "org12345678901234567890"
    Tags:
      - Key: "Environment"
        Value: "Production"
      - Key: "Site"
        Value: "DataCenter-A"
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

    # Resource path used to fetch vHBA Template info
    resource_path = '/vnic/VhbaTemplates'

    # Get query parameters for templates
    query_params = intersight.set_query_params()

    # Get vHBA Templates
    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
