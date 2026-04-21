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
module: intersight_vnic_template_info
short_description: Gather information about vNIC Templates in Cisco Intersight
description:
  - Retrieve comprehensive information about vNIC Templates from L(Cisco Intersight,https://intersight.com).
  - Query templates by organization, template name, or other filters.
  - Returns structured data with template metadata and policy associations.
  - If no filters are provided, all vNIC Templates will be returned.
  - vNIC Templates are used to define standardized network interface configurations for FI-Attached deployments.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization to filter vNIC Templates by.
      - Use 'default' for the default organization.
      - When specified, only templates from this organization will be returned.
    type: str
  name:
    description:
      - The exact name of the vNIC Template to retrieve information from.
      - When specified, only the matching template will be returned.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
# Basic Usage Examples
- name: Fetch all vNIC Templates from all organizations
  cisco.intersight.intersight_vnic_template_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
  register: all_vnic_templates

- name: Display all template names
  debug:
    msg: "Template: {{ item.Name }}"
  loop: "{{ all_vnic_templates.api_response }}"
  when: all_vnic_templates.api_response is iterable

# Organization-specific Examples
- name: Fetch all vNIC Templates from the default organization
  cisco.intersight.intersight_vnic_template_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
  register: default_org_templates

- name: Fetch all vNIC Templates from a custom organization
  cisco.intersight.intersight_vnic_template_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
  register: engineering_templates
'''

RETURN = r'''
api_response:
  description:
    - The API response containing vNIC Template information.
    - Returns a dictionary when querying a single template or no templates found.
    - Returns a list when multiple templates are found.
  returned: always
  type: dict
  sample:
    Name: "production-vnic-template"
    ObjectType: "vnic.VnicTemplate"
    Moid: "12345678901234567890abcd"
    Description: "Production vNIC template for FI-attached servers"
    EnableOverride: false
    SwitchId: "A"
    FailoverEnabled: false
    Cdn:
      Source: "vnic"
    MacPool:
      Name: "default-mac-pool"
      ObjectType: "macpool.Pool"
      Moid: "macpool12345678901234567890"
    FabricEthNetworkGroupPolicy:
      - Name: "default-network-group"
        ObjectType: "fabric.EthNetworkGroupPolicy"
        Moid: "netgroup12345678901234567890"
    FabricEthNetworkControlPolicy:
      Name: "default-network-control"
      ObjectType: "fabric.EthNetworkControlPolicy"
      Moid: "netcontrol12345678901234567890"
    EthQosPolicy:
      Name: "default-qos-policy"
      ObjectType: "vnic.EthQosPolicy"
      Moid: "qos12345678901234567890"
    EthAdapterPolicy:
      Name: "default-adapter-policy"
      ObjectType: "vnic.EthAdapterPolicy"
      Moid: "adapter12345678901234567890"
    Organization:
      Name: "default"
      ObjectType: "organization.Organization"
      Moid: "org12345678901234567890"
    Tags:
      - Key: "Environment"
        Value: "Production"
      - Key: "Site"
        Value: "DataCenter-A"
    SriovSettings:
      Enabled: true
      VfCount: 64
      RxCountPerVf: 4
      TxCountPerVf: 1
      CompCountPerVf: 5
      IntCountPerVf: 8
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

    # Resource path used to fetch vNIC Template info
    resource_path = '/vnic/VnicTemplates'

    # Get query parameters for templates
    query_params = intersight.set_query_params()

    # Reset api_response before the API call to avoid previous responses
    intersight.result['api_response'] = {}

    # Get vNIC Templates
    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    templates = intersight.result.get('api_response', [])

    # Create final response structure
    final_api_response = None

    # Ensure templates is always a list for checking length, even if a single dict is returned
    if isinstance(templates, dict):
        templates = [templates]
    elif not isinstance(templates, list):
        templates = []

    # Set final response based on number of templates found
    if len(templates) == 1:
        # Single template - return as dict
        final_api_response = templates[0]
    elif len(templates) > 1:
        # Multiple templates - return as list
        final_api_response = templates
    else:
        # No templates found - return empty dict
        final_api_response = {}

    # Use intersight.result and update api_response directly
    intersight.result['api_response'] = final_api_response
    final_result = intersight.result

    module.exit_json(**final_result)


if __name__ == '__main__':
    main()
