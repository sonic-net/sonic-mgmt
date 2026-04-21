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
module: intersight_fibre_channel_network_policy
short_description: Manage Fibre Channel Network Policies for Cisco Intersight
description:
  - Create, update, and delete Fibre Channel Network Policies on Cisco Intersight.
  - Fibre Channel Network policies configure VSAN settings for Fibre Channel virtual interfaces.
  - These policies control the default VLAN ID and VSAN ID assignments for FC networks.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/vnic/FcNetworkPolicies/get/).
extends_documentation_fragment: intersight
options:
  state:
    description:
      - If C(present), will verify the resource is present and will create if needed.
      - If C(absent), will verify the resource is absent and will delete if needed.
    type: str
    choices: [present, absent]
    default: present
  organization:
    description:
      - The name of the Organization this resource is assigned to.
      - Policies created within a Custom Organization are applicable only to devices in the same Organization.
      - Use 'default' for the default organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the Fibre Channel Network Policy.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Fibre Channel Network Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  default_vlan:
    description:
      - The default VLAN ID for the Fibre Channel network.
      - Valid range is 0 to 4094.
      - A value of 0 means the VLAN is not configured.
    type: int
    default: 0
  vsan_id:
    description:
      - The VSAN (Virtual Storage Area Network) ID for the Fibre Channel network.
      - Valid range is 1 to 4094.
    type: int
    default: 1
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create Fibre Channel Network Policy with default settings
  cisco.intersight.intersight_fibre_channel_network_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-network-default"
    description: "Fibre Channel Network policy with default values"
    state: present

- name: Create Fibre Channel Network Policy with custom VSAN settings
  cisco.intersight.intersight_fibre_channel_network_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-network-vsan100"
    description: "Fibre Channel Network policy for VSAN 100"
    default_vlan: 100
    vsan_id: 100
    tags:
      - Key: Environment
        Value: Production
    state: present

- name: Create Fibre Channel Network Policy with VLAN and different VSAN
  cisco.intersight.intersight_fibre_channel_network_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
    name: "fc-network-custom"
    description: "Custom Fibre Channel Network policy"
    default_vlan: 200
    vsan_id: 300
    state: present

- name: Create Fibre Channel Network Policy with maximum VSAN ID
  cisco.intersight.intersight_fibre_channel_network_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-network-max-vsan"
    description: "Fibre Channel Network policy with maximum VSAN ID"
    default_vlan: 4094
    vsan_id: 4094
    state: present

- name: Update Fibre Channel Network Policy description
  cisco.intersight.intersight_fibre_channel_network_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-network-default"
    description: "Updated Fibre Channel Network policy description"
    state: present

- name: Delete Fibre Channel Network Policy
  cisco.intersight.intersight_fibre_channel_network_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-network-default"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "fc-network-vsan100",
        "ObjectType": "vnic.FcNetworkPolicy",
        "Moid": "1234567890abcdef12345678",
        "Description": "Fibre Channel Network policy for VSAN 100",
        "VsanSettings": {
            "DefaultVlanId": 100,
            "Id": 100
        },
        "Organization": {
            "Moid": "abcdef1234567890abcdef12",
            "ObjectType": "organization.Organization"
        },
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Production"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def validate_parameters(module):
    """
    Validate module parameters for Fibre Channel Network policy configuration.
    """
    if module.params['state'] != 'present':
        return
    # Validate default_vlan range (0-4094)
    default_vlan = module.params.get('default_vlan')
    if default_vlan is not None and (default_vlan < 0 or default_vlan > 4094):
        module.fail_json(msg="Parameter 'default_vlan' must be between 0 and 4094")
    # Validate vsan_id range (1-4094)
    vsan_id = module.params.get('vsan_id')
    if vsan_id is not None and (vsan_id < 1 or vsan_id > 4094):
        module.fail_json(msg="Parameter 'vsan_id' must be between 1 and 4094")


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        default_vlan=dict(type='int', default=0),
        vsan_id=dict(type='int', default=1),
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )
    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''
    # Validate module parameters
    validate_parameters(module)
    # Resource path used to configure policy
    resource_path = '/vnic/FcNetworkPolicies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': module.params['organization'],
        },
        'Name': module.params['name'],
    }
    if module.params['state'] == 'present':
        intersight.api_body['VsanSettings'] = {
            'DefaultVlanId': module.params['default_vlan'],
            'Id': module.params['vsan_id'],
        }
        intersight.set_tags_and_description()
    intersight.configure_policy_or_profile(resource_path=resource_path)
    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
