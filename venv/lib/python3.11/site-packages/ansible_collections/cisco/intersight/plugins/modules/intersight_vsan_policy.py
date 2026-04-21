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
module: intersight_vsan_policy
short_description: Manage VSAN Policies and VSANs for Cisco Intersight
description:
  - Create, update, and delete VSAN (Virtual Storage Area Network) Policies on Cisco Intersight.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/fabric/FcNetworkPolicy/get/).
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
      - The name assigned to the VSAN Policy.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the VSAN Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  enable_trunking:
    description:
      - Enable or disable VSAN trunking on the policy.
      - When enabled, allows multiple VSANs to be carried over a single physical link.
    type: bool
    default: false
  vsans:
    description:
      - List of VSANs to be created and attached to the VSAN policy.
      - Each VSAN represents a virtual SAN segment.
      - Leave empty to create a policy without VSANs for manual configuration later.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - User-defined name for the VSAN configuration.
          - Must be unique within the VSAN policy.
        type: str
        required: true
      vsan_id:
        description:
          - Virtual SAN Identifier in the switch.
          - Valid range is typically 1-4094.
          - Must be unique within the fabric interconnect domain.
          - Required when state is present.
        type: int
      fcoe_vlan_id:
        description:
          - FCoE VLAN ID associated with the VSAN configuration.
          - Must be between 2 and 4093.
          - VLAN IDs from 4043-4047, 4094, and 4095 are reserved for system use.
          - Required when state is present.
        type: int
      vsan_scope:
        description:
          - Indicates whether the VSAN ID is defined for storage or uplink or both traffics in FI.
          - Required when state is present.
        type: str
        choices: ['uplink', 'storage', 'common']
      state:
        description:
          - Whether to create/update or delete the VSAN.
        type: str
        choices: ['present', 'absent']
        default: present
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a VSAN Policy with multiple VSANs
  cisco.intersight.intersight_vsan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "datacenter-vsan-policy"
    description: "VSAN policy for datacenter SAN infrastructure"
    enable_trunking: false
    tags:
      - Key: "Environment"
        Value: "Production"
      - Key: "Site"
        Value: "DataCenter-A"
    vsans:
      - name: "vsan_uplink_100"
        vsan_id: 100
        fcoe_vlan_id: 100
        vsan_scope: "uplink"
      - name: "vsan_storage_200"
        vsan_id: 200
        fcoe_vlan_id: 200
        vsan_scope: "storage"
      - name: "vsan_common_300"
        vsan_id: 300
        fcoe_vlan_id: 300
        vsan_scope: "common"
    state: present

- name: Create a VSAN Policy with trunking enabled
  cisco.intersight.intersight_vsan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "trunked-vsan-policy"
    description: "VSAN policy with trunking enabled"
    enable_trunking: true
    vsans:
      - name: "vsan_fabric_a"
        vsan_id: 10
        fcoe_vlan_id: 10
        vsan_scope: "common"
      - name: "vsan_fabric_b"
        vsan_id: 20
        fcoe_vlan_id: 20
        vsan_scope: "common"
    state: present

- name: Create a VSAN Policy without VSANs (for manual configuration)
  cisco.intersight.intersight_vsan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
    name: "empty-vsan-policy"
    description: "Empty policy for manual VSAN configuration"
    enable_trunking: false
    state: present

- name: Update an existing VSAN Policy
  cisco.intersight.intersight_vsan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "datacenter-vsan-policy"
    description: "Updated description for datacenter SAN infrastructure"
    enable_trunking: true
    tags:
      - Key: "Environment"
        Value: "Production"
      - Key: "Site"
        Value: "DataCenter-A"
      - Key: "Updated"
        Value: "2024-01-01"
    state: present

- name: Delete a VSAN from a policy
  cisco.intersight.intersight_vsan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "datacenter-vsan-policy"
    vsans:
      - name: "vsan_uplink_100"
        vsan_id: 100
        fcoe_vlan_id: 100
        vsan_scope: "uplink"
      - name: "vsan_storage_200"
        vsan_id: 200
        fcoe_vlan_id: 200
        vsan_scope: "storage"
        state: absent
    state: present

- name: Delete a VSAN Policy
  cisco.intersight.intersight_vsan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "datacenter-vsan-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "datacenter-vsan-policy",
        "ObjectType": "fabric.FcNetworkPolicy",
        "EnableTrunking": false,
        "Tags": [
            {
                "Key": "Site",
                "Value": "DataCenter-A"
            }
        ],
        "vsans": [
            {
                "Name": "vsan_uplink_100",
                "ObjectType": "fabric.Vsan",
                "VsanId": 100,
                "FcoeVlan": 100,
                "VsanScope": "Uplink"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        enable_trunking=dict(type='bool', default=False),
        vsans=dict(type='list', elements='dict', options=dict(
            name=dict(type='str', required=True),
            vsan_id=dict(type='int'),
            fcoe_vlan_id=dict(type='int'),
            vsan_scope=dict(type='str', choices=['uplink', 'storage', 'common']),
            state=dict(type='str', choices=['present', 'absent'], default='present')
        ))
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/fabric/FcNetworkPolicies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }
    if intersight.module.params['state'] == 'present':
        intersight.api_body['EnableTrunking'] = intersight.module.params['enable_trunking']
        intersight.set_tags_and_description()

    intersight.configure_policy_or_profile(resource_path=resource_path)

    # Store the VSAN policy response
    vsan_policy_response = intersight.result['api_response']

    vsan_policy_moid = None
    if intersight.module.params['state'] == 'present' and vsan_policy_response:
        vsan_policy_moid = vsan_policy_response.get('Moid')

    # Process VSANs if provided
    vsan_responses = []
    if intersight.module.params['state'] == 'present' and intersight.module.params.get('vsans'):
        for vsan_config in intersight.module.params['vsans']:
            # Validate VSAN configuration
            vsan_name = vsan_config['name']
            vsan_state = vsan_config.get('state', 'present')

            # If VSAN state is present, require vsan_id, fcoe_vlan_id, and vsan_scope
            if vsan_state == 'present':
                if not vsan_config.get('vsan_id'):
                    module.fail_json(msg=f"vsan_id is required for VSAN '{vsan_name}' when state is present")
                if not vsan_config.get('fcoe_vlan_id'):
                    module.fail_json(msg=f"fcoe_vlan_id is required for VSAN '{vsan_name}' when state is present")
                if not vsan_config.get('vsan_scope'):
                    module.fail_json(msg=f"vsan_scope is required for VSAN '{vsan_name}' when state is present")

            vsan_id = vsan_config.get('vsan_id')
            fcoe_vlan_id = vsan_config.get('fcoe_vlan_id')
            vsan_scope = vsan_config.get('vsan_scope')

            # Only build API body and validate if VSAN state is present
            if vsan_state == 'present':
                # Validate FCoE VLAN ID range
                if fcoe_vlan_id < 2 or fcoe_vlan_id > 4093 or (fcoe_vlan_id >= 4043 and fcoe_vlan_id <= 4047):
                    module.fail_json(msg=f"FCoE VLAN ID {fcoe_vlan_id} is invalid. Must be between 2 and 4093, excluding 4043-4047, 4094, and 4095.")

                # Build VSAN API body
                vsan_api_body = {
                    'Name': vsan_name,
                    'VsanId': vsan_id,
                    'FcoeVlan': fcoe_vlan_id,
                    'VsanScope': vsan_scope.capitalize(),
                    'FcNetworkPolicy': vsan_policy_moid
                }
                intersight.api_body = vsan_api_body

            # Create or delete the VSAN
            resource_path = '/fabric/Vsans'
            # Filter by both VSAN name AND FcNetworkPolicy to avoid affecting VSANs in other policies
            custom_filter = f"Name eq '{vsan_name}' and FcNetworkPolicy.Moid eq '{vsan_policy_moid}'"
            intersight.configure_secondary_resource(
                resource_path=resource_path,
                state=vsan_state,
                custom_filter=custom_filter
            )

            # Store the VSAN response
            if intersight.result.get('api_response'):
                vsan_responses.append(intersight.result['api_response'])

    # Combine VSAN policy and VSANs in the main response
    if vsan_policy_response:
        if vsan_responses:
            vsan_policy_response['vsans'] = vsan_responses
        intersight.result['api_response'] = vsan_policy_response

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
