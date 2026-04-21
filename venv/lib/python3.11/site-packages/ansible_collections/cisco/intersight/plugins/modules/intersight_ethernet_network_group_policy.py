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
module: intersight_ethernet_network_group_policy
short_description: Ethernet Network Group Policy configuration for Cisco Intersight
description:
  - Manages Ethernet Network Group Policy configuration on Cisco Intersight.
  - A policy to configure VLAN settings and QinQ (802.1Q-in-802.1Q) tunneling for Ethernet virtual interfaces on Cisco Intersight managed servers.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/fabric/EthNetworkGroupPolicy/get/).
extends_documentation_fragment: intersight
options:
  state:
    description:
      - If C(present), will verify the resource is present and will create if needed.
      - If C(absent), will verify the resource is absent and will delete if needed.
      - When C(absent), VLAN configuration parameters are not required.
    type: str
    choices: [present, absent]
    default: present
  organization:
    description:
      - The name of the Organization this resource is assigned to.
      - Profiles, Policies, and Pools that are created within a Custom Organization are applicable only to devices in the same Organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the Ethernet Network Group Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Ethernet Network Group Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  qinq_enabled:
    description:
      - Enable QinQ (802.1Q-in-802.1Q) Tunneling on the vNIC.
      - When enabled, C(qinq_vlan) is required and C(allowed_vlans) is ignored.
      - When disabled, C(allowed_vlans) is required.
    type: bool
    default: false
  qinq_vlan:
    description:
      - Set QinQ VLAN number.
      - Required when C(qinq_enabled) is true.
      - Only one QinQ VLAN can be specified.
      - Valid range is 2-4093.
    type: int
  native_vlan:
    description:
      - Set native VLAN for the Ethernet Network Group Policy.
      - Can be used with QinQ (when C(qinq_enabled) is true) or with regular VLAN mode (when C(qinq_enabled) is false).
      - When used with C(allowed_vlans), the native VLAN must be included in the allowed VLANs list.
      - Only one native VLAN can be specified.
      - Valid range is 1-4093.
    type: int
  allowed_vlans:
    description:
      - Include VLAN IDs using a list of comma separated VLAN IDs and VLAN ID Ranges.
      - Required when C(qinq_enabled) is false.
      - Examples of valid formats are C(1), C(1,2,3,4,8), C(1-4,7), C(1-8,12,16).
      - Valid VLAN range is 1-4093.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create an Ethernet Network Group Policy with regular VLANs
  cisco.intersight.intersight_ethernet_network_group_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "regular-vlans-policy"
    description: "Policy with regular VLAN configuration"
    qinq_enabled: false
    allowed_vlans: "1-8,12,16"
    state: present

- name: Create an Ethernet Network Group Policy with QinQ enabled
  cisco.intersight.intersight_ethernet_network_group_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "qinq-policy"
    description: "Policy with QinQ configuration"
    tags:
      - Key: "Environment"
        Value: "Production"
    qinq_enabled: true
    qinq_vlan: 4
    native_vlan: 1
    state: present

- name: Create an Ethernet Network Group Policy with QinQ enabled (no native VLAN)
  cisco.intersight.intersight_ethernet_network_group_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "qinq-no-native-policy"
    description: "QinQ policy without native VLAN"
    qinq_enabled: true
    qinq_vlan: 100
    state: present

- name: Create an Ethernet Network Group Policy with single VLAN
  cisco.intersight.intersight_ethernet_network_group_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "single-vlan-policy"
    description: "Policy with single VLAN"
    qinq_enabled: false
    allowed_vlans: "50"
    state: present

- name: Create an Ethernet Network Group Policy with native VLAN
  cisco.intersight.intersight_ethernet_network_group_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "native-vlan-policy"
    description: "Policy with allowed VLANs and native VLAN"
    qinq_enabled: false
    allowed_vlans: "1-100,200-300"
    native_vlan: 1
    state: present

- name: Delete an Ethernet Network Group Policy
  cisco.intersight.intersight_ethernet_network_group_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "qinq-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "regular-vlans-policy",
        "ObjectType": "fabric.EthNetworkGroupPolicy",
        "VlanSettings": {
            "ClassId": "fabric.VlanSettings",
            "ObjectType": "fabric.VlanSettings",
            "QinqEnabled": false,
            "AllowedVlans": "1-5,10,15-20"
        },
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Prod"
            }
        ]
    }
'''


import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def validate_allowed_vlans_format(allowed_vlans):
    """Validate allowed_vlans format and return parsed VLAN IDs"""
    if not allowed_vlans or not allowed_vlans.strip():
        return False, "allowed_vlans cannot be empty"

    # Remove all whitespace
    vlans_str = allowed_vlans.replace(' ', '')

    # Pattern to match: single VLAN (123) or VLAN range (123-456)
    # Full pattern: comma-separated list of single VLANs or ranges
    pattern = r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$'

    if not re.match(pattern, vlans_str):
        return False, "allowed_vlans must be in format '1', '1,2,3', '1-4', or '1-4,7,10-15'"

    # Parse and validate individual VLAN IDs and ranges
    vlan_parts = vlans_str.split(',')
    for part in vlan_parts:
        if '-' in part:
            try:
                start, end = part.split('-')
                start_id, end_id = int(start), int(end)
                if start_id >= end_id:
                    return False, f"Invalid VLAN range '{part}': start must be less than end"
                if start_id < 1 or start_id > 4093 or end_id < 1 or end_id > 4093:
                    return False, f"VLAN IDs in range '{part}' must be between 1 and 4093"
            except ValueError:
                return False, f"Invalid VLAN range format '{part}'"
        else:
            # Validate single vlan
            try:
                vlan_id = int(part)
                if vlan_id < 1 or vlan_id > 4093:
                    return False, f"VLAN ID '{vlan_id}' must be between 1 and 4093"
            except ValueError:
                return False, f"Invalid VLAN ID '{part}'"

    return True, None


def is_vlan_in_allowed_vlans(vlan_id, allowed_vlans_str):
    """Check if a VLAN ID is included in the allowed VLANs string"""
    # Remove all whitespace
    vlans_str = allowed_vlans_str.replace(' ', '')
    vlan_parts = vlans_str.split(',')

    for part in vlan_parts:
        if '-' in part:
            # VLAN range
            start, end = part.split('-')
            start_id, end_id = int(start), int(end)
            if start_id <= vlan_id <= end_id:
                return True
        else:
            # Single VLAN
            if int(part) == vlan_id:
                return True

    return False


def validate_vlan_ranges(module):
    """Validate VLAN range values and required parameters"""
    state = module.params.get('state')
    qinq_enabled = module.params.get('qinq_enabled')
    qinq_vlan = module.params.get('qinq_vlan')
    native_vlan = module.params.get('native_vlan')
    allowed_vlans = module.params.get('allowed_vlans')

    if state == 'present':
        if qinq_enabled:
            # When qinq_enabled is true, qinq_vlan is required
            if not qinq_vlan:
                module.fail_json(msg='missing required arguments: qinq_vlan')
        else:
            # When qinq_enabled is false, allowed_vlans is required
            if not allowed_vlans:
                module.fail_json(msg='missing required arguments: allowed_vlans')

    if qinq_vlan and (qinq_vlan < 2 or qinq_vlan > 4093):
        module.fail_json(msg='qinq_vlan must be between 2 and 4093')

    if native_vlan and (native_vlan < 1 or native_vlan > 4093):
        module.fail_json(msg='native_vlan must be between 1 and 4093')

    # Validate allowed_vlans format if provided and clean it
    if allowed_vlans:
        is_valid, error_msg = validate_allowed_vlans_format(allowed_vlans)
        if not is_valid:
            module.fail_json(msg=error_msg)
        # Store the cleaned version (whitespace removed) back to module.params
        module.params['allowed_vlans'] = allowed_vlans.replace(' ', '')

    # Validate native_vlan is in allowed_vlans when both are specified
    if native_vlan and allowed_vlans and not qinq_enabled:
        if not is_vlan_in_allowed_vlans(native_vlan, allowed_vlans):
            module.fail_json(msg=f'native_vlan {native_vlan} must be included in allowed_vlans: {allowed_vlans}')


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        qinq_enabled=dict(type='bool', default=False),  # Verify that placing default works with required_if
        qinq_vlan=dict(type='int'),
        native_vlan=dict(type='int'),
        allowed_vlans=dict(type='str'),
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ['allowed_vlans', 'qinq_vlan'],
        ],
    )

    validate_vlan_ranges(module)
    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/fabric/EthNetworkGroupPolicies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Build VlanSettings based on qinq_enabled
        vlan_settings = {
            'QinqEnabled': module.params['qinq_enabled']
        }

        if module.params['qinq_enabled']:
            vlan_settings['QinqVlan'] = module.params['qinq_vlan']
            if module.params['native_vlan']:
                vlan_settings['NativeVlan'] = module.params['native_vlan']
        else:
            # Regular VLAN mode
            vlan_settings['AllowedVlans'] = module.params['allowed_vlans']
            if module.params['native_vlan']:
                vlan_settings['NativeVlan'] = module.params['native_vlan']

        intersight.api_body.update({
            'VlanSettings': vlan_settings
        })

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
