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
module: intersight_thermal_policy
short_description: Thermal Policy configuration for Cisco Intersight
description:
  - Manages Thermal Policy configuration on Cisco Intersight.
  - A policy to configure the fan control mode on Cisco Intersight managed servers.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/thermal/Policy/get/).
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
      - Profiles, Policies, and Pools that are created within a Custom Organization are applicable only to devices in the same Organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the Thermal Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Thermal Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  fan_control_mode:
    description:
      - Sets the Fan Control Mode.
      - High Power, Maximum Power and Acoustic modes are supported only on the Cisco UCS C-Series servers and on the X-Series Chassis.
    type: str
    choices: ['Balanced', 'LowPower', 'HighPower', 'MaximumPower', 'Acoustic']
    default: 'Balanced'
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a Thermal Policy with High Power fan mode
  cisco.intersight.intersight_thermal_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "HighPower-Thermal-Policy"
    description: "High power thermal policy"
    tags:
      - Key: "Site"
        Value: "DataCenter-A"
    fan_control_mode: "HighPower"
    state: present

- name: Create a Thermal Policy using the default Balanced fan mode
  cisco.intersight.intersight_thermal_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Balanced-Power-Policy"
    description: "A standard thermal policy for general use."
    state: present

- name: Delete a Thermal Policy
  cisco.intersight.intersight_thermal_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "HighPower-Thermal-Policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "test_thermal_policy",
        "ObjectType": "thermal.Policy",
        "FanControlMode": "LowPower",
        "Tags": [
            {
                "Key": "Site",
                "Value": "tag1"
            },
            {
                "Key": "Site2",
                "Value": "tag2"
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
        fan_control_mode=dict(
            type='str',
            choices=['Balanced', 'LowPower', 'HighPower', 'MaximumPower', 'Acoustic'],
            default='Balanced'
        )
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/thermal/Policies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
        'FanControlMode': intersight.module.params['fan_control_mode']
    }

    intersight.set_tags_and_description()

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
