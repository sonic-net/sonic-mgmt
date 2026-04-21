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
module: intersight_device_connector_policy
short_description: Device Connector Policy configuration for Cisco Intersight
description:
  - Manages Device Connector Policy configuration on Cisco Intersight.
  - A policy to configure device connector settings for Cisco Intersight managed devices.
  - Enables or disables configuration lockout on the endpoint to prevent local configuration changes.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs).
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
      - Profiles and Policies that are created within a Custom Organization are applicable only to devices in the same Organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the Device Connector Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Device Connector Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
    default: []
  enable_lockout:
    description:
      - Enables configuration lockout on the endpoint.
      - When enabled, prevents local configuration changes on the device through IMC or CIMC interfaces.
      - Lockout ensures that all configuration changes must be made through Intersight.
    type: bool
    default: false
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create Device Connector Policy with lockout enabled
  cisco.intersight.intersight_device_connector_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "device-connector-lockout-policy"
    description: "Device connector policy with lockout enabled"
    enable_lockout: true
    tags:
      - Key: "Environment"
        Value: "Production"
    state: present

- name: Create Device Connector Policy with lockout disabled
  cisco.intersight.intersight_device_connector_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "device-connector-no-lockout-policy"
    description: "Device connector policy with lockout disabled"
    enable_lockout: false
    state: present

- name: Update existing Device Connector Policy
  cisco.intersight.intersight_device_connector_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "device-connector-lockout-policy"
    description: "Updated device connector policy"
    enable_lockout: false
    state: present

- name: Delete Device Connector Policy
  cisco.intersight.intersight_device_connector_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "device-connector-lockout-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "device-connector-lockout-policy",
        "ObjectType": "deviceconnector.Policy",
        "Description": "Device connector policy with lockout enabled",
        "LockoutEnabled": true,
        "Organization": {
            "Moid": "675450ee69726530014753e2",
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


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict', default=[]),
        enable_lockout=dict(type='bool', default=False)
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    intersight.api_body = {
        'Organization': {
            'Name': module.params['organization'],
        },
        'Name': module.params['name']
    }
    if module.params['state'] == 'present':
        intersight.set_tags_and_description()
        intersight.api_body['LockoutEnabled'] = module.params['enable_lockout']

    resource_path = '/deviceconnector/Policies'
    intersight.configure_policy_or_profile(resource_path=resource_path)
    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
