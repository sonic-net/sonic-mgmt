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
module: intersight_firmware_policy
short_description: Firmware Policy configuration for Cisco Intersight
description:
  - Manages Firmware Policy configuration on Cisco Intersight.
  - A policy to configure firmware settings and versions for Cisco Intersight managed servers.
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
      - Profiles, Policies, and Pools that are created within a Custom Organization are applicable only to devices in the same Organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the Firmware Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Firmware Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
    default: []
  target_platform:
    description:
      - The platform type for which the firmware policy is intended.
      - Server type can be either Standalone or FIAttached.
      - This parameter is required when C(state) is C(present).
    type: str
    choices: ['Standalone', 'FIAttached']
  model_bundle_combo:
    description:
      - List of server model and firmware version pairs.
      - Each entry specifies which firmware version should be used for a specific server model family.
      - This parameter is required when C(state) is C(present).
    type: list
    elements: dict
    suboptions:
      model_family:
        description:
          - The server model family (e.g., UCSC-C220-M5, UCSC-C220-M4, UCSC-C220-M7).
        type: str
        required: true
      bundle_version:
        description:
          - The firmware bundle version to apply to the specified model family.
        type: str
        required: true
  exclude_drives:
    description:
      - When set to C(true), excludes local disk drives from firmware upgrades.
      - This adds local-disk to the ExcludeComponentList.
    type: bool
    default: false
  exclude_storage_controllers:
    description:
      - When set to C(true), excludes storage controllers from firmware upgrades.
      - This adds storage-controller to the ExcludeComponentList.
    type: bool
    default: false
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a firmware policy for standalone servers
  cisco.intersight.intersight_firmware_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Standalone-Firmware-Policy"
    description: "Firmware policy for standalone servers"
    target_platform: "Standalone"
    model_bundle_combo:
      - model_family: "UCSC-C220-M5"
        bundle_version: "4.3(2.250037)"
      - model_family: "UCSC-C220-M4"
        bundle_version: "4.1(2m)"
    tags:
      - Key: "Environment"
        Value: "Production"

- name: Create a firmware policy with excluded components
  cisco.intersight.intersight_firmware_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Firmware-Policy-With-Exclusions"
    description: "Firmware policy excluding storage components"
    target_platform: "Standalone"
    model_bundle_combo:
      - model_family: "UCSC-C220-M7"
        bundle_version: "4.3(4.242038)"
    exclude_drives: true
    exclude_storage_controllers: true
    tags:
      - Key: "Site"
        Value: "Datacenter1"

- name: Delete a firmware policy
  cisco.intersight.intersight_firmware_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Old-Firmware-Policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "Standalone-Firmware-Policy",
        "TargetPlatform": "Standalone",
        "ModelBundleCombo": [
            {
                "ModelFamily": "UCSC-C220-M5",
                "BundleVersion": "4.3(2.250037)"
            }
        ],
        "ExcludeComponentList": ["local-disk", "storage-controller"],
        "ObjectType": "firmware.Policy",
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


def validate_input(module):
    """
    Validate input parameters for the firmware policy module.
    """
    # Validate ModelBundleCombo entries
    model_bundle_combo = module.params.get('model_bundle_combo')
    for combo in model_bundle_combo:
        if not combo.get('model_family'):
            module.fail_json(msg="model_family is required for each entry in model_bundle_combo")
        if not combo.get('bundle_version'):
            module.fail_json(msg="bundle_version is required for each entry in model_bundle_combo")


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict', default=[]),
        target_platform=dict(type='str', choices=['Standalone', 'FIAttached']),
        exclude_drives=dict(type='bool', default=False),
        exclude_storage_controllers=dict(type='bool', default=False),
        model_bundle_combo=dict(
            type='list',
            elements='dict',
            options=dict(
                model_family=dict(type='str', required=True),
                bundle_version=dict(type='str', required=True)
            ),
        ),
    )

    required_if = [
        ['state', 'present', ['target_platform', 'model_bundle_combo']],
    ]

    module = AnsibleModule(
        argument_spec,
        required_if=required_if,
        supports_check_mode=True,
    )
    if module.params['state'] == 'present':
        validate_input(module)
    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/firmware/Policies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if module.params['state'] == 'present':
        intersight.set_tags_and_description()
        intersight.api_body['TargetPlatform'] = intersight.module.params['target_platform']

        # Set ModelBundleCombo
        model_bundle_combo = []
        for combo in module.params['model_bundle_combo']:
            model_bundle_combo.append({
                'ModelFamily': combo['model_family'],
                'BundleVersion': combo['bundle_version']
            })
        intersight.api_body['ModelBundleCombo'] = model_bundle_combo

        # Set exclude list
        exclude_components = []
        if module.params['exclude_drives']:
            exclude_components.append('local-disk')
        if module.params['exclude_storage_controllers']:
            exclude_components.append('storage-controller')
        intersight.api_body['ExcludeComponentList'] = exclude_components

    intersight.configure_policy_or_profile(resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
