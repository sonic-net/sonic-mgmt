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
module: intersight_link_control_policy
short_description: Link Control Policy configuration for Cisco Intersight
description:
  - Manages Link Control Policy configuration on Cisco Intersight.
  - A policy to configure UDLD (UniDirectional Link Detection) settings on Cisco Intersight managed devices.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/fabric/LinkControlPolicy/get/).
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
      - The name assigned to the Link Control Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Link Control Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  udld_admin_state:
    description:
      - UDLD Admin configured Link State for this port.
    type: str
    choices: ['Enabled', 'Disabled']
    default: 'Enabled'
  udld_mode:
    description:
      - UDLD Admin configured Mode for this port.
      - Cannot be set to 'aggressive' when udld_admin_state is 'Disabled'.
    type: str
    choices: ['normal', 'aggressive']
    default: 'normal'
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Configure Link Control Policy with UDLD enabled in aggressive mode
  cisco.intersight.intersight_link_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "test-link-aggressive"
    description: "Link Control Policy with aggressive UDLD"
    udld_admin_state: "Enabled"
    udld_mode: "aggressive"
    tags:
      - Key: Site
        Value: DataCenter-A

- name: Configure Link Control Policy with UDLD disabled
  cisco.intersight.intersight_link_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "test-link-disabled"
    description: "Link Control Policy with UDLD disabled"
    udld_admin_state: "Disabled"
    udld_mode: "normal"

- name: Delete Link Control Policy
  cisco.intersight.intersight_link_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "test-link-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "test-link-policy",
        "ObjectType": "fabric.LinkControlPolicy",
        "UdldSettings": {
            "AdminState": "Enabled",
            "Mode": "aggressive",
            "ClassId": "fabric.UdldSettings",
            "ObjectType": "fabric.UdldSettings"
        },
        "Tags": [
            {
                "Key": "Site",
                "Value": "DataCenter-A"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def validate_udld_configuration(module):
    """
    Validate UDLD configuration to ensure aggressive mode is not used when admin state is disabled.
    """
    udld_admin_state = module.params['udld_admin_state']
    udld_mode = module.params['udld_mode']

    if udld_admin_state == 'Disabled' and udld_mode == 'aggressive':
        module.fail_json(
            msg="Cannot configure the link control policy. Mode should not be 'aggressive' when the policy is disabled."
        )


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        udld_admin_state=dict(type='str', choices=['Enabled', 'Disabled'], default='Enabled'),
        udld_mode=dict(type='str', choices=['normal', 'aggressive'], default='normal')
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    # Validate UDLD configuration
    validate_udld_configuration(module)

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/fabric/LinkControlPolicies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()
        intersight.api_body['UdldSettings'] = {
            'AdminState': intersight.module.params['udld_admin_state'],
            'Mode': intersight.module.params['udld_mode']
        }

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
