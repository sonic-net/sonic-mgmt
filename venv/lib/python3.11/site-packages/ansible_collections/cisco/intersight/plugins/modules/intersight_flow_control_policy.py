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
module: intersight_flow_control_policy
short_description: Flow Control Policy configuration for Cisco Intersight
description:
  - Manages Flow Control Policy configuration on Cisco Intersight.
  - A policy to configure Priority Flow Control (PFC) and link-level flow control settings for Cisco Intersight managed fabric interconnects.
  - Priority Flow Control (PFC) enables no-drop behavior for specific traffic classes, while link-level flow control manages traffic flow at the link layer.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/fabric/FlowControlPolicies/get/).
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
      - The name assigned to the Flow Control Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Flow Control Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  priority_flow_control_mode:
    description:
      - Configure the Priority Flow Control (PFC) for each port to enable the no-drop behavior for the CoS defined by the System QoS Policy.
      - PFC works with Ethernet QoS policy to enable no-drop behavior for specific CoS values.
      - If Auto or On is selected for PFC, the Receive and Send link level flow control will be Off.
      - C(auto) - PFC is automatically configured based on the QoS policies (default).
      - C(on) - PFC is always enabled for the configured CoS values.
      - C(off) - PFC is disabled. Link-level flow control settings will be used instead.
    type: str
    choices: ['auto', 'on', 'off']
    default: auto
  receive_direction:
    description:
      - Link-level Flow Control configured in the receive direction.
      - This parameter is only applicable when C(priority_flow_control_mode) is set to C(off).
      - When C(priority_flow_control_mode) is C(auto) or C(on), this will be automatically set to C(disabled).
      - C(enabled) - Enable receive direction flow control.
      - C(disabled) - Disable receive direction flow control.
    type: str
    choices: [enabled, disabled]
    default: enabled
  send_direction:
    description:
      - Link-level Flow Control configured in the send direction.
      - This parameter is only applicable when C(priority_flow_control_mode) is set to C(off).
      - When C(priority_flow_control_mode) is C(auto) or C(on), this will be automatically set to C(disabled).
      - C(enabled) - Enable send direction flow control.
      - C(disabled) - Disable send direction flow control.
    type: str
    choices: [enabled, disabled]
    default: enabled
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a Flow Control Policy with auto PFC mode
  cisco.intersight.intersight_flow_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "FlowControl-Auto-Policy"
    description: "Flow control policy with auto PFC"
    priority_flow_control_mode: auto
    tags:
      - Key: "Site"
        Value: "DataCenter-A"
    state: present

- name: Create a Flow Control Policy with PFC enabled
  cisco.intersight.intersight_flow_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "FlowControl-PFC-On-Policy"
    description: "Flow control policy with PFC always on"
    priority_flow_control_mode: on
    state: present

- name: Create a Flow Control Policy with link-level flow control
  cisco.intersight.intersight_flow_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "FlowControl-LinkLevel-Policy"
    description: "Flow control policy with link-level settings"
    priority_flow_control_mode: off
    receive_direction: enabled
    send_direction: enabled
    state: present

- name: Create a Flow Control Policy with disabled flow control
  cisco.intersight.intersight_flow_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "FlowControl-Disabled-Policy"
    priority_flow_control_mode: off
    receive_direction: disabled
    send_direction: disabled
    state: present

- name: Update a Flow Control Policy
  cisco.intersight.intersight_flow_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "FlowControl-Auto-Policy"
    description: "Updated flow control policy"
    priority_flow_control_mode: on
    state: present

- name: Delete a Flow Control Policy
  cisco.intersight.intersight_flow_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "FlowControl-Auto-Policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "FlowControl-Auto-Policy",
        "ObjectType": "fabric.FlowControlPolicy",
        "PriorityFlowControlMode": "auto",
        "ReceiveDirection": "Enabled",
        "SendDirection": "Enabled",
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


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        priority_flow_control_mode=dict(type='str', choices=['auto', 'on', 'off'], default='auto'),
        receive_direction=dict(type='str', choices=['enabled', 'disabled'], default='enabled'),
        send_direction=dict(type='str', choices=['enabled', 'disabled'], default='enabled')
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/fabric/FlowControlPolicies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Convert lowercase choices to API format
        priority_mode = intersight.module.params['priority_flow_control_mode']
        intersight.api_body['PriorityFlowControlMode'] = priority_mode

        # Set receive and send direction based on priority flow control mode
        # When PFC is auto or on, receive/send must be disabled
        # When PFC is off, use the configured receive/send direction values
        if priority_mode in ['auto', 'on']:
            intersight.api_body['ReceiveDirection'] = 'Disabled'
            intersight.api_body['SendDirection'] = 'Disabled'
        else:
            receive_dir = intersight.module.params['receive_direction']
            intersight.api_body['ReceiveDirection'] = receive_dir.capitalize()
            send_dir = intersight.module.params['send_direction']
            intersight.api_body['SendDirection'] = send_dir.capitalize()

    # Configure the policy
    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
