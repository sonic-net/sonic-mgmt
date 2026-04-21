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
module: intersight_adapter_config_policy
short_description: Adapter Configuration Policy for Cisco Intersight
description:
  - Manages Adapter Configuration Policy on Cisco Intersight.
  - This policy allows you to configure adapter settings such as LLDP, FIP, Port Channel, and FEC mode.
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
      - The name assigned to the Adapter Configuration Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Adapter Configuration Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
    default: []
  settings:
    description:
      - List of adapter configurations.
    type: list
    elements: dict
    suboptions:
      slot_id:
        description:
          - PCIe slot where the VIC adapter is installed.
          - Supported values are (1-15) and MLOM.
        type: str
        required: true
      enable_lldp:
        description:
          - Status of LLDP protocol on the adapter interfaces.
        type: bool
        default: true
      enable_fip:
        description:
          - Status of FIP protocol on the adapter interfaces.
        type: bool
        default: true
      enable_port_channel:
        description:
          - Status of Port Channel on the adapter interfaces.
          - When enabled, two vNICs and two vHBAs are available.
          - When disabled, four vNICs and four vHBAs are available.
          - Disabling port channel reboots the server.
          - Supported only for Cisco VIC 1455/1457 adapters.
        type: bool
        default: true
      dce_interface_1_fec_mode:
        description:
          - Forward Error Correction (FEC) mode setting for DCE interface 1 (Interface ID 0).
          - Supported only for Cisco VIC 14xx adapters.
          - FEC mode 'cl74' is unsupported for Cisco VIC 1495/1497.
        type: str
        choices: ['cl91', 'cl74', 'off']
        default: cl91
      dce_interface_2_fec_mode:
        description:
          - Forward Error Correction (FEC) mode setting for DCE interface 2 (Interface ID 1).
        type: str
        choices: ['cl91', 'cl74', 'off']
        default: cl91
      dce_interface_3_fec_mode:
        description:
          - Forward Error Correction (FEC) mode setting for DCE interface 3 (Interface ID 2).
        type: str
        choices: ['cl91', 'cl74', 'off']
        default: cl91
      dce_interface_4_fec_mode:
        description:
          - Forward Error Correction (FEC) mode setting for DCE interface 4 (Interface ID 3).
        type: str
        choices: ['cl91', 'cl74', 'off']
        default: cl91
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create Adapter Config Policy
  cisco.intersight.intersight_adapter_config_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "adapter-config-policy"
    description: "Policy for VIC 1455"
    settings:
      - slot_id: "2"
        enable_lldp: true
        enable_fip: true
        enable_port_channel: true
        dce_interface_1_fec_mode: "cl91"
        dce_interface_2_fec_mode: "cl91"
        dce_interface_3_fec_mode: "cl91"
        dce_interface_4_fec_mode: "off"
    state: present

- name: Delete Adapter Config Policy
  cisco.intersight.intersight_adapter_config_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "adapter-config-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample: {
    "Name": "adapter-config-policy",
    "ObjectType": "adapter.ConfigPolicy",
    "Settings": [
      {
        "SlotId": "2",
        "EthSettings": {
          "LldpEnabled": true
        },
        "FcSettings": {
          "FipEnabled": true
        },
        "PortChannelSettings": {
          "Enabled": true
        },
        "DceInterfaceSettings": [
          {
            "FecMode": "cl91",
            "InterfaceId": 0
          }
        ]
      }
    ]
  }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def format_fec_mode(mode):
    """
    Format FEC mode string for API.
    'off' should be 'Off'.
    """
    if mode and mode.lower() == 'off':
        return 'Off'
    return mode


def build_settings_config(settings):
    """
    Build Settings configuration for API body.
    """
    settings_list = []
    for setting in settings:
        config = {
            'ObjectType': 'adapter.AdapterConfig',
            'SlotId': setting['slot_id'],
            'EthSettings': {
                'LldpEnabled': setting['enable_lldp'],
                'ObjectType': 'adapter.EthSettings'
            },
            'FcSettings': {
                'FipEnabled': setting['enable_fip'],
                'ObjectType': 'adapter.FcSettings'
            },
            'PortChannelSettings': {
                'Enabled': setting['enable_port_channel'],
                'ObjectType': 'adapter.PortChannelSettings'
            },
            'PhysicalNicModeSettings': {
                'PhyNicEnabled': False,
                'ObjectType': 'adapter.PhysicalNicModeSettings'
            }
        }

        dce_settings = []
        # Interface 1
        dce_settings.append({
            'ObjectType': 'adapter.DceInterfaceSettings',
            'InterfaceId': 0,
            'FecMode': format_fec_mode(setting['dce_interface_1_fec_mode'])
        })
        # Interface 2
        dce_settings.append({
            'ObjectType': 'adapter.DceInterfaceSettings',
            'InterfaceId': 1,
            'FecMode': format_fec_mode(setting['dce_interface_2_fec_mode'])
        })
        # Interface 3
        dce_settings.append({
            'ObjectType': 'adapter.DceInterfaceSettings',
            'InterfaceId': 2,
            'FecMode': format_fec_mode(setting['dce_interface_3_fec_mode'])
        })
        # Interface 4
        dce_settings.append({
            'ObjectType': 'adapter.DceInterfaceSettings',
            'InterfaceId': 3,
            'FecMode': format_fec_mode(setting['dce_interface_4_fec_mode'])
        })

        config['DceInterfaceSettings'] = dce_settings
        settings_list.append(config)

    return settings_list


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict', default=[]),
        settings=dict(
            type='list',
            elements='dict',
            options=dict(
                slot_id=dict(type='str', required=True),
                enable_lldp=dict(type='bool', default=True),
                enable_fip=dict(type='bool', default=True),
                enable_port_channel=dict(type='bool', default=True),
                dce_interface_1_fec_mode=dict(type='str', choices=['cl91', 'cl74', 'off'], default='cl91'),
                dce_interface_2_fec_mode=dict(type='str', choices=['cl91', 'cl74', 'off'], default='cl91'),
                dce_interface_3_fec_mode=dict(type='str', choices=['cl91', 'cl74', 'off'], default='cl91'),
                dce_interface_4_fec_mode=dict(type='str', choices=['cl91', 'cl74', 'off'], default='cl91'),
            )
        )
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
        'Name': module.params['name'],
        'ObjectType': 'adapter.ConfigPolicy'
    }

    if module.params['state'] == 'present':
        intersight.set_tags_and_description()

        if module.params.get('settings'):
            intersight.api_body['Settings'] = build_settings_config(module.params['settings'])

    resource_path = '/adapter/ConfigPolicies'
    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
