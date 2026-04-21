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
module: intersight_switch_control_policy
short_description: Switch Control Policy configuration for Cisco Intersight
description:
  - Manages Switch Control Policy configuration on Cisco Intersight.
  - A policy to configure switching modes, VLAN optimization, MAC address aging, and UDLD settings for Cisco Intersight managed fabric interconnects.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/fabric/SwitchControlPolicies/get/).
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
      - The name assigned to the Switch Control Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Switch Control Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  ethernet_switching_mode:
    description:
      - Enable or Disable Ethernet End Host Switching Mode.
      - Ethernet End Host Switching Mode is not applicable for Unified Edge; the value defaults to Ethernet Switch Mode.
      - C(end-host) - Ethernet End Host Switching Mode (default).
      - C(switch) - Ethernet Switch Mode.
    type: str
    choices: [end-host, switch]
    default: end-host
  fc_switching_mode:
    description:
      - Enable or Disable FC End Host Switching Mode.
      - FC is not supported on Unified Edge, so this setting cannot be configured and is ignored.
      - C(end-host) - FC End Host Switching Mode (default).
      - C(switch) - FC Switch Mode.
    type: str
    choices: [end-host, switch]
    default: end-host
  vlan_port_optimization_enabled:
    description:
      - To enable or disable the VLAN port count optimization.
      - This feature will always be enabled for Cisco UCS Fabric Interconnect 9108 100G.
      - Also enabled on the IMM 6.x Bundle version and onwards.
      - VLAN Port Count Optimization is not applicable for Unified Edge.
    type: bool
    default: false
  reserved_vlan_start_id:
    description:
      - The starting ID for VLANs reserved for internal use within the Fabric Interconnect.
      - This VLAN ID is the starting ID of a contiguous block of 128 VLANs that cannot be configured for user data.
      - This range of VLANs cannot be configured in VLAN policy.
      - If this property is not configured, VLAN range 3915 - 4042 is reserved for internal use by default.
      - The reserved VLAN range is fixed for Unified Edge, so this setting cannot be configured and is ignored.
    type: int
    default: 3915
  mac_aging_option:
    description:
      - MAC address aging time configuration option.
      - C(default) - Use default MAC aging time with UDLD message interval (default).
      - C(custom) - Use custom MAC aging time in seconds.
      - C(never) - MAC addresses never age out.
    type: str
    choices: [default, custom, never]
    default: default
  mac_aging_time:
    description:
      - Define the MAC address aging time in seconds.
      - This field is valid when the C(mac_aging_option) is set to C(custom).
      - Valid range is 120-918000 seconds.
    type: int
    default: 14500
  message_interval:
    description:
      - Configures the time between UDLD probe messages on the UDLD enabled ports.
      - Valid values are from 7 to 90 seconds.
    type: int
    default: 15
  recovery_action:
    description:
      - UDLD recovery action when enabled, attempts to bring an UDLD error-disabled port out of reset.
      - C(none) - No recovery action (default).
      - C(reset) - Reset the port to recover from UDLD error-disabled state.
    type: str
    choices: [none, reset]
    default: none
  fabric_pc_vhba_reset:
    description:
      - When enabled, a Registered State Change Notification (RSCN) is sent to the VIC adapter.
      - This occurs when any member port within the fabric port-channel goes down and vHBA would reset to restore the connection immediately.
      - When disabled (default), vHBA reset is done only when all the members of a fabric port-channel are down.
      - Fabric port-channel vHBA reset is not supported on Unified Edge and cannot be enabled.
      - C(enabled) - Enable fabric port-channel vHBA reset.
      - C(disabled) - Disable fabric port-channel vHBA reset (default).
    type: str
    choices: [enabled, disabled]
    default: disabled
  primary_key:
    description:
      - Encrypts MACsec keys in type-6 format.
      - If a MACsec key is already provided in a type-6 format, the primary key decrypts it.
      - MACSec is not supported on Unified Edge, so the primary key cannot be configured.
      - Must be 16-64 characters in length when specified.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a Switch Control Policy with default settings
  cisco.intersight.intersight_switch_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "SwitchControl-Policy-01"
    description: "Switch control policy with default settings"
    tags:
      - Key: "Site"
        Value: "DataCenter-A"
    state: present

- name: Create a Switch Control Policy with custom settings
  cisco.intersight.intersight_switch_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "SwitchControl-Custom-Policy"
    description: "Switch control policy with custom MAC aging"
    ethernet_switching_mode: switch
    fc_switching_mode: switch
    vlan_port_optimization_enabled: true
    reserved_vlan_start_id: 3915
    mac_aging_option: custom
    mac_aging_time: 14500
    message_interval: 15
    recovery_action: reset
    fabric_pc_vhba_reset: enabled
    primary_key: "mySecureKey12345"
    state: present

- name: Create a Switch Control Policy with end-host mode
  cisco.intersight.intersight_switch_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "SwitchControl-EndHost-Policy"
    ethernet_switching_mode: end-host
    fc_switching_mode: end-host
    vlan_port_optimization_enabled: false
    recovery_action: none
    fabric_pc_vhba_reset: disabled
    state: present

- name: Create a Switch Control Policy with never aging MAC addresses
  cisco.intersight.intersight_switch_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "SwitchControl-NeverAge-Policy"
    mac_aging_option: never
    message_interval: 20
    state: present

- name: Update a Switch Control Policy
  cisco.intersight.intersight_switch_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "SwitchControl-Policy-01"
    description: "Updated switch control policy"
    ethernet_switching_mode: switch
    vlan_port_optimization_enabled: true
    state: present

- name: Delete a Switch Control Policy
  cisco.intersight.intersight_switch_control_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "SwitchControl-Policy-01"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "SwitchControl-Policy-01",
        "ObjectType": "fabric.SwitchControlPolicy",
        "EthernetSwitchingMode": "end-host",
        "FcSwitchingMode": "end-host",
        "VlanPortOptimizationEnabled": false,
        "ReservedVlanStartId": 3915,
        "MacAgingSettings": {
            "MacAgingOption": "Default"
        },
        "UdldSettings": {
            "MessageInterval": 15,
            "RecoveryAction": "none"
        },
        "FabricPcVhbaReset": "Disabled",
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
        ethernet_switching_mode=dict(type='str', choices=['end-host', 'switch'], default='end-host'),
        fc_switching_mode=dict(type='str', choices=['end-host', 'switch'], default='end-host'),
        vlan_port_optimization_enabled=dict(type='bool', default=False),
        reserved_vlan_start_id=dict(type='int', default=3915),
        mac_aging_option=dict(type='str', choices=['default', 'custom', 'never'], default='default'),
        mac_aging_time=dict(type='int', default=14500),
        message_interval=dict(type='int', default=15),
        recovery_action=dict(type='str', choices=['none', 'reset'], default='none'),
        fabric_pc_vhba_reset=dict(type='str', choices=['enabled', 'disabled'], default='disabled'),
        primary_key=dict(type='str', no_log=True)
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/fabric/SwitchControlPolicies'

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
        ethernet_mode = intersight.module.params['ethernet_switching_mode']
        intersight.api_body['EthernetSwitchingMode'] = ethernet_mode

        fc_mode = intersight.module.params['fc_switching_mode']
        intersight.api_body['FcSwitchingMode'] = fc_mode

        intersight.api_body['VlanPortOptimizationEnabled'] = intersight.module.params['vlan_port_optimization_enabled']
        intersight.api_body['ReservedVlanStartId'] = intersight.module.params['reserved_vlan_start_id']

        # Build MacAgingSettings object
        mac_aging_option = intersight.module.params['mac_aging_option']
        mac_aging_settings = {
            'MacAgingOption': mac_aging_option.capitalize()
        }
        if mac_aging_option == 'custom':
            mac_aging_settings['MacAgingTime'] = intersight.module.params['mac_aging_time']

        intersight.api_body['MacAgingSettings'] = mac_aging_settings

        # Build UdldSettings object
        intersight.api_body['UdldSettings'] = {
            'MessageInterval': intersight.module.params['message_interval'],
            'RecoveryAction': intersight.module.params['recovery_action']
        }

        # Set fabric port-channel vHBA reset
        fabric_pc_vhba_reset = intersight.module.params['fabric_pc_vhba_reset']
        intersight.api_body['FabricPcVhbaReset'] = fabric_pc_vhba_reset.capitalize()

        # Set primary key if provided
        if intersight.module.params.get('primary_key'):
            intersight.api_body['AesPrimaryKey'] = intersight.module.params['primary_key']
        else:
            intersight.api_body['AesPrimaryKey'] = ""

    # Configure the policy
    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
