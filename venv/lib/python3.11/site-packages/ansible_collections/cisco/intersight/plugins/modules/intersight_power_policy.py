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
module: intersight_power_policy
short_description: Power Policy configuration for Cisco Intersight
description:
  - Manages Power Policy configuration on Cisco Intersight.
  - A policy to configure the power settings on Cisco Intersight managed servers.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/power/Policy/get/).
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
      - The name assigned to the Power Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Power Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  target_platform:
    description:
      - The platform type for which the power policy is intended. This determines which settings are applicable.
      - This parameter is required when C(state) is C(present).
    type: str
    choices: ['all', 'standalone-server', 'fi-attached-server', 'chassis']
  power_profiling:
    description:
      - Sets the Power Profiling of the Server.
      - If Enabled, this field allows the power manager to run power profiling utility to determine the power needs of the server.
      - This field is only supported for Cisco UCS X series servers.
      - Applicable for 'fi-attached-server' and 'all' platforms.
    type: str
    choices: ['Enabled', 'Disabled']
    default: 'Enabled'
  power_priority:
    description:
      - Sets the Power Priority of the Server. This priority is used to determine the initial power allocation for servers.
      - This field is only supported for Cisco UCS B series and X series servers.
      - Applicable for 'fi-attached-server' and 'all' platforms.
    type: str
    choices: ['Low', 'Medium', 'High']
    default: 'Low'
  power_restore:
    description:
      - Sets the Power Restore State of the Server.
      - In the absence of Intersight connectivity, the chassis/server will use this policy to recover the host power after a power loss event.
      - Applicable for 'standalone-server', 'fi-attached-server', and 'all' platforms.
    type: str
    choices: ['AlwaysOff', 'AlwaysOn', 'LastState']
    default: 'AlwaysOff'
  power_redundancy:
    description:
      - Sets the Power Redundancy Mode of the Chassis. Redundancy Mode determines the number of PSUs the chassis keeps as redundant.
      - N+2 mode is only supported for Cisco UCS X series Chassis.
      - Applicable for 'chassis' and 'all' platforms.
    type: str
    choices: ['Grid', 'NotRedundant', 'N+1', 'N+2']
    default: 'Grid'
  processor_package_power_limit:
    description:
      - Sets the Processor Package Power Limit (PPL) of a server. PPL refers to the amount of power that a CPU can draw from the power supply.
      - The Processor Package Power Limit (PPL) feature is currently available exclusively on Cisco UCS C225/C245 M8 servers.
      - Applicable for 'standalone-server', 'fi-attached-server', and 'all' platforms.
    type: str
    choices: ['Default', 'Maximum', 'Minimum']
    default: 'Default'
  power_save_mode:
    description:
      - Sets the power save mode of the chassis.
      - If the requested power budget is less than available power capacity,
        the additional PSUs not required to comply with redundancy policy are placed in power save mode.
      - Applicable for 'chassis' and 'all' platforms.
    type: str
    choices: ['Enabled', 'Disabled']
    default: 'Enabled'
  dynamic_power_rebalancing:
    description:
      - Sets the dynamic power rebalancing mode of the chassis.
      - If enabled, this mode allows the chassis to dynamically reallocate the power between servers depending on their power usage.
      - Applicable for 'chassis' and 'all' platforms.
    type: str
    choices: ['Enabled', 'Disabled']
    default: 'Enabled'
  extended_power_capacity:
    description:
      - Sets the Extended Power Capacity of the Chassis.
      - If Enabled, this mode allows chassis available power to be increased by borrowing power from redundant power supplies.
      - This option is only supported for Cisco UCS X series Chassis.
      - Applicable for 'chassis' and 'all' platforms.
    type: str
    choices: ['Enabled', 'Disabled']
    default: 'Enabled'
  power_allocation:
    description:
      - Sets the limit for the maximum input power consumption by the chassis (in Watts). Set to 0 for no limit.
      - Applicable for 'chassis' and 'all' platforms.
    type: int
    default: 0
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a Power Policy for a Standalone Server
  cisco.intersight.intersight_power_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Standalone-Server-Power-Policy"
    description: "Power policy for standalone servers, restores to last state."
    target_platform: "standalone-server"
    power_restore: "LastState"
    processor_package_power_limit: "Minimum"
    tags:
      - Key: "Owner"
        Value: "DevOps"

- name: Create a Power Policy for a Chassis with N+1 Redundancy
  cisco.intersight.intersight_power_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Chassis-N1-Redundancy"
    description: "Power policy for chassis with N+1 redundancy."
    target_platform: "chassis"
    power_redundancy: "N+1"
    power_save_mode: "Disabled"
    power_allocation: 7500

- name: Create a universal Power Policy for FI-Attached Servers
  cisco.intersight.intersight_power_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "FI-Attached-Default"
    description: "Default power policy for all FI-attached servers."
    target_platform: "fi-attached-server"
    power_profiling: "Enabled"
    power_priority: "Medium"

- name: Delete a Power Policy
  cisco.intersight.intersight_power_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Standalone-Server-Power-Policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "FI-Attached-Default",
        "ObjectType": "power.Policy",
        "PowerPriority": "Medium",
        "PowerProfiling": "Enabled",
        "PowerRestoreState": "AlwaysOff",
        "Tags": [],
        ...
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec

ALL = 'all'
STANDALONE_SERVER = 'standalone-server'
FI_ATTACHED_SERVER = 'fi-attached-server'
CHASSIS = 'chassis'


def validate_input(module: AnsibleModule):
    power_allocation = module.params['power_allocation']
    if 0 > power_allocation or power_allocation > 65535:
        module.fail_json(msg=f"power_allocation has to be between 0 and 65535, current value is: {power_allocation}")


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        target_platform=dict(
            type='str',
            choices=[ALL, STANDALONE_SERVER, FI_ATTACHED_SERVER, CHASSIS]
        ),
        power_profiling=dict(
            type='str',
            choices=['Enabled', 'Disabled'],
            default='Enabled'
        ),
        power_priority=dict(
            type='str',
            choices=['Low', 'Medium', 'High'],
            default='Low'
        ),
        power_restore=dict(
            type='str',
            choices=['AlwaysOff', 'AlwaysOn', 'LastState'],
            default='AlwaysOff'
        ),
        power_redundancy=dict(
            type='str',
            choices=['Grid', 'NotRedundant', 'N+1', 'N+2'],
            default='Grid'
        ),
        processor_package_power_limit=dict(
            type='str',
            choices=['Default', 'Maximum', 'Minimum'],
            default='Default'
        ),
        power_save_mode=dict(
            type='str',
            choices=['Enabled', 'Disabled'],
            default='Enabled'
        ),
        dynamic_power_rebalancing=dict(
            type='str',
            choices=['Enabled', 'Disabled'],
            default='Enabled'
        ),
        extended_power_capacity=dict(
            type='str',
            choices=['Enabled', 'Disabled'],
            default='Enabled'
        ),
        power_allocation=dict(
            type='int',
            default=0
        ),
    )
    required_if = [
        ('state', 'present', ['target_platform']),
    ]
    module = AnsibleModule(
        argument_spec,
        required_if=required_if,
        supports_check_mode=True,
    )

    validate_input(module)
    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/power/Policies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if module.params['state'] == 'present':
        intersight.set_tags_and_description()

        platform = module.params['target_platform']

        # Chassis-specific parameters
        if platform in [CHASSIS, ALL]:
            intersight.api_body.update({
                "RedundancyMode": module.params['power_redundancy'],
                "PowerSaveMode": module.params['power_save_mode'],
                "DynamicRebalancing": module.params['dynamic_power_rebalancing'],
                "ExtendedPowerCapacity": module.params['extended_power_capacity'],
                "AllocatedBudget": module.params['power_allocation']
            })

        # Server-specific parameters (Standalone and FI-Attached)
        if platform in [STANDALONE_SERVER, FI_ATTACHED_SERVER, ALL]:
            intersight.api_body.update({
                "ProcessorPackagePowerLimit": module.params['processor_package_power_limit'],
                "PowerRestoreState": module.params['power_restore']
            })

        # FI-Attached specific parameters
        if platform in [FI_ATTACHED_SERVER, ALL]:
            intersight.api_body.update({
                "PowerPriority": module.params['power_priority'],
                "PowerProfiling": module.params['power_profiling']
            })

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
