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
module: intersight_port_policy_info
short_description: Gather information about Cisco Intersight Port Policies
description:
  - Gathers information about Port Policies and their associated resources on Cisco Intersight.
  - Retrieves comprehensive information including breakout ports, server ports, uplink port channels, pin groups, and all other port configurations.
  - Supports filtering by policy name and organization.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/fabric/PortPolicies/get/).
extends_documentation_fragment: intersight
options:
  name:
    description:
      - Name of the Port Policy to retrieve information for.
      - If not provided, information for all Port Policies will be returned.
    type: str
  organization:
    description:
      - The name of the Organization to filter policies by.
      - If not provided, policies from all accessible organizations will be returned.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Get information about all Port Policies
  cisco.intersight.intersight_port_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
  register: all_port_policies

- name: Get information about a specific Port Policy
  cisco.intersight.intersight_port_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "port-policy-example"
  register: specific_policy

- name: Get information about Port Policies in a specific organization
  cisco.intersight.intersight_port_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "production"
  register: org_policies

- name: Get information about a specific Port Policy in a specific organization
  cisco.intersight.intersight_port_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "port-policy-example"
    organization: "production"
  register: specific_org_policy
'''

RETURN = r'''
api_response:
  description: List of Port Policy information with all associated resources
  returned: always
  type: list
  elements: dict
  sample: [
    {
      "Name": "port-policy-example",
      "Moid": "5dee1d736972652d321d26b5",
      "ObjectType": "fabric.PortPolicy",
      "DeviceModel": "UCS-FI-6454",
      "Description": "Example port policy with various configurations",
      "Organization": {
        "Name": "default",
        "Moid": "5dee1d736972652d321d26b5",
        "ObjectType": "organization.Organization"
      },
      "Tags": [
        {
          "Key": "Environment",
          "Value": "Production"
        }
      ],
      "BreakoutPorts": [
        {
          "PortId": 49,
          "CustomMode": "BreakoutEthernet25G",
          "SlotId": 1,
          "Moid": "5dee1d736972652d321d26b6",
          "ObjectType": "fabric.PortMode"
        }
      ],
      "FcPortModes": [
        {
          "PortIdStart": 1,
          "PortIdEnd": 16,
          "SlotId": 1,
          "CustomMode": "FibreChannel",
          "Moid": "5dee1d736972652d321d26b7",
          "ObjectType": "fabric.PortMode"
        }
      ],
      "ServerRoles": [
        {
          "PortId": 1,
          "AggregatePortId": 49,
          "SlotId": 1,
          "Fec": "Auto",
          "UserLabel": "Server Port 1",
          "PreferredDeviceType": "Chassis",
          "PreferredDeviceId": 1,
          "Moid": "5dee1d736972652d321d26b8",
          "ObjectType": "fabric.ServerRole"
        }
      ],
      "UplinkPcRoles": [
        {
          "PcId": 123,
          "AdminSpeed": "25Gbps",
          "Fec": "Auto",
          "UserLabel": "Uplink PC 123",
          "SlotId": 1,
          "Moid": "5dee1d736972652d321d26b9",
          "ObjectType": "fabric.UplinkPcRole",
          "Ports": [
            {
              "PortId": 1,
              "SlotId": 1,
              "AggregatePortId": 0
            },
            {
              "PortId": 2,
              "SlotId": 1,
              "AggregatePortId": 0
            }
          ],
          "EthNetworkGroupPolicy": [
            {
              "Moid": "5dee1d736972652d321d26ba",
              "ObjectType": "fabric.EthNetworkGroupPolicy"
            }
          ],
          "FlowControlPolicy": {
            "Moid": "5dee1d736972652d321d26bb",
            "ObjectType": "fabric.FlowControlPolicy"
          },
          "LinkAggregationPolicy": {
            "Moid": "5dee1d736972652d321d26bc",
            "ObjectType": "fabric.LinkAggregationPolicy"
          },
          "LinkControlPolicy": {
            "Moid": "5dee1d736972652d321d26bd",
            "ObjectType": "fabric.LinkControlPolicy"
          }
        }
      ],
      "FcUplinkPortChannels": [
        {
          "PcId": 13,
          "AdminSpeed": "16Gbps",
          "VsanId": 1,
          "UserLabel": "FC Uplink PC 13",
          "SlotId": 1,
          "Moid": "5dee1d736972652d321d26be",
          "ObjectType": "fabric.FcUplinkPcRole",
          "Ports": [
            {
              "PortId": 17,
              "SlotId": 1,
              "AggregatePortId": 0
            },
            {
              "PortId": 18,
              "SlotId": 1,
              "AggregatePortId": 0
            }
          ]
        }
      ],
      "FcUplinkRoles": [
        {
          "PortId": 19,
          "AdminSpeed": "16Gbps",
          "VsanId": 1,
          "UserLabel": "FC Uplink 19",
          "SlotId": 1,
          "Moid": "5dee1d736972652d321d26bf",
          "ObjectType": "fabric.FcUplinkRole"
        }
      ],
      "UplinkRoles": [
        {
          "PortId": 3,
          "AdminSpeed": "25Gbps",
          "Fec": "Auto",
          "UserLabel": "Ethernet Uplink 3",
          "SlotId": 1,
          "Moid": "5dee1d736972652d321d26c0",
          "ObjectType": "fabric.UplinkRole"
        }
      ],
      "LanPinGroups": [
        {
          "Name": "pin-group-1",
          "Moid": "5dee1d736972652d321d26c1",
          "ObjectType": "fabric.LanPinGroup",
          "PinTargetInterfaceRole": {
            "Moid": "5dee1d736972652d321d26c2",
            "ObjectType": "fabric.UplinkPcRole"
          }
        }
      ],
      "SanPinGroups": [
        {
          "Name": "san-pin-group-1",
          "Moid": "5dee1d736972652d321d26c3",
          "ObjectType": "fabric.SanPinGroup",
          "PinTargetInterfaceRole": {
            "Moid": "5dee1d736972652d321d26c4",
            "ObjectType": "fabric.FcUplinkPcRole"
          }
        }
      ],
      "FcoeUplinkPcRoles": [],
      "AppliancePcRoles": [],
      "FcStorageRoles": [],
      "ApplianceRoles": [],
      "FcoeUplinkRoles": []
    }
  ]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def get_port_policy_secondary_resources(intersight, port_policy_moid):
    """
    Retrieve all secondary resources associated with a port policy.

    Args:
        intersight: IntersightModule instance
        port_policy_moid: MOID of the port policy

    Returns:
        Dictionary containing all secondary resources
    """
    # Initialize all resource keys to ensure consistent structure
    secondary_resources = {
        'BreakoutPorts': [],
        'FcPortModes': [],
        'ServerRoles': [],
        'UplinkPcRoles': [],
        'FcUplinkPortChannels': [],
        'FcoeUplinkPcRoles': [],
        'AppliancePcRoles': [],
        'FcUplinkRoles': [],
        'FcStorageRoles': [],
        'ApplianceRoles': [],
        'UplinkRoles': [],
        'FcoeUplinkRoles': [],
        'LanPinGroups': [],
        'SanPinGroups': [],
    }

    # Define resource mappings based on actual endpoints used in intersight_port_policy.py
    resource_mappings = [
        # Port Modes (FC port mode and Breakout ports)
        ('/fabric/PortModes', 'PortModes'),

        # Port Channels
        ('/fabric/UplinkPcRoles', 'UplinkPcRoles'),
        ('/fabric/FcUplinkPcRoles', 'FcUplinkPortChannels'),
        ('/fabric/FcoeUplinkPcRoles', 'FcoeUplinkPcRoles'),
        ('/fabric/AppliancePcRoles', 'AppliancePcRoles'),

        # Individual Ports
        ('/fabric/ServerRoles', 'ServerRoles'),
        ('/fabric/FcUplinkRoles', 'FcUplinkRoles'),
        ('/fabric/FcStorageRoles', 'FcStorageRoles'),
        ('/fabric/ApplianceRoles', 'ApplianceRoles'),
        ('/fabric/UplinkRoles', 'UplinkRoles'),
        ('/fabric/FcoeUplinkRoles', 'FcoeUplinkRoles'),

        # Pin Groups
        ('/fabric/LanPinGroups', 'LanPinGroups'),
        ('/fabric/SanPinGroups', 'SanPinGroups'),
    ]

    for api_path, result_key in resource_mappings:
        try:
            # Build query parameters
            query_params = {
                '$filter': f"PortPolicy.Moid eq '{port_policy_moid}'"
            }
            intersight.result['api_response'] = {}
            # Get the resources
            intersight.get_resource(
                resource_path=api_path,
                query_params=query_params,
                return_list=True
            )

            if intersight.result.get('api_response'):
                resources = intersight.result['api_response']

                # Special handling for PortModes to separate FC port mode and breakout ports
                if result_key == 'PortModes':
                    fc_port_modes = []
                    breakout_ports = []

                    for port_mode in resources:
                        # Make a deep copy to avoid modifying original data
                        port_mode_copy = port_mode.copy()

                        # Breakout ports have CustomMode specified
                        if port_mode_copy.get('CustomMode') != "FibreChannel":
                            # Change PortIdStart and PortIdEnd to PortId to align the main module.
                            if 'PortIdStart' in port_mode_copy:
                                port_mode_copy['PortId'] = port_mode_copy['PortIdStart']
                                del port_mode_copy['PortIdStart']
                            if 'PortIdEnd' in port_mode_copy:
                                del port_mode_copy['PortIdEnd']
                            breakout_ports.append(port_mode_copy)
                        else:
                            fc_port_modes.append(port_mode_copy)

                    secondary_resources['FcPortModes'] = fc_port_modes
                    secondary_resources['BreakoutPorts'] = breakout_ports
                else:
                    secondary_resources[result_key] = resources

        except Exception as e:
            # Log the error but continue with other resources
            intersight.module.warn(f"Failed to retrieve {result_key} from {api_path}: {str(e)}")

    return secondary_resources


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        name=dict(type='str'),
        organization=dict(type='str')
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)

    # Build query parameters using the standard method
    query_params = intersight.set_query_params()

    try:
        # Get Port Policies
        intersight.get_resource(
            resource_path='/fabric/PortPolicies',
            query_params=query_params,
            return_list=True
        )

        port_policies = intersight.result.get('api_response', [])

        # Ensure port_policies is a list
        if isinstance(port_policies, dict):
            port_policies = [port_policies]
        elif not isinstance(port_policies, list):
            port_policies = []

        # For each port policy, get all associated secondary resources
        for policy in port_policies:
            policy_moid = policy.get('Moid')
            if policy_moid:
                # Get all secondary resources for this policy
                secondary_resources = get_port_policy_secondary_resources(intersight, policy_moid)

                # Merge secondary resources directly into the policy data
                policy.update(secondary_resources)

        # Update the api_response with the enhanced policy data
        intersight.result['api_response'] = port_policies

        # Set count of policies found
        intersight.result['count'] = len(port_policies)

    except Exception as e:
        module.fail_json(msg=f"Failed to retrieve Port Policy information: {str(e)}")

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
