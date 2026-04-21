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
module: intersight_lan_connectivity_policy_info
short_description: Gather information about LAN Connectivity Policies in Cisco Intersight
description:
  - Gather information about LAN Connectivity Policies in L(Cisco Intersight,https://intersight.com).
  - Information can be filtered by O(organization) and O(name).
  - If no filters are passed, all LAN Connectivity Policies will be returned.
  - Each policy includes its associated vNICs as part of the response.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization the LAN Connectivity Policy belongs to.
    type: str
  name:
    description:
      - The name of the LAN Connectivity Policy to gather information from.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Fetch a specific LAN Connectivity Policy by name
  cisco.intersight.intersight_lan_connectivity_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "datacenter-lan-policy"

- name: Fetch all LAN Connectivity Policies in a specific Organization
  cisco.intersight.intersight_lan_connectivity_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"

- name: Fetch all LAN Connectivity Policies
  cisco.intersight.intersight_lan_connectivity_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": [
    {
        "Name": "datacenter-lan-policy",
        "ObjectType": "vnic.LanConnectivityPolicy",
        "TargetPlatform": "Standalone",
        "AzureQosEnabled": false,
        "IqnAllocationType": "None",
        "PlacementMode": "custom",
        "StaticIqnName": "",
        "vNICs": [
            {
                "Name": "eth0",
                "ObjectType": "vnic.EthIf",
                "Order": 0,
                "Placement": {
                    "Id": "1",
                    "Uplink": 0,
                    "PciLink": 0
                },
                "Cdn": {
                    "Source": "vnic"
                },
                "EthNetworkPolicy": "6898934a010c5abf01f88125",
                "EthQosPolicy": "6898934a010c5abf01f88126",
                "EthAdapterPolicy": "68989358010c5abf01f89569"
            },
            {
                "Name": "eth1-usnic",
                "ObjectType": "vnic.EthIf",
                "Order": 1,
                "Placement": {
                    "Id": "2",
                    "Uplink": 0,
                    "PciLink": 0
                },
                "Cdn": {
                    "Source": "user",
                    "Value": "custom-eth1"
                },
                "UsnicSettings": {
                    "Count": 15,
                    "Cos": 3,
                    "UsnicAdapterPolicy": "68989358010c5abf01f89569"
                },
                "EthNetworkPolicy": "6898934a010c5abf01f88125",
                "EthQosPolicy": "6898934a010c5abf01f88126",
                "EthAdapterPolicy": "68989358010c5abf01f89569"
            }
        ],
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Production"
            }
        ]
    },
    {
        "Name": "fi-attached-policy",
        "ObjectType": "vnic.LanConnectivityPolicy",
        "TargetPlatform": "FIAttached",
        "AzureQosEnabled": true,
        "IqnAllocationType": "Pool",
        "PlacementMode": "auto",
        "IqnPool": "6898a32d6f62693301a90d5c",
        "vNICs": [
            {
                "Name": "vnic-fi-attached",
                "ObjectType": "vnic.EthIf",
                "MacAddressType": "POOL",
                "MacPool": "6898a2fc6962753101f5bb41",
                "Order": 0,
                "Placement": {
                    "SwitchId": "A",
                    "AutoSlotId": true,
                    "AutoPciLink": true
                },
                "Cdn": {
                    "Source": "vnic"
                },
                "FailoverEnabled": false,
                "FabricEthNetworkGroupPolicy": [
                    "6898a32d6f62693301a90d5c"
                ],
                "FabricEthNetworkControlPolicy": "6898a3426f62693301a92527",
                "EthQosPolicy": "6898934a010c5abf01f88126",
                "EthAdapterPolicy": "68989358010c5abf01f89569"
            }
        ],
        "Tags": [
            {
                "Key": "Site",
                "Value": "Datacenter1"
            }
        ]
    }
  ]
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        organization=dict(type='str'),
        name=dict(type='str')
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    resource_path = '/vnic/LanConnectivityPolicies'

    query_params = intersight.set_query_params()

    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    # Fetch vNICs for each LAN connectivity policy
    lan_policies = intersight.result['api_response']
    if isinstance(lan_policies, list):
        for policy in lan_policies:
            if policy.get('Moid'):
                # Fetch vNICs for this policy using LanConnectivityPolicy.Moid filter
                vnics_query_params = {
                    '$filter': f"LanConnectivityPolicy.Moid eq '{policy['Moid']}'"
                }

                # Create a temporary intersight instance for vNICs query
                temp_intersight = IntersightModule(module)
                temp_intersight.get_resource(
                    resource_path='/vnic/EthIfs',
                    query_params=vnics_query_params,
                    return_list=True
                )

                # Add vNICs to the policy
                policy['vNICs'] = temp_intersight.result.get('api_response', [])
    elif isinstance(lan_policies, dict) and lan_policies.get('Moid'):
        # Single policy case
        vnics_query_params = {
            '$filter': f"LanConnectivityPolicy.Moid eq '{lan_policies['Moid']}'"
        }

        # Create a temporary intersight instance for vNICs query
        temp_intersight = IntersightModule(module)
        temp_intersight.get_resource(
            resource_path='/vnic/EthIfs',
            query_params=vnics_query_params,
            return_list=True
        )

        # Add vNICs to the policy
        lan_policies['vNICs'] = temp_intersight.result.get('api_response', [])

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
