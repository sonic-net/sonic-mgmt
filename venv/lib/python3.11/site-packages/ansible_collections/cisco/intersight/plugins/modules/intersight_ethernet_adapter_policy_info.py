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
module: intersight_ethernet_adapter_policy_info
short_description: Gather information about Ethernet Adapter Policies in Cisco Intersight
description:
  - Gather information about Ethernet Adapter Policies in L(Cisco Intersight,https://intersight.com).
  - Information can be filtered by O(organization) and O(name).
  - If no filters are passed, all Ethernet Adapter Policies will be returned.
  - Returns comprehensive policy configuration including VXLAN, NVGRE, ARFS, PTP, RoCE, queue settings, and offload configurations.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization the Ethernet Adapter Policy belongs to.
      - Use 'default' for the default organization.
    type: str
  name:
    description:
      - The name of the Ethernet Adapter Policy to gather information from.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Fetch all Ethernet Adapter Policies
  cisco.intersight.intersight_ethernet_adapter_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
  register: all_adapter_policies

- name: Fetch Ethernet Adapter Policies from a specific organization
  cisco.intersight.intersight_ethernet_adapter_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
  register: engineering_adapter_policies

- name: Fetch a specific Ethernet Adapter Policy by name
  cisco.intersight.intersight_ethernet_adapter_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "high-performance-adapter-policy"
  register: specific_adapter_policy
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: list
  sample:
    [
      {
        "Moid": "6889f3e8f654d9f7013baae4",
        "ObjectType": "vnic.EthAdapterPolicy",
        "ClassId": "vnic.EthAdapterPolicy",
        "Name": "high-performance-adapter-policy",
        "Description": "High performance Ethernet adapter policy",
        "AdvancedFilter": true,
        "ArfsSettings": {
          "ClassId": "vnic.ArfsSettings",
          "ObjectType": "vnic.ArfsSettings",
          "Enabled": true
        },
        "CompletionQueueSettings": {
          "ClassId": "vnic.CompletionQueueSettings",
          "ObjectType": "vnic.CompletionQueueSettings",
          "Count": 12,
          "RingSize": 1
        },
        "EtherChannelPinningEnabled": false,
        "GeneveEnabled": false,
        "InterruptScaling": true,
        "InterruptSettings": {
          "ClassId": "vnic.EthInterruptSettings",
          "ObjectType": "vnic.EthInterruptSettings",
          "CoalescingTime": 125,
          "CoalescingType": "MIN",
          "Count": 16,
          "Mode": "MSIx"
        },
        "NvgreSettings": {
          "ClassId": "vnic.NvgreSettings",
          "ObjectType": "vnic.NvgreSettings",
          "Enabled": false
        },
        "PtpSettings": {
          "ClassId": "vnic.PtpSettings",
          "ObjectType": "vnic.PtpSettings",
          "Enabled": true
        },
        "RoceSettings": {
          "ClassId": "vnic.RoceSettings",
          "ObjectType": "vnic.RoceSettings",
          "ClassOfService": 5,
          "Enabled": true,
          "MemoryRegions": 131072,
          "QueuePairs": 256,
          "ResourceGroups": 2,
          "Version": 2
        },
        "RssHashSettings": {
          "ClassId": "vnic.RssHashSettings",
          "ObjectType": "vnic.RssHashSettings",
          "Ipv4Hash": true,
          "Ipv6ExtHash": false,
          "Ipv6Hash": true,
          "TcpIpv4Hash": true,
          "TcpIpv6ExtHash": false,
          "TcpIpv6Hash": true,
          "UdpIpv4Hash": false,
          "UdpIpv6Hash": false
        },
        "RssSettings": true,
        "RxQueueSettings": {
          "ClassId": "vnic.EthRxQueueSettings",
          "ObjectType": "vnic.EthRxQueueSettings",
          "Count": 8,
          "RingSize": 512
        },
        "TcpOffloadSettings": {
          "ClassId": "vnic.TcpOffloadSettings",
          "ObjectType": "vnic.TcpOffloadSettings",
          "LargeReceive": true,
          "LargeSend": true,
          "RxChecksum": true,
          "TxChecksum": true
        },
        "TxQueueSettings": {
          "ClassId": "vnic.EthTxQueueSettings",
          "ObjectType": "vnic.EthTxQueueSettings",
          "Count": 4,
          "RingSize": 256
        },
        "UplinkFailbackTimeout": 5,
        "VxlanSettings": {
          "ClassId": "vnic.VxlanSettings",
          "ObjectType": "vnic.VxlanSettings",
          "Enabled": true
        },
        "Organization": {
          "ObjectType": "organization.Organization",
          "ClassId": "mo.MoRef",
          "Moid": "675450ee69726530014753e2",
          "link": "https://us-east-1.intersight.com/api/v1/organization/Organizations/675450ee69726530014753e2"
        },
        "Tags": [
          {
            "Key": "Environment",
            "Value": "Production"
          },
          {
            "Key": "Feature",
            "Value": "HighPerformance"
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

    # Resource path used to fetch info
    resource_path = '/vnic/EthAdapterPolicies'

    query_params = intersight.set_query_params()

    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
