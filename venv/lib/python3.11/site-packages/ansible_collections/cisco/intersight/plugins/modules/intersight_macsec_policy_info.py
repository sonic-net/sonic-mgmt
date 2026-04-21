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
module: intersight_macsec_policy_info
short_description: Gather information about MACsec Policies in Cisco Intersight
description:
  - Gather information about MACsec Policies in L(Cisco Intersight,https://intersight.com).
  - Information can be filtered by O(organization) and O(name).
  - If no filters are passed, all MACsec Policies will be returned.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization the MACsec Policy belongs to.
    type: str
  name:
    description:
      - The name of the MACsec Policy to gather information from.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Fetch a specific MACsec Policy by name
  cisco.intersight.intersight_macsec_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "macsec-policy-01"

- name: Fetch all MACsec Policies in a specific Organization
  cisco.intersight.intersight_macsec_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"

- name: Fetch all MACsec Policies
  cisco.intersight.intersight_macsec_policy_info:
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
        "Name": "macsec-policy-01",
        "ObjectType": "fabric.MacsecPolicy",
        "Description": "MACsec policy with primary keychain",
        "CipherSuite": "GCM-AES-XPN-256",
        "ConfidentialityOffset": "CONF-OFFSET-0",
        "SecurityPolicy": "Should-secure",
        "KeyServerPriority": 16,
        "SakExpiryTime": 0,
        "ReplayWindowSize": 148809600,
        "IncludeIcvIndicator": false,
        "MacSecEaPol": {
            "EaPolMacAddress": "0180.C200.0003",
            "EaPolEthertype": "0x888e"
        },
        "PrimaryKeyChain": {
            "Name": "primary-keychain",
            "SecKeys": [
                {
                    "Id": "1234",
                    "CryptographicAlgorithm": "AES_256_CMAC",
                    "KeyType": "Type-6",
                    "SendLifetimeUnlimited": true,
                    "SendLifetimeInfinite": false,
                    "IsOctetStringSet": true
                }
            ]
        },
        "FallbackKeyChain": {
            "Name": "",
            "SecKeys": null
        },
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Production"
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

    resource_path = '/fabric/MacSecPolicies'
    query_params = intersight.set_query_params()

    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )
    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
