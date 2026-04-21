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
module: intersight_server_pool_qualification_policy_info
short_description: Gather information about Server Pool Qualification Policies in Cisco Intersight
description:
  - Gather information about Server Pool Qualification Policies in L(Cisco Intersight,https://intersight.com).
  - Information can be filtered by O(organization) and O(name).
  - If no filters are passed, all Server Pool Qualification Policies will be returned.
  - Server Pool Qualification Policies define conditions to qualify servers for resource pools based on hardware and configuration attributes.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization the Server Pool Qualification Policy belongs to.
    type: str
  name:
    description:
      - The name of the Server Pool Qualification Policy to gather information from.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Fetch a specific Server Pool Qualification Policy by name
  cisco.intersight.intersight_server_pool_qualification_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "ServerPool-Qual-Policy-01"

- name: Fetch all Server Pool Qualification Policies in a specific Organization
  cisco.intersight.intersight_server_pool_qualification_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Production"

- name: Fetch all Server Pool Qualification Policies
  cisco.intersight.intersight_server_pool_qualification_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"

- name: Register Server Pool Qualification Policy info and display
  cisco.intersight.intersight_server_pool_qualification_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "ServerPool-Comprehensive-Policy"
  register: policy_info

- name: Display the policy qualifiers
  ansible.builtin.debug:
    var: policy_info.api_response[0].Qualifiers
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": [
    {
        "Name": "ServerPool-Qual-Policy-01",
        "ObjectType": "resourcepool.QualificationPolicy",
        "Organization": {
            "Moid": "675450ee69726530014753e2",
            "ObjectType": "organization.Organization"
        },
        "Qualifiers": [
            {
                "FabricInterConnectPids": ["UCS-FI-6454", "UCS-FI-64108"],
                "DomainNames": ["AC08-6454"],
                "ObjectType": "resource.DomainQualifier"
            },
            {
                "RackIdRange": [{"MinValue": 2, "MaxValue": 4}],
                "Pids": ["UCSC-C245-M8SX", "UCSC-C220-M8S"],
                "AssetTags": ["production"],
                "ObjectType": "resource.RackServerQualifier"
            },
            {
                "MemoryCapacityRange": {"MinValue": 64, "MaxValue": 512},
                "ObjectType": "resource.MemoryQualifier"
            },
            {
                "GpuEvaluationType": "ServerWithoutGpu",
                "ObjectType": "resource.GpuQualifier"
            },
            {
                "CpuCoresRange": {"MinValue": 16, "MaxValue": 64},
                "Vendor": "Intel(R) Corporation",
                "ObjectType": "resource.ProcessorQualifier"
            }
        ]
    },
    {
        "Name": "ServerPool-GPU-Policy",
        "ObjectType": "resourcepool.QualificationPolicy",
        "Description": "Policy for servers with NVIDIA GPUs",
        "Qualifiers": [
            {
                "GpuEvaluationType": "ServerWithGpu",
                "GpuCountRange": {"MinValue": 2, "MaxValue": 4},
                "Vendor": "NVIDIA",
                "ObjectType": "resource.GpuQualifier"
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
    resource_path = '/resourcepool/QualificationPolicies'

    query_params = intersight.set_query_params()

    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
