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
module: intersight_link_aggregation_policy
short_description: Link Aggregation Policy configuration for Cisco Intersight
description:
  - Manages Link Aggregation Policy configuration on Cisco Intersight.
  - A policy to configure LACP (Link Aggregation Control Protocol) settings for link aggregation on Cisco Intersight managed fabric interconnects.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/fabric/LinkAggregationPolicies/get/).
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
      - The name assigned to the Link Aggregation Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Link Aggregation Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  suspend_individual:
    description:
      - Flag tells the switch whether to suspend the port if it didn't receive LACP PDU.
      - If enabled, the switch will suspend the port in the port channel if LACP PDUs are not received.
    type: bool
    default: false
  lacp_rate:
    description:
      - Flag used to indicate whether LACP PDUs are to be sent 'fast', i.e., every 1 second.
      - C(normal) - LACP PDUs are sent every 30 seconds.
      - C(fast) - LACP PDUs are sent every 1 second.
    type: str
    choices: [normal, fast]
    default: normal
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a Link Aggregation Policy with default settings
  cisco.intersight.intersight_link_aggregation_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "LinkAgg-Policy-01"
    description: "Link aggregation policy with default LACP settings"
    tags:
      - Key: "Site"
        Value: "DataCenter-A"
    state: present

- name: Create a Link Aggregation Policy with fast LACP rate
  cisco.intersight.intersight_link_aggregation_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "LinkAgg-Fast-Policy"
    description: "Link aggregation policy with fast LACP rate"
    lacp_rate: fast
    suspend_individual: true
    state: present

- name: Create a Link Aggregation Policy with normal LACP rate and suspend individual disabled
  cisco.intersight.intersight_link_aggregation_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "LinkAgg-Normal-Policy"
    lacp_rate: normal
    suspend_individual: false
    state: present

- name: Update a Link Aggregation Policy
  cisco.intersight.intersight_link_aggregation_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "LinkAgg-Policy-01"
    description: "Updated link aggregation policy"
    lacp_rate: fast
    suspend_individual: true
    state: present

- name: Delete a Link Aggregation Policy
  cisco.intersight.intersight_link_aggregation_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "LinkAgg-Policy-01"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "LinkAgg-Policy-01",
        "ObjectType": "fabric.LinkAggregationPolicy",
        "SuspendIndividual": false,
        "LacpRate": "normal",
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
        suspend_individual=dict(type='bool', default=False),
        lacp_rate=dict(type='str', choices=['normal', 'fast'], default='normal')
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/fabric/LinkAggregationPolicies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()
        intersight.api_body['SuspendIndividual'] = intersight.module.params['suspend_individual']
        intersight.api_body['LacpRate'] = intersight.module.params['lacp_rate']

    # Configure the policy
    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
