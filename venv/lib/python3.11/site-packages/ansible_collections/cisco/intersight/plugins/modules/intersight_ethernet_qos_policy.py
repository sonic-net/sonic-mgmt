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
module: intersight_ethernet_qos_policy
short_description: Ethernet QoS Policy configuration for Cisco Intersight
description:
  - Manages Ethernet QoS Policy configuration on Cisco Intersight.
  - A policy to configure Quality of Service settings for Ethernet virtual interfaces on Cisco Intersight managed servers.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/vnic/EthQosPolicy/get/).
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
      - The name assigned to the Ethernet QoS Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Ethernet QoS Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  mtu:
    description:
      - The Maximum Transmission Unit (MTU) or packet size that the virtual interface accepts.
      - The acceptable range is 1500-9000.
    type: int
    default: 1500
  cos:
    description:
      - Class of Service to be associated to the traffic on the virtual interface.
      - The acceptable range is 0-6.
    type: int
    default: 0
  priority:
    description:
      - The priority matching the System QoS specified in the fabric profile.
    type: str
    choices: ['Best Effort', 'FC', 'Platinum', 'Gold', 'Silver', 'Bronze']
    default: 'Best Effort'
  trust_host_cos:
    description:
      - Enables usage of the Class of Service provided by the operating system.
    type: bool
    default: false
  rate_limit:
    description:
      - The value in Mbps (0-10G/40G/100G depending on Adapter Model) to use for limiting the data rate on the virtual interface.
      - The range is between 0 and 100000.
    type: int
    default: 0
  burst:
    description:
      - The burst traffic, in bytes, allowed on the vNIC.
      - The range is between 1 to 1000000.
    type: int
    default: 10240
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create an Ethernet QoS Policy with default settings
  cisco.intersight.intersight_ethernet_qos_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "default-qos-policy"
    description: "Default Ethernet QoS policy"
    state: present

- name: Create an Ethernet QoS Policy with Platinum priority and trust host CoS
  cisco.intersight.intersight_ethernet_qos_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "platinum-qos-policy"
    description: "High priority Ethernet QoS policy"
    tags:
      - Key: "Environment"
        Value: "Production"
    mtu: 9000
    cos: 5
    priority: "Platinum"
    trust_host_cos: true
    rate_limit: 10000
    burst: 100000
    state: present

- name: Create an Ethernet QoS Policy with custom settings
  cisco.intersight.intersight_ethernet_qos_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "custom-qos-policy"
    description: "Custom Ethernet QoS policy for specific workload"
    mtu: 1500
    cos: 3
    priority: "Gold"
    trust_host_cos: false
    rate_limit: 5000
    burst: 50000
    state: present

- name: Delete an Ethernet QoS Policy
  cisco.intersight.intersight_ethernet_qos_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "custom-qos-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "platinum-qos-policy",
        "ObjectType": "vnic.EthQosPolicy",
        "Mtu": 9000,
        "Cos": 5,
        "Priority": "Platinum",
        "TrustHostCos": true,
        "RateLimit": 10000,
        "Burst": 100000,
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Production"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def validate_input(module):
    """Validate input parameters"""
    mtu = module.params.get('mtu')
    if mtu is not None and (mtu < 1500 or mtu > 9000):
        module.fail_json(msg='MTU must be between 1500 and 9000')

    cos = module.params.get('cos')
    if cos is not None and (cos < 0 or cos > 6):
        module.fail_json(msg='CoS must be between 0 and 6')

    rate_limit = module.params.get('rate_limit')
    if rate_limit is not None and (rate_limit < 0 or rate_limit > 100000):
        module.fail_json(msg='Rate limit must be between 0 and 100000')

    burst = module.params.get('burst')
    if burst is not None and (burst < 1 or burst > 1000000):
        module.fail_json(msg='Burst must be between 1 and 1000000')


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        mtu=dict(type='int', default=1500),
        cos=dict(type='int', default=0),
        priority=dict(
            type='str',
            choices=['Best Effort', 'FC', 'Platinum', 'Gold', 'Silver', 'Bronze'],
            default='Best Effort'
        ),
        trust_host_cos=dict(type='bool', default=False),
        rate_limit=dict(type='int', default=0),
        burst=dict(type='int', default=10240),
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    validate_input(module)
    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/vnic/EthQosPolicies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if module.params['state'] == 'present':
        intersight.set_tags_and_description()

        intersight.api_body.update({
            'Mtu': module.params['mtu'],
            'Cos': module.params['cos'],
            'Priority': module.params['priority'],
            'TrustHostCos': module.params['trust_host_cos'],
            'RateLimit': module.params['rate_limit'],
            'Burst': module.params['burst']
        })

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
