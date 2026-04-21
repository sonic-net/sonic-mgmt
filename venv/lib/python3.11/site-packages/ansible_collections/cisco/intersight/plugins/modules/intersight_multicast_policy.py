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
module: intersight_multicast_policy
short_description: Multicast Policy configuration for Cisco Intersight
description:
  - Manages Multicast Policy configuration on Cisco Intersight.
  - A policy to configure multicast settings including IGMP snooping and querier on Cisco Intersight managed switches.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/fabric/MulticastPolicy/get/).
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
      - The name assigned to the Multicast Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Multicast Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  querier_state:
    description:
      - Administrative state of the IGMP Querier for this VLAN.
    type: str
    choices: ['Enabled', 'Disabled']
    default: 'Disabled'
  snooping_state:
    description:
      - Administrative state of the IGMP Snooping for this VLAN.
    type: str
    choices: ['Enabled', 'Disabled']
    default: 'Enabled'
  querier_ip_address:
    description:
      - Used to define the IGMP Querier IP address.
      - Must be a valid IPv4 address.
    type: str
  querier_ip_address_peer:
    description:
      - Used to define the IGMP Querier IP address of the peer switch.
      - This is optional and only applicable when querier_state is set to 'Enabled'.
      - Must be a valid IPv4 address.
    type: str
  src_ip_proxy:
    description:
      - Administrative state of the IGMP source IP proxy for this VLAN.
    type: str
    choices: ['Enabled', 'Disabled']
    default: 'Enabled'
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a Multicast Policy with querier enabled
  cisco.intersight.intersight_multicast_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "Multicast-Policy-Querier"
    description: "Multicast policy with IGMP querier enabled"
    tags:
      - Key: "Site"
        Value: "DataCenter-A"
    querier_state: "Enabled"
    snooping_state: "Enabled"
    querier_ip_address: "192.168.1.1"
    querier_ip_address_peer: "192.168.1.2"
    src_ip_proxy: "Enabled"
    state: present

- name: Create a basic Multicast Policy with defaults
  cisco.intersight.intersight_multicast_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Basic-Multicast-Policy"
    description: "Basic multicast policy with snooping enabled"
    querier_state: "Disabled"
    snooping_state: "Enabled"
    src_ip_proxy: "Enabled"
    state: present

- name: Create a Multicast Policy with only snooping
  cisco.intersight.intersight_multicast_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Snooping-Only-Policy"
    description: "Multicast policy with only snooping enabled"
    querier_state: "Disabled"
    snooping_state: "Enabled"
    src_ip_proxy: "Disabled"
    state: present

- name: Delete a Multicast Policy
  cisco.intersight.intersight_multicast_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Multicast-Policy-Querier"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "test_multicast_policy",
        "ObjectType": "fabric.MulticastPolicy",
        "QuerierState": "Enabled",
        "SnoopingState": "Enabled",
        "QuerierIpAddress": "192.168.1.1",
        "QuerierIpAddressPeer": "192.168.1.2",
        "SrcIpProxy": "Enabled",
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
        querier_state=dict(type='str', choices=['Enabled', 'Disabled'], default='Disabled'),
        snooping_state=dict(type='str', choices=['Enabled', 'Disabled'], default='Enabled'),
        querier_ip_address=dict(type='str'),
        querier_ip_address_peer=dict(type='str'),
        src_ip_proxy=dict(type='str', choices=['Enabled', 'Disabled'], default='Enabled')
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
        required_if=[
            ['querier_state', 'Enabled', ['querier_ip_address']],
        ]
    )

    # Validate that snooping cannot be disabled with querier enabled
    if (module.params['snooping_state'] == 'Disabled' and module.params['querier_state'] == 'Enabled'):
        module.fail_json(
            msg="Invalid configuration: Multicast policy cannot have Snooping Disabled and Querier Enabled simultaneously."
        )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/fabric/MulticastPolicies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
        'QuerierState': intersight.module.params['querier_state'],
        'SnoopingState': intersight.module.params['snooping_state'],
        'SrcIpProxy': intersight.module.params['src_ip_proxy'],
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Add querier IP address if querier is enabled
        if intersight.module.params['querier_state'] == 'Enabled':
            intersight.api_body['QuerierIpAddress'] = intersight.module.params['querier_ip_address']

            # Add peer IP address if provided
            if intersight.module.params['querier_ip_address_peer']:
                intersight.api_body['QuerierIpAddressPeer'] = intersight.module.params['querier_ip_address_peer']

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
