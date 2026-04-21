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
module: intersight_ipmi_over_lan_policy
short_description: IPMI over LAN Policy configuration for Cisco Intersight
description:
  - Manages IPMI over LAN Policy configuration on Cisco Intersight.
  - A policy to configure the IPMI over LAN settings on Cisco Intersight managed servers.
  - IPMI over LAN allows management of servers using the IPMI protocol over Ethernet networks.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/ipmioverlan/Policy/get/).
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
      - The name assigned to the IPMI over LAN Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the IPMI over LAN Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  enabled:
    description:
      - State of the IPMI Over LAN service on the endpoint.
      - Enable or disable IPMI over LAN functionality on the server.
    type: bool
    default: true
  privilege:
    description:
      - The highest privilege level that can be assigned to an IPMI session on a server.
      - This configuration is supported by all Standalone C-Series servers.
      - FI-attached C-Series servers with firmware at minimum of 4.2.3a support this configuration.
      - B/X-Series servers with firmware at minimum of 5.1.0.x support this configuration.
      - Privilege level 'user' is not supported for B/X-Series servers.
    type: str
    choices: ['admin', 'user', 'read-only']
    default: 'admin'
  encryption_key:
    description:
      - The encryption key to use for IPMI communication.
      - It should have an even number of hexadecimal characters and not exceed 40 characters.
      - Use "00" to disable encryption key use.
      - This configuration is supported by all Standalone C-Series servers.
      - FI-attached C-Series servers with firmware at minimum of 4.2.3a support this configuration.
      - B/X-Series servers with firmware at minimum of 5.1.0.x support this configuration.
      - IPMI commands using this key should append zeroes to the key to achieve a length of 40 characters.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create IPMI over LAN Policy with encryption enabled
  cisco.intersight.intersight_ipmi_over_lan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "IPMI-Policy-Encrypted"
    description: "IPMI over LAN policy with encryption"
    enabled: true
    privilege: "admin"
    encryption_key: "AB2134AC"
    tags:
      - Key: "Site"
        Value: "DataCenter-A"
    state: present

- name: Create IPMI over LAN Policy with encryption disabled
  cisco.intersight.intersight_ipmi_over_lan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "IPMI-Policy-No-Encryption"
    description: "IPMI over LAN policy without encryption"
    enabled: true
    privilege: "operator"
    encryption_key: "00"
    state: present

- name: Create disabled IPMI over LAN Policy
  cisco.intersight.intersight_ipmi_over_lan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "IPMI-Policy-Disabled"
    description: "Disabled IPMI over LAN policy"
    enabled: false
    state: present

- name: Delete IPMI over LAN Policy
  cisco.intersight.intersight_ipmi_over_lan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "IPMI-Policy-Encrypted"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "IPMI-Policy-Encrypted",
        "ObjectType": "ipmioverlan.Policy",
        "Enabled": true,
        "Privilege": "admin",
        "IsEncryptionKeySet": true,
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


def validate_encryption_key(module):
    """Validate the encryption key format"""
    encryption_key = module.params.get('encryption_key')
    if encryption_key and encryption_key != "00":
        # Check if it's a valid hex string
        try:
            int(encryption_key, 16)
        except ValueError:
            module.fail_json(msg="encryption_key must contain only hexadecimal characters")

        # Check if it has even number of characters
        if len(encryption_key) % 2 != 0:
            module.fail_json(msg="encryption_key must have an even number of characters")

        # Check if it doesn't exceed 40 characters
        if len(encryption_key) > 40:
            module.fail_json(msg="encryption_key must not exceed 40 characters")


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        enabled=dict(type='bool', default=True),
        privilege=dict(
            type='str',
            choices=['admin', 'user', 'read-only'],
            default='admin'
        ),
        encryption_key=dict(type='str', no_log=True)
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    # Validate encryption key format
    validate_encryption_key(module)

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/ipmioverlan/Policies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    # In case state is absent we don't want to populate the api_body with any values
    if intersight.module.params['state'] == 'present':
        intersight.api_body['Enabled'] = intersight.module.params['enabled']
        if intersight.module.params['enabled']:
            intersight.api_body['Privilege'] = intersight.module.params['privilege']
            # Add encryption key if provided
            if intersight.module.params.get('encryption_key'):
                intersight.api_body['EncryptionKey'] = intersight.module.params['encryption_key']

        intersight.set_tags_and_description()

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
