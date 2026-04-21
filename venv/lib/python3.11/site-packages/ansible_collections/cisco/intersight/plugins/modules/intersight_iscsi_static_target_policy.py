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
module: intersight_iscsi_static_target_policy
short_description: Manage iSCSI Static Target Policies for Cisco Intersight
description:
  - Create, update, and delete iSCSI Static Target Policies on Cisco Intersight.
  - iSCSI static target policy enables you to configure the iSCSI targets for iSCSI vNIC interfaces.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/vnic/IscsiStaticTargetPolicy/get/).
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
      - Policies created within a Custom Organization are applicable only to devices in the same Organization.
      - Use 'default' for the default organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the iSCSI Static Target Policy.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the iSCSI Static Target Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  target_name:
    description:
      - Qualified Name (IQN) or Extended Unique Identifier (EUI) name of the iSCSI target.
      - This is the name that uniquely identifies the target in the iSCSI network.
      - Example IQN format - iqn.1991-05.com.microsoft:winclient1
      - Example EUI format - eui.02004567A425678D
      - Required when state is present.
    type: str
  port:
    description:
      - The port associated with the iSCSI target.
      - Valid range is 1-65535.
      - Common iSCSI port is 3260.
      - Required when state is present.
    type: int
  lun_id:
    description:
      - The Logical Unit Number (LUN) Identifier for the iSCSI target.
      - Valid values are 0 or greater (typically 0-255).
      - Required when state is present.
    type: int
  ip_protocol:
    description:
      - Type of the IP address requested for iSCSI vNIC.
      - IPv4 or IPv6.
      - Required when state is present.
    type: str
    choices: ['IPv4', 'IPv6']
  ipv4_address:
    description:
      - The IPv4 address assigned to the iSCSI target.
      - Required when ip_protocol is IPv4 and state is present.
    type: str
  ipv6_address:
    description:
      - The IPv6 address assigned to the iSCSI target.
      - Required when ip_protocol is IPv6 and state is present.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create an iSCSI Static Target Policy with IPv4
  cisco.intersight.intersight_iscsi_static_target_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-static-target-policy-01"
    description: "iSCSI static target policy for production servers"
    target_name: "iqn.1991-05.com.microsoft:winclient1"
    port: 3260
    lun_id: 0
    ip_protocol: "IPv4"
    ipv4_address: "192.168.10.100"
    tags:
      - Key: "Environment"
        Value: "Production"
      - Key: "Owner"
        Value: "Storage-Team"
    state: present

- name: Create an iSCSI Static Target Policy with IPv6
  cisco.intersight.intersight_iscsi_static_target_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-static-target-policy-ipv6"
    description: "iSCSI static target policy with IPv6 addressing"
    target_name: "iqn.2001-04.com.example:storage.disk2"
    port: 3260
    lun_id: 1
    ip_protocol: "IPv6"
    ipv6_address: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    state: present

- name: Update an existing iSCSI Static Target Policy
  cisco.intersight.intersight_iscsi_static_target_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "iscsi-static-target-policy-01"
    description: "Updated description for iSCSI target policy"
    target_name: "iqn.1991-05.com.microsoft:winclient1"
    port: 3260
    lun_id: 2
    ip_protocol: "IPv4"
    ipv4_address: "192.168.10.101"
    state: present

- name: Delete an iSCSI Static Target Policy
  cisco.intersight.intersight_iscsi_static_target_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "iscsi-static-target-policy-01"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "iscsi-static-target-policy-01",
        "ObjectType": "vnic.IscsiStaticTargetPolicy",
        "Moid": "1234567890abcdef12345678",
        "TargetName": "iqn.1991-05.com.microsoft:winclient1",
        "Port": 3260,
        "Lun": {
            "LunId": 0
        },
        "IscsiIpType": "IPv4",
        "IpAddress": "192.168.10.100",
        "Organization": {
            "Moid": "abcdef1234567890abcdef12",
            "ObjectType": "organization.Organization"
        },
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


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        target_name=dict(type='str'),
        port=dict(type='int'),
        lun_id=dict(type='int'),
        ip_protocol=dict(type='str', choices=['IPv4', 'IPv6']),
        ipv4_address=dict(type='str'),
        ipv6_address=dict(type='str')
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'present', ['target_name', 'port', 'lun_id', 'ip_protocol']],
            ['ip_protocol', 'IPv4', ['ipv4_address']],
            ['ip_protocol', 'IPv6', ['ipv6_address']]
        ],
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Validate port range (1-65535)
    if module.params['state'] == 'present' and module.params.get('port'):
        port = module.params['port']
        if port < 1 or port > 65535:
            module.fail_json(msg=f"Port must be between 1 and 65535. Provided value: {port}")

    # Validate LUN ID (>= 0)
    if module.params['state'] == 'present' and module.params.get('lun_id') is not None:
        lun_id = module.params['lun_id']
        if lun_id < 0:
            module.fail_json(msg=f"LUN ID must be 0 or greater. Provided value: {lun_id}")

    # Resource path used to configure policy
    resource_path = '/vnic/IscsiStaticTargetPolicies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    # Add fields for present state
    if intersight.module.params['state'] == 'present':
        intersight.api_body['TargetName'] = intersight.module.params['target_name']
        intersight.api_body['Port'] = intersight.module.params['port']
        intersight.api_body['Lun'] = {
            'LunId': intersight.module.params['lun_id']
        }
        intersight.api_body['IscsiIpType'] = intersight.module.params['ip_protocol']

        # Add IP address based on protocol type
        if intersight.module.params['ip_protocol'] == 'IPv4':
            intersight.api_body['IpAddress'] = intersight.module.params['ipv4_address']
        elif intersight.module.params['ip_protocol'] == 'IPv6':
            intersight.api_body['IpAddress'] = intersight.module.params['ipv6_address']

        intersight.set_tags_and_description()

    # Configure the policy
    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
