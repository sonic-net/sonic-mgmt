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
module: intersight_iscsi_adapter_policy
short_description: Manage iSCSI Adapter Policies for Cisco Intersight
description:
  - Create, update, and delete iSCSI Adapter Policies on Cisco Intersight.
  - iSCSI adapter policies configure timeout and retry settings for iSCSI adapters.
  - These policies control TCP connection timeout, DHCP timeout, and LUN busy retry behavior.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/vnic/IscsiAdapterPolicies/get/).
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
      - The name assigned to the iSCSI Adapter Policy.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the iSCSI Adapter Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  connection_time_out:
    description:
      - The number of seconds to wait until Cisco UCS assumes that the initial login has failed and the iSCSI adapter is unavailable.
      - TCP connection timeout value.
      - Valid range is 0 to 255 seconds.
    type: int
    default: 15
  dhcp_timeout:
    description:
      - The number of seconds to wait before the initiator assumes that the DHCP server is unavailable.
      - Valid range is 60 to 300 seconds.
    type: int
    default: 60
  lun_busy_retry_count:
    description:
      - The number of times to retry the connection in case of a failure during iSCSI LUN discovery.
      - Valid range is 0 to 60 retries.
    type: int
    default: 15
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create iSCSI Adapter Policy with default settings
  cisco.intersight.intersight_iscsi_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-adapter-default"
    description: "iSCSI adapter policy with default timeout values"
    state: present

- name: Create iSCSI Adapter Policy with custom timeout settings
  cisco.intersight.intersight_iscsi_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-adapter-custom"
    description: "iSCSI adapter policy with custom timeouts"
    connection_time_out: 30
    dhcp_timeout: 120
    lun_busy_retry_count: 30
    tags:
      - Key: Environment
        Value: Production
    state: present

- name: Create iSCSI Adapter Policy with extended timeouts
  cisco.intersight.intersight_iscsi_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
    name: "iscsi-adapter-extended"
    description: "iSCSI adapter policy with extended timeout values"
    connection_time_out: 60
    dhcp_timeout: 300
    lun_busy_retry_count: 60
    state: present

- name: Create iSCSI Adapter Policy with minimal timeouts
  cisco.intersight.intersight_iscsi_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-adapter-minimal"
    description: "iSCSI adapter policy with minimal timeout values"
    connection_time_out: 0
    dhcp_timeout: 60
    lun_busy_retry_count: 0
    state: present

- name: Update iSCSI Adapter Policy description
  cisco.intersight.intersight_iscsi_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-adapter-default"
    description: "Updated iSCSI adapter policy description"
    state: present

- name: Delete iSCSI Adapter Policy
  cisco.intersight.intersight_iscsi_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "iscsi-adapter-default"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "iscsi-adapter-custom",
        "ObjectType": "vnic.IscsiAdapterPolicy",
        "ConnectionTimeOut": 30,
        "DhcpTimeout": 120,
        "LunBusyRetryCount": 30,
        "Moid": "1234567890abcdef12345678",
        "Description": "iSCSI adapter policy with custom timeouts",
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


def validate_parameters(module):
    """
    Validate module parameters for iSCSI adapter policy configuration.
    """
    if module.params['state'] != 'present':
        return
    # Validate connection_time_out range (0-255)
    connection_time_out = module.params.get('connection_time_out')
    if connection_time_out is not None and (connection_time_out < 0 or connection_time_out > 255):
        module.fail_json(msg="Parameter 'connection_time_out' must be between 0 and 255 seconds")
    # Validate dhcp_timeout range (60-300)
    dhcp_timeout = module.params.get('dhcp_timeout')
    if dhcp_timeout is not None and (dhcp_timeout < 60 or dhcp_timeout > 300):
        module.fail_json(msg="Parameter 'dhcp_timeout' must be between 60 and 300 seconds")
    # Validate lun_busy_retry_count range (0-60)
    lun_busy_retry_count = module.params.get('lun_busy_retry_count')
    if lun_busy_retry_count is not None and (lun_busy_retry_count < 0 or lun_busy_retry_count > 60):
        module.fail_json(msg="Parameter 'lun_busy_retry_count' must be between 0 and 60 retries")


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        connection_time_out=dict(type='int', default=15),
        dhcp_timeout=dict(type='int', default=60),
        lun_busy_retry_count=dict(type='int', default=15),
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )
    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''
    # Validate module parameters
    validate_parameters(module)
    # Resource path used to configure policy
    resource_path = '/vnic/IscsiAdapterPolicies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': module.params['organization'],
        },
        'Name': module.params['name'],
    }
    if module.params['state'] == 'present':
        intersight.api_body['ConnectionTimeOut'] = module.params['connection_time_out']
        intersight.api_body['DhcpTimeout'] = module.params['dhcp_timeout']
        intersight.api_body['LunBusyRetryCount'] = module.params['lun_busy_retry_count']
        intersight.set_tags_and_description()
    intersight.configure_policy_or_profile(resource_path=resource_path)
    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
