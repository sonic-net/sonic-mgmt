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
module: intersight_fibre_channel_qos_policy
short_description: Manage Fibre Channel QoS Policies for Cisco Intersight
description:
  - Create, update, and delete Fibre Channel QoS Policies on Cisco Intersight.
  - Fibre Channel QoS policies configure Quality of Service settings for Fibre Channel virtual interfaces.
  - These policies control bandwidth rate limits, maximum data field size, class of service, and burst traffic.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/vnic/FcQosPolicies/get/).
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
      - The name assigned to the Fibre Channel QoS Policy.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Fibre Channel QoS Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  rate_limit:
    description:
      - The value in Mbps to use for limiting the data rate on the virtual interface.
      - A value of 0 means no rate limiting.
      - Valid range is 0 to 100000 Mbps.
    type: int
    default: 0
  max_data_field_size:
    description:
      - The maximum size of the Fibre Channel frame payload bytes that the virtual interface supports.
      - Valid range is 256 to 2112 bytes.
    type: int
    default: 2112
  cos:
    description:
      - Class of Service to be associated to the traffic on the virtual interface.
      - Valid range is 0 to 6.
    type: int
    default: 3
  burst:
    description:
      - The burst traffic, in bytes, allowed on the vHBA.
      - Valid range is 1 to 1000000 bytes.
    type: int
    default: 10240
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create Fibre Channel QoS Policy with default settings
  cisco.intersight.intersight_fibre_channel_qos_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-qos-default"
    description: "Fibre Channel QoS policy with default values"
    state: present

- name: Create Fibre Channel QoS Policy with custom settings
  cisco.intersight.intersight_fibre_channel_qos_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-qos-custom"
    description: "Fibre Channel QoS policy with custom values"
    rate_limit: 10000
    max_data_field_size: 2048
    cos: 5
    burst: 20480
    tags:
      - Key: Environment
        Value: Production
    state: present

- name: Create Fibre Channel QoS Policy with maximum rate limit
  cisco.intersight.intersight_fibre_channel_qos_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
    name: "fc-qos-high-bandwidth"
    description: "Fibre Channel QoS policy with maximum bandwidth"
    rate_limit: 100000
    max_data_field_size: 2112
    cos: 6
    burst: 1000000
    state: present

- name: Create Fibre Channel QoS Policy with minimal frame size
  cisco.intersight.intersight_fibre_channel_qos_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-qos-minimal"
    description: "Fibre Channel QoS policy with minimal frame size"
    rate_limit: 0
    max_data_field_size: 256
    cos: 0
    burst: 1
    state: present

- name: Update Fibre Channel QoS Policy description
  cisco.intersight.intersight_fibre_channel_qos_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-qos-default"
    description: "Updated Fibre Channel QoS policy description"
    state: present

- name: Delete Fibre Channel QoS Policy
  cisco.intersight.intersight_fibre_channel_qos_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-qos-default"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "fc-qos-custom",
        "ObjectType": "vnic.FcQosPolicy",
        "RateLimit": 10000,
        "MaxDataFieldSize": 2048,
        "Cos": 5,
        "Burst": 20480,
        "Moid": "1234567890abcdef12345678",
        "Description": "Fibre Channel QoS policy with custom values",
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
    Validate module parameters for Fibre Channel QoS policy configuration.
    """
    if module.params['state'] != 'present':
        return
    # Validate rate_limit range (0-100000)
    rate_limit = module.params.get('rate_limit')
    if rate_limit is not None and (rate_limit < 0 or rate_limit > 100000):
        module.fail_json(msg="Parameter 'rate_limit' must be between 0 and 100000 Mbps")
    # Validate max_data_field_size range (256-2112)
    max_data_field_size = module.params.get('max_data_field_size')
    if max_data_field_size is not None and (max_data_field_size < 256 or max_data_field_size > 2112):
        module.fail_json(msg="Parameter 'max_data_field_size' must be between 256 and 2112 bytes")
    # Validate cos range (0-6)
    cos = module.params.get('cos')
    if cos is not None and (cos < 0 or cos > 6):
        module.fail_json(msg="Parameter 'cos' must be between 0 and 6")
    # Validate burst range (1-1000000)
    burst = module.params.get('burst')
    if burst is not None and (burst < 1 or burst > 1000000):
        module.fail_json(msg="Parameter 'burst' must be between 1 and 1000000 bytes")


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        rate_limit=dict(type='int', default=0),
        max_data_field_size=dict(type='int', default=2112),
        cos=dict(type='int', default=3),
        burst=dict(type='int', default=10240),
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
    resource_path = '/vnic/FcQosPolicies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': module.params['organization'],
        },
        'Name': module.params['name'],
    }
    if module.params['state'] == 'present':
        intersight.api_body['RateLimit'] = module.params['rate_limit']
        intersight.api_body['MaxDataFieldSize'] = module.params['max_data_field_size']
        intersight.api_body['Cos'] = module.params['cos']
        intersight.api_body['Burst'] = module.params['burst']
        intersight.set_tags_and_description()
    intersight.configure_policy_or_profile(resource_path=resource_path)
    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
