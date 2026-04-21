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
module: intersight_ssh_policy
short_description: SSH Policy configuration for Cisco Intersight
description:
  - Manages SSH Policy configuration on Cisco Intersight.
  - A policy to configure SSH service settings on Cisco Intersight managed servers.
  - This policy is applicable only for UCS Servers (Standalone).
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/ssh/Policies/get/).
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
      - Profiles and Policies that are created within a Custom Organization are applicable only to devices in the same Organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the SSH Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the SSH Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  enable_ssh:
    description:
      - State of SSH service on the endpoint.
      - If set to false, SSH service will be disabled and ssh_port and ssh_timeout will be ignored.
    type: bool
    default: true
  ssh_port:
    description:
      - Port used for secure shell access.
      - Valid range is 1-65535.
      - This parameter is only used when enable_ssh is true.
    type: int
    default: 22
  ssh_timeout:
    description:
      - Number of seconds to wait before the system considers a SSH request to have timed out.
      - Valid range is 60-10800 seconds.
      - This parameter is only used when enable_ssh is true.
    type: int
    default: 1800
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create SSH Policy with default settings
  cisco.intersight.intersight_ssh_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "SSH-Policy-Default"
    description: "SSH policy with default settings"
    tags:
      - Key: "Environment"
        Value: "Production"
    enable_ssh: true
    state: present

- name: Create SSH Policy with custom port and timeout
  cisco.intersight.intersight_ssh_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "SSH-Policy-Custom"
    description: "SSH policy with custom port and timeout"
    enable_ssh: true
    ssh_port: 2222
    ssh_timeout: 3600
    state: present

- name: Create SSH Policy with SSH disabled
  cisco.intersight.intersight_ssh_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "SSH-Policy-Disabled"
    description: "SSH policy with SSH service disabled"
    enable_ssh: false
    state: present

- name: Delete SSH Policy
  cisco.intersight.intersight_ssh_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "SSH-Policy-Default"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "SSH-Policy-Default",
        "ObjectType": "ssh.Policy",
        "Enabled": true,
        "Port": 22,
        "Timeout": 1800,
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
        enable_ssh=dict(type='bool', default=True),
        ssh_port=dict(type='int', default=22),
        ssh_timeout=dict(type='int', default=1800)
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True
    )

    # Validate ssh_port range
    if module.params['ssh_port'] < 1 or module.params['ssh_port'] > 65535:
        module.fail_json(msg="ssh_port must be between 1 and 65535")

    # Validate ssh_timeout range
    if module.params['ssh_timeout'] < 60 or module.params['ssh_timeout'] > 10800:
        module.fail_json(msg="ssh_timeout must be between 60 and 10800 seconds")

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/ssh/Policies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
        'Enabled': intersight.module.params['enable_ssh'],
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Add SSH port and timeout only if SSH is enabled
        if intersight.module.params['enable_ssh']:
            intersight.api_body['Port'] = intersight.module.params['ssh_port']
            intersight.api_body['Timeout'] = intersight.module.params['ssh_timeout']

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
