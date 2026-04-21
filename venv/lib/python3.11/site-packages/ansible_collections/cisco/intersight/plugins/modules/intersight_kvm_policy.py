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
module: intersight_kvm_policy
short_description: Virtual KVM Policy configuration for Cisco Intersight
description:
  - Manages Virtual KVM Policy configuration on Cisco Intersight.
  - A policy to configure virtual KVM settings on Cisco Intersight managed servers.
  - When enabled, configures session limits, port settings, encryption, and tunneling options.
  - When disabled, only the enabled state is configured while other settings are ignored.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/kvm/Policy/get/).
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
      - The name assigned to the KVM Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the KVM Policy.
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
      - State of the vKVM service on the endpoint.
      - When set to false, all other configuration parameters are ignored and only the enabled state is configured.
      - When set to true, all other configuration parameters take effect.
    type: bool
    default: true
  maximum_sessions:
    description:
      - The maximum number of concurrent KVM sessions allowed.
      - Valid range is 1-4 sessions.
      - This parameter is ignored when C(enabled) is C(false).
    type: int
    default: 4
  remote_port:
    description:
      - The port used for KVM communication.
      - Valid range is 1024-65535.
      - This parameter is ignored when C(enabled) is C(false).
    type: int
    default: 2068
  enable_video_encryption:
    description:
      - If enabled, encrypts all video information sent through KVM.
      - Please note that this can no longer be disabled for servers running versions 4.2 and above.
      - This parameter is ignored when C(enabled) is C(false).
    type: bool
    default: true
  enable_local_server_video:
    description:
      - If enabled, displays KVM session on any monitor attached to the server.
      - This parameter is ignored when C(enabled) is C(false).
    type: bool
    default: true
  tunneled_kvm_enabled:
    description:
      - Enables Tunneled vKVM on the endpoint.
      - Applicable only for Device Connectors that support Tunneled vKVM.
      - This parameter is ignored when C(enabled) is C(false).
    type: bool
    default: false
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create an enabled KVM Policy with default settings
  cisco.intersight.intersight_kvm_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Default-KVM-Policy"
    description: "KVM policy with standard settings"
    enabled: true
    tags:
      - Key: "Environment"
        Value: "Production"

- name: Create a KVM Policy with custom settings
  cisco.intersight.intersight_kvm_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Custom-KVM-Policy"
    description: "KVM policy with custom port and session limits"
    enabled: true
    maximum_sessions: 2
    remote_port: 3000
    enable_video_encryption: true
    enable_local_server_video: false
    tunneled_kvm_enabled: true
    tags:
      - Key: "Owner"
        Value: "DevOps"

- name: Create a disabled KVM Policy
  cisco.intersight.intersight_kvm_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Disabled-KVM-Policy"
    description: "Disabled KVM policy for security compliance"
    enabled: false
    tags:
      - Key: "Security"
        Value: "Disabled"

- name: Delete a KVM Policy
  cisco.intersight.intersight_kvm_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Old-KVM-Policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "Custom-KVM-Policy",
        "ObjectType": "kvm.Policy",
        "Enabled": true,
        "MaximumSessions": 2,
        "RemotePort": 3000,
        "EnableVideoEncryption": true,
        "EnableLocalServerVideo": false,
        "TunneledKvmEnabled": true,
        "Tags": [
            {
                "Key": "Owner",
                "Value": "DevOps"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def validate_kvm_policy_params(module):
    """
    Validate KVM policy parameters
    """
    # Validate maximum_sessions range
    max_sessions = module.params.get('maximum_sessions', 4)
    if max_sessions < 1 or max_sessions > 4:
        module.fail_json(msg="maximum_sessions must be between 1 and 4 (inclusive)")

    # Validate remote_port range
    remote_port = module.params.get('remote_port', 2068)
    if remote_port < 1024 or remote_port > 65535:
        module.fail_json(msg="remote_port must be between 1024 and 65535 (inclusive)")


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        enabled=dict(type='bool', default=True),
        maximum_sessions=dict(type='int', default=4),
        remote_port=dict(type='int', default=2068),
        enable_video_encryption=dict(type='bool', default=True),
        enable_local_server_video=dict(type='bool', default=True),
        tunneled_kvm_enabled=dict(type='bool', default=False)
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    # Validate KVM policy specific parameters
    validate_kvm_policy_params(module)

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/kvm/Policies'
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
            'Enabled': intersight.module.params['enabled']
        })
        # Only add KVM-specific settings if enabled is True
        if intersight.module.params['enabled']:
            intersight.api_body.update({
                'MaximumSessions': intersight.module.params['maximum_sessions'],
                'RemotePort': intersight.module.params['remote_port'],
                'EnableVideoEncryption': intersight.module.params['enable_video_encryption'],
                'EnableLocalServerVideo': intersight.module.params['enable_local_server_video'],
                'TunneledKvmEnabled': intersight.module.params['tunneled_kvm_enabled']
            })

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
