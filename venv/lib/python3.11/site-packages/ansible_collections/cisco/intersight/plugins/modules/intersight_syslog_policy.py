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
module: intersight_syslog_policy
short_description: Syslog Policy configuration for Cisco Intersight
description:
  - Manages Syslog Policy configuration on Cisco Intersight.
  - This policy configures local logging severity and up to two remote syslog server destinations for managed devices.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/syslog/Policy/get/).
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
    type: str
    default: default
  name:
    description:
      - The name assigned to the Syslog Policy.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Syslog Policy.
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  local_logging_minimum_severity:
    description:
      - Lowest level of messages to be included in the local log.
    type: str
    choices: ['warning', 'emergency', 'alert', 'critical', 'error', 'notice', 'informational', 'debug']
    default: 'warning'
  first_remote_logging_enabled:
    description:
      - If C(true), enables the first remote syslog server destination.
    type: bool
    default: false
  first_remote_logging_hostname:
    description:
      - Hostname or IP Address of the first syslog server where log should be stored.
      - This parameter is required if C(first_remote_logging_enabled) is C(true).
    type: str
  first_remote_logging_port:
    description:
      - Port number used for logging on first syslog server.
    type: int
    default: 514
  first_remote_logging_protocol:
    description:
      - Transport layer protocol for transmission of log messages to first syslog server.
    type: str
    choices: ['udp', 'tcp']
    default: 'udp'
  first_remote_logging_minimum_severity:
    description:
      - Lowest level of messages to be included in the first remote log.
    type: str
    choices: ['warning', 'emergency', 'alert', 'critical', 'error', 'notice', 'informational', 'debug']
    default: 'warning'
  second_remote_logging_enabled:
    description:
      - If C(true), enables the second remote syslog server destination.
    type: bool
    default: false
  second_remote_logging_hostname:
    description:
      - Hostname or IP Address of the second syslog server where log should be stored.
      - This parameter is required if C(second_remote_logging_enabled) is C(true).
    type: str
  second_remote_logging_port:
    description:
      - Port number used for logging on second syslog server.
    type: int
    default: 514
  second_remote_logging_protocol:
    description:
      - Transport layer protocol for transmission of log messages to second syslog server.
    type: str
    choices: ['udp', 'tcp']
    default: 'udp'
  second_remote_logging_minimum_severity:
    description:
      - Lowest level of messages to be included in the second remote log.
    type: str
    choices: ['warning', 'emergency', 'alert', 'critical', 'error', 'notice', 'informational', 'debug']
    default: 'warning'
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a Syslog Policy with one remote server enabled
  cisco.intersight.intersight_syslog_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Syslog-Policy-PROD"
    description: "Syslog policy for production servers"
    tags:
      - Key: "Env"
        Value: "Production"
    local_logging_minimum_severity: "notice"
    first_remote_logging_enabled: true
    first_remote_logging_hostname: "10.10.10.50"
    first_remote_logging_port: 514
    first_remote_logging_protocol: "udp"
    first_remote_logging_minimum_severity: "informational"

- name: Create a Syslog Policy with only local logging configured
  cisco.intersight.intersight_syslog_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Syslog-Policy-Local-Only"
    description: "Send only critical local logs"
    local_logging_minimum_severity: "critical"

- name: Delete a Syslog Policy
  cisco.intersight.intersight_syslog_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Syslog-Policy-PROD"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "Syslog-Policy-Local-Only",
        "ObjectType": "syslog.Policy",
        "Tags": [],
        "LocalClients": [{
        "ClassId": "syslog.LocalFileLoggingClient",
        "ObjectType": "syslog.LocalFileLoggingClient",
        "MinSeverity": "critical"
        }],
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def validate_input(module: AnsibleModule):
    first_remote_logging_port = module.params['first_remote_logging_port']
    second_remote_logging_port = module.params['second_remote_logging_port']

    if 0 > first_remote_logging_port or first_remote_logging_port > 65535:
        module.fail_json(msg=f"first_remote_logging_port has to be between 0 and 65535, current value is: {first_remote_logging_port}")

    if 0 > second_remote_logging_port or second_remote_logging_port > 65535:
        module.fail_json(msg=f"second_remote_logging_port has to be between 0 and 65535, current value is: {second_remote_logging_port}")


def customize_hostname_default(intersight: IntersightModule):
    # Create a custom default
    if not intersight.module.params['first_remote_logging_hostname']:
        intersight.module.params['first_remote_logging_hostname'] = "0.0.0.0"

    if not intersight.module.params['second_remote_logging_hostname']:
        intersight.module.params['second_remote_logging_hostname'] = "0.0.0.0"


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        local_logging_minimum_severity=dict(
            type='str',
            choices=['warning', 'emergency', 'alert', 'critical', 'error', 'notice', 'informational', 'debug'],
            default='warning'
        ),
        first_remote_logging_enabled=dict(type='bool', default=False),
        first_remote_logging_hostname=dict(type='str'),
        first_remote_logging_port=dict(type='int', default=514),
        first_remote_logging_protocol=dict(
            type='str',
            choices=['udp', 'tcp'],
            default='udp'
        ),
        first_remote_logging_minimum_severity=dict(
            type='str',
            choices=['warning', 'emergency', 'alert', 'critical', 'error', 'notice', 'informational', 'debug'],
            default='warning'
        ),
        second_remote_logging_enabled=dict(type='bool', default=False),
        second_remote_logging_hostname=dict(type='str'),
        second_remote_logging_port=dict(type='int', default=514),
        second_remote_logging_protocol=dict(
            type='str',
            choices=['udp', 'tcp'],
            default='udp'
        ),
        second_remote_logging_minimum_severity=dict(
            type='str',
            choices=['warning', 'emergency', 'alert', 'critical', 'error', 'notice', 'informational', 'debug'],
            default='warning'
        )

    )
    required_if = [
        ('first_remote_logging_enabled', True, ['first_remote_logging_hostname']),
        ('second_remote_logging_enabled', True, ['second_remote_logging_hostname'])
    ]

    module = AnsibleModule(
        argument_spec,
        required_if=required_if,
        supports_check_mode=True,
    )

    validate_input(module)
    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    customize_hostname_default(intersight)

    # Resource path used to configure policy
    resource_path = '/syslog/Policies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
        'LocalClients': [
            {
                'ObjectType': 'syslog.LocalFileLoggingClient',
                "MinSeverity": intersight.module.params['local_logging_minimum_severity']
            }
        ],
        'RemoteClients': [
            {
                'Type': 'syslog.RemoteLoggingClient',
                'Enabled': intersight.module.params['first_remote_logging_enabled'],
                'ObjectType': 'syslog.RemoteLoggingClient',
                'Hostname': intersight.module.params['first_remote_logging_hostname'],
                'Port': intersight.module.params['first_remote_logging_port'],
                'Protocol': intersight.module.params['first_remote_logging_protocol'],
                'MinSeverity': intersight.module.params['first_remote_logging_minimum_severity']
            },
            {
                'Type': 'syslog.RemoteLoggingClient',
                'Enabled': intersight.module.params['second_remote_logging_enabled'],
                'ObjectType': 'syslog.RemoteLoggingClient',
                'Hostname': intersight.module.params['second_remote_logging_hostname'],
                'Port': intersight.module.params['second_remote_logging_port'],
                'Protocol': intersight.module.params['second_remote_logging_protocol'],
                'MinSeverity': intersight.module.params['second_remote_logging_minimum_severity']
            }
        ],
    }

    intersight.set_tags_and_description()

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
