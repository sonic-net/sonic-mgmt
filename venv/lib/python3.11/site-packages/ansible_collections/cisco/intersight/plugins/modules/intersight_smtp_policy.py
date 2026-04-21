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
module: intersight_smtp_policy
short_description: SMTP Policy configuration for Cisco Intersight
description:
  - Manages SMTP Policy configuration on Cisco Intersight.
  - Configures SMTP settings for email notifications.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs).
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
      - The name assigned to the SMTP Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the SMTP Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
    default: []
  enabled:
    description:
      - If enabled, controls the state of the SMTP client service on the managed device.
    type: bool
    default: true
  smtp_server:
    description:
      - IP address or hostname of the SMTP server.
      - The SMTP server is used by the managed device to send email notifications.
      - Required when C(enabled) is True.
    type: str
  smtp_port:
    description:
      - Port number used by the SMTP server for outgoing SMTP communication.
      - Valid range is 1-65535.
    type: int
    default: 25
  min_severity:
    description:
      - Minimum fault severity level to receive email notifications.
      - Email notifications are sent for all faults whose severity is equal to or greater than the chosen level.
    type: str
    choices: [critical, major, minor, warning, condition, condition]
    default: critical
  sender_email:
    description:
      - The email address entered here will be displayed as the from address (mail received from address) of all the SMTP mail alerts that are received.
      - If not configured, the hostname of the server is used in the from address field.
    type: str
  smtp_recipients:
    description:
      - List of email addresses that will receive notifications for faults.
    type: list
    elements: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create SMTP Policy
  cisco.intersight.intersight_smtp_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "smtp-policy-test"
    description: "SMTP Policy for Alerting"
    enabled: true
    smtp_server: "smtp.example.com"
    smtp_port: 25
    min_severity: "warning"
    sender_email: "alerts@example.com"
    smtp_recipients:
      - "admin@example.com"
      - "devops@example.com"
    tags:
      - Key: "Environment"
        Value: "Production"
    state: present

- name: Disable SMTP Policy
  cisco.intersight.intersight_smtp_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "smtp-policy-test"
    enabled: false
    state: present

- name: Delete SMTP Policy
  cisco.intersight.intersight_smtp_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "smtp-policy-test"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "smtp-policy-test",
        "ObjectType": "smtp.Policy",
        "Description": "SMTP Policy for Alerting",
        "Enabled": true,
        "SmtpServer": "smtp.example.com",
        "SmtpPort": 25,
        "MinSeverity": "warning",
        "SenderEmail": "alerts@example.com",
        "SmtpRecipients": [
            "admin@example.com",
            "devops@example.com"
        ],
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
        tags=dict(type='list', elements='dict', default=[]),
        enabled=dict(type='bool', default=True),
        smtp_server=dict(type='str'),
        smtp_port=dict(type='int', default=25),
        min_severity=dict(type='str', choices=['critical', 'major', 'minor', 'warning', 'condition', 'condition'], default='critical'),
        sender_email=dict(type='str'),
        smtp_recipients=dict(type='list', elements='str')
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Build API Body
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if module.params['state'] == 'present':
        intersight.set_tags_and_description()
        intersight.api_body['Enabled'] = module.params['enabled']
        if module.params['enabled']:
            if not module.params.get('smtp_server'):
                module.fail_json(msg="smtp_server is required when enabled is True")

            if module.params.get('smtp_server'):
                intersight.api_body['SmtpServer'] = module.params['smtp_server']
            if module.params.get('smtp_port'):
                intersight.api_body['SmtpPort'] = module.params['smtp_port']
            if module.params.get('min_severity'):
                intersight.api_body['MinSeverity'] = module.params['min_severity']
            if module.params.get('sender_email'):
                intersight.api_body['SenderEmail'] = module.params['sender_email']
            if module.params.get('smtp_recipients'):
                intersight.api_body['SmtpRecipients'] = module.params['smtp_recipients']

    resource_path = '/smtp/Policies'
    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
