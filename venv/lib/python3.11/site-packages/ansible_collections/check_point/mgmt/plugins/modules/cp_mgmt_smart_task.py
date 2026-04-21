#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: cp_mgmt_smart_task
short_description: Manages smart-task objects on Checkpoint over Web Services API
description:
  - Manages smart-task objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R80.40 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  action:
    description:
      - The action to be run when the trigger is fired.
    type: dict
    suboptions:
      send_web_request:
        description:
          - When the trigger is fired, sends an HTTPS POST web request to the configured URL.<br>The trigger data will be passed along with the
            SmartTask's custom data in the request's payload.
        type: dict
        suboptions:
          url:
            description:
              - URL used for the web request.
            type: str
          fingerprint:
            description:
              - The SHA1 fingerprint of the URL's SSL certificate. Used to trust servers with self-signed SSL certificates.
            type: str
          override_proxy:
            description:
              - Option to send to the web request via a proxy other than the Management's Server proxy (if defined).
            type: bool
          proxy_url:
            description:
              - URL of the proxy used to send the request.
            type: str
          shared_secret:
            description:
              - Shared secret that can be used by the target server to identify the Management Server.<br>The value will be sent as part of
                the request in the "X-chkp-shared-secret" header.
            type: str
          time_out:
            description:
              - Web Request time-out in seconds.
            type: int
      run_script:
        description:
          - When the trigger is fired, runs the configured Repository Script on the defined targets.<br>The trigger data is then passed to the
            script as the first parameter. The parameter is JSON encoded in Base64 format.
        type: dict
        suboptions:
          repository_script:
            description:
              - Repository script that is executed when the trigger is fired.,  identified by the name or UID.
            type: str
          targets:
            description:
              - Targets to execute the script on.
            type: list
            elements: str
          time_out:
            description:
              - Script execution time-out in seconds.
            type: int
      send_mail:
        description:
          - When the trigger is fired, sends the configured email to the defined recipients.
        type: dict
        suboptions:
          mail_settings:
            description:
              - The required settings to send the mail by.
            type: dict
            suboptions:
              recipients:
                description:
                  - A comma separated list of recipient mail addresses.
                type: str
              sender_email:
                description:
                  - An email address to send the mail from.
                type: str
              subject:
                description:
                  - The email subject.
                type: str
              body:
                description:
                  - The email body.
                type: str
              attachment:
                description:
                  - What file should be attached to the mail.
                type: str
                choices: ['no attachment', 'changes report', 'policy installation report']
              bcc_recipients:
                description:
                  - A comma separated list of bcc recipient mail addresses.
                type: str
              cc_recipients:
                description:
                  - A comma separated list of cc recipient mail addresses.
                type: str
          smtp_server:
            description:
              - The UID or the name a preconfigured SMTP server object.
            type: str
  trigger:
    description:
      - Trigger type associated with the SmartTask.
    type: str
  custom_data:
    description:
      - Per SmartTask custom data in JSON format.<br>When the trigger is fired, the trigger data is converted to JSON. The custom data is then
        concatenated to the trigger data JSON.
    type: str
  description:
    description:
      - Description of the SmartTask's functionality and options.
    type: str
  enabled:
    description:
      - Whether the SmartTask is enabled and will run when triggered.
    type: bool
  fail_open:
    description:
      - If the action fails to execute, whether to treat the execution failure as an error, or continue.
    type: bool
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
  color:
    description:
      - Color of the object. Should be one of existing colors.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-smart-task
  cp_mgmt_smart_task:
    action:
      run_script:
        repository_script: Session Name Validation Script
        time_out: 30
    custom_data: '{"session-name-format": "CR"}'
    description: Run a validation script that ensures that the a session name matches the expected name format as described in the Custom Data field.
    enabled: true
    name: Validate Session Name Before Publish
    state: present
    trigger: Before Publish

- name: set-smart-task
  cp_mgmt_smart_task:
    action:
      send_web_request:
        fingerprint: 3FDD902286DBF130EF4CEC7939EF81060AB0FEB6
        url: https://demo.example.com/policy-installation-reports
    custom_data: '{"mail-address": "example-admin@example-corp.com"}'
    description: Send policy installation results to the mail address specified in the Custom Data field using the corporate's dedicated web server.
    enabled: true
    name: Send Policy Installation Reports
    state: present
    trigger: After Install Policy

- name: delete-smart-task
  cp_mgmt_smart_task:
    name: Validate Session Name Before Publish
    state: absent
"""

RETURN = """
cp_mgmt_smart_task:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        action=dict(type='dict', options=dict(
            send_web_request=dict(type='dict', options=dict(
                url=dict(type='str'),
                fingerprint=dict(type='str'),
                override_proxy=dict(type='bool'),
                proxy_url=dict(type='str'),
                shared_secret=dict(type='str', no_log=True),
                time_out=dict(type='int')
            )),
            run_script=dict(type='dict', options=dict(
                repository_script=dict(type='str'),
                targets=dict(type='list', elements='str'),
                time_out=dict(type='int')
            )),
            send_mail=dict(type='dict', options=dict(
                mail_settings=dict(type='dict', options=dict(
                    recipients=dict(type='str'),
                    sender_email=dict(type='str'),
                    subject=dict(type='str'),
                    body=dict(type='str'),
                    attachment=dict(type='str', choices=['no attachment', 'changes report', 'policy installation report']),
                    bcc_recipients=dict(type='str'),
                    cc_recipients=dict(type='str')
                )),
                smtp_server=dict(type='str')
            ))
        )),
        trigger=dict(type='str'),
        custom_data=dict(type='str'),
        description=dict(type='str'),
        enabled=dict(type='bool'),
        fail_open=dict(type='bool'),
        tags=dict(type='list', elements='str'),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'smart-task'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
