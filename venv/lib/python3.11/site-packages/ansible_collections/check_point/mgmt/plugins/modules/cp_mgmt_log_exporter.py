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
module: cp_mgmt_log_exporter
short_description: Manages log-exporter objects on Checkpoint over Web Services API
description:
  - Manages log-exporter objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R82 JHF management version.
version_added: "6.5.0"
author: "Dor Berenstein (@chkp-dorbe)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  target_server:
    description:
      - Target server port to which logs are exported.
    type: str
  target_port:
    description:
      - Port number of the target server.
    type: int
  protocol:
    description:
      - Protocol used to send logs to the target server.
    type: str
    choices: ['udp', 'tcp']
  enabled:
    description:
      - Indicates whether to enable export.
    type: bool
  attachments:
    description:
      - Log exporter attachments.
    type: dict
    suboptions:
      add_link_to_log_attachment:
        description:
          - Indicates whether to add link to log attachment in SmartView.
        type: bool
      add_link_to_log_details:
        description:
          - Indicates whether to add link to log details in SmartView.
        type: bool
      add_log_attachment_id:
        description:
          - Indicates whether to add log attachment ID.
        type: bool
  data_manipulation:
    description:
      - Log exporter data manipulation.
    type: dict
    suboptions:
      aggregate_log_updates:
        description:
          - Indicates whether to aggregate log updates.
        type: bool
      format:
        description:
          - Logs format.
        type: str
        choices: ['syslog', 'cef', 'leef', 'generic', 'splunk', 'logrhythm', 'json']
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
  domains_to_process:
    description:
      - Indicates which domains to process the commands on. It cannot be used with the details-level full, must be run from the System Domain only and
        with ignore-warnings true. Valid values are, CURRENT_DOMAIN, ALL_DOMAINS_ON_THIS_SERVER.
    type: list
    elements: str
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
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
- name: add-log-exporter
  cp_mgmt_log_exporter:
    attachments:
      add_link_to_log_attachment: true
    name: newLogExporter
    protocol: tcp
    state: present
    target_port: 1234
    target_server: 1.2.3.4

- name: set-log-exporter
  cp_mgmt_log_exporter:
    data_manipulation:
      format: json
    name: newLogExporter
    state: present
    target_port: 999

- name: delete-log-exporter
  cp_mgmt_log_exporter:
    name: newLogExporter
    state: absent
"""

RETURN = """
cp_mgmt_log_exporter:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        target_server=dict(type='str'),
        target_port=dict(type='int'),
        protocol=dict(type='str', choices=['udp', 'tcp']),
        enabled=dict(type='bool'),
        attachments=dict(type='dict', options=dict(
            add_link_to_log_attachment=dict(type='bool'),
            add_link_to_log_details=dict(type='bool'),
            add_log_attachment_id=dict(type='bool')
        )),
        data_manipulation=dict(type='dict', options=dict(
            aggregate_log_updates=dict(type='bool'),
            format=dict(type='str', choices=['syslog', 'cef', 'leef', 'generic', 'splunk', 'logrhythm', 'json'])
        )),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        domains_to_process=dict(type='list', elements="str"),
        tags=dict(type='list', elements="str"),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'log-exporter'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
