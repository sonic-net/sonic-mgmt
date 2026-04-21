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
module: cp_mgmt_resource_tcp
short_description: Manages resource-tcp objects on Checkpoint over Web Services API
description:
  - Manages resource-tcp objects on Checkpoint devices including creating, updating and removing objects.
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
  resource_type:
    description:
      - The type of the TCP resource.
    type: str
    choices: ['cvp', 'ufp']
  exception_track:
    description:
      - Configures how to track connections that match this rule but fail the content security checks. An example of an exception is a connection with
        an unsupported scheme or method.
    type: str
    choices: ['none', 'exception log', 'exception alert']
  ufp_settings:
    description:
      - UFP settings.
    type: dict
    suboptions:
      server:
        description:
          - UFP server identified by name or UID. The UFP server must already be defined as an OPSEC Application.
        type: str
      caching_control:
        description:
          - Specifies if and how caching is to be enabled.
        type: str
        choices: ['security_gateway_one_request', 'security_gateway_two_requests', 'no_caching', 'ufp_server']
      ignore_ufp_server_after_failure:
        description:
          - The UFP server will be ignored after numerous UFP server connections were unsuccessful.
        type: bool
      number_of_failures_before_ignore:
        description:
          - Signifies at what point the UFP server should be ignored, Applicable only if 'ignore after fail' is enabled.
        type: int
      timeout_before_reconnecting:
        description:
          - The amount of time, in seconds, that must pass before a UFP server connection should be attempted, Applicable only if 'ignore after
            fail' is enabled.
        type: int
  cvp_settings:
    description:
      - CVP settings.
    type: dict
    suboptions:
      server:
        description:
          - CVP server identified by name or UID. The CVP server must already be defined as an OPSEC Application.
        type: str
      allowed_to_modify_content:
        description:
          - Configures the CVP server to inspect but not modify content.
        type: bool
      reply_order:
        description:
          - Designates when the CVP server returns data to the Security Gateway security server.
        type: str
        choices: ['return_data_after_content_is_approved', 'return_data_before_content_is_approved']
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
- name: add-resource-tcp
  cp_mgmt_resource_tcp:
    name: newTcpResource
    state: present
    ufp_settings:
      caching_control: security_gateway_one_request
      ignore_ufp_server_after_failure: true
      number_of_failures_before_ignore: 3
      server: ufpServer

- name: set-resource-tcp
  cp_mgmt_resource_tcp:
    cvp_settings:
      server: cvpServer
    name: newTcpResource
    state: present
    ufp_settings:
      caching_control: ufp_server
      ignore_ufp_server_after_failure: false
      number_of_failures_before_ignore: 0

- name: delete-resource-tcp
  cp_mgmt_resource_tcp:
    name: tcpResource
    state: absent
"""

RETURN = """
cp_mgmt_resource_tcp:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        resource_type=dict(type='str', choices=['cvp', 'ufp']),
        exception_track=dict(type='str', choices=['none', 'exception log', 'exception alert']),
        ufp_settings=dict(type='dict', options=dict(
            server=dict(type='str'),
            caching_control=dict(type='str', choices=['security_gateway_one_request', 'security_gateway_two_requests', 'no_caching', 'ufp_server']),
            ignore_ufp_server_after_failure=dict(type='bool'),
            number_of_failures_before_ignore=dict(type='int'),
            timeout_before_reconnecting=dict(type='int')
        )),
        cvp_settings=dict(type='dict', options=dict(
            server=dict(type='str'),
            allowed_to_modify_content=dict(type='bool'),
            reply_order=dict(type='str', choices=['return_data_after_content_is_approved', 'return_data_before_content_is_approved'])
        )),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        domains_to_process=dict(type='list', elements='str'),
        tags=dict(type='list', elements='str'),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'resource-tcp'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
