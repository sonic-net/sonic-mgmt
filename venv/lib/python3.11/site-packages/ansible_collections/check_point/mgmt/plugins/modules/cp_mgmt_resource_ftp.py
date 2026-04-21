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
module: cp_mgmt_resource_ftp
short_description: Manages resource-ftp objects on Checkpoint over Web Services API
description:
  - Manages resource-ftp objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R82 management version.
version_added: "6.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  resource_matching_method:
    description:
      - GET allows Downloads from the server to the client. PUT allows Uploads from the client to the server.
    type: str
    choices: ['get', 'put', 'get_and_put']
  exception_track:
    description:
      - The UID or Name of the exception track to be used to log actions taken as a result of a match on the resource.
    type: str
    choices: ['none', 'exception log', 'exception alert']
  resources_path:
    description:
      - Refers to a location on the FTP server.
    type: str
  cvp:
    description:
      - Configure CVP inspection on mail messages.
    type: dict
    suboptions:
      enable_cvp:
        description:
          - Select to enable the Content Vectoring Protocol.
        type: bool
      server:
        description:
          - The UID or Name of the CVP server, make sure the CVP server is already be defined as an OPSEC Application.
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
- name: add-resource-ftp
  cp_mgmt_resource_ftp:
    exception_track: exception log
    name: newFtpResource
    resource_matching_method: get_and_put
    resources_path: path
    state: present

- name: set-resource-ftp
  cp_mgmt_resource_ftp:
    name: newFtpResource
    resource_matching_method: put
    state: present

- name: delete-resource-ftp
  cp_mgmt_resource_ftp:
    name: newFtpResource
    state: absent
"""

RETURN = """
cp_mgmt_resource_ftp:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        resource_matching_method=dict(type='str', choices=['get', 'put', 'get_and_put']),
        exception_track=dict(type='str', choices=['none', 'exception log', 'exception alert']),
        resources_path=dict(type='str'),
        cvp=dict(type='dict', options=dict(
            enable_cvp=dict(type='bool'),
            server=dict(type='str'),
            allowed_to_modify_content=dict(type='bool'),
            reply_order=dict(type='str', choices=['return_data_after_content_is_approved', 'return_data_before_content_is_approved'])
        )),
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
    api_call_object = 'resource-ftp'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
