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
module: cp_mgmt_set_outbound_inspection_certificate
short_description: Edit outbound-inspection-certificate
description:
  - Edit outbound-inspection-certificate
  - All operations are performed over Web Services API.
  - Available from R81.20 management version.
version_added: "6.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  issued_by:
    description:
      - The DN (Distinguished Name) of the certificate.<br><font color="red">Required only if</font> one of the following parameters is given,
        base64-password, valid-from, valid-to.
      - Available from R82 management version.
    type: str
  base64_password:
    description:
      - Password (encoded in Base64 with padding) for the certificate file.<br><font color="red">Required only if</font> one of the following
        parameters is given, issued-by, valid-from, valid-to.
      - Available from R82 management version.
    type: str
  valid_from:
    description:
      - The date, from which the certificate is valid. Format, YYYY-MM-DD.<br><font color="red">Required only if</font> one of the following
        parameters is given, issued-by, base64-password, valid-to.
      - Available from R82 management version.
    type: str
  valid_to:
    description:
      - The certificate expiration date. Format, YYYY-MM-DD.<br><font color="red">Required only if</font> one of the following parameters is given,
        issued-by, base64-password, valid-from.
      - Available from R82 management version.
    type: str
  name:
    description:
      - Object name.
    type: str
    required: True
  is_default:
    description:
      - Is the certificate the default certificate.
      - Available from R82 management version.
    type: bool
  tags:
    description:
      - Collection of tag identifiers.
      - Available from R82 management version.
    type: list
    elements: str
  color:
    description:
      - Color of the object. Should be one of existing colors.
      - Available from R82 management version.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
      - Available from R82 management version.
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
      - Available from R82 management version.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
      - Available from R82 management version.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """

- name: set-outbound-inspection-certificate
  cp_mgmt_set_outbound_inspection_certificate:
    base64_password: bXlfcGFzc3dvcmQ=
    is_default: 'false'
    issued_by: www.checkpoint.com
    name: OutboundCertificate
    valid_from: '2021-04-17'
    valid_to: '2028-04-17'
"""

RETURN = """
cp_mgmt_set_outbound_inspection_certificate:
  description: The checkpoint set-outbound-inspection-certificate output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        issued_by=dict(type='str'),
        base64_password=dict(type='str', no_log=True),
        valid_from=dict(type='str'),
        valid_to=dict(type='str'),
        name=dict(type='str', required=True),
        is_default=dict(type='bool'),
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
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)
    command = 'set-outbound-inspection-certificate'

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
