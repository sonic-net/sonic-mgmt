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
module: cp_mgmt_import_outbound_inspection_certificate
short_description: Import Outbound Inspection certificate for HTTPS inspection.
description:
  - Import Outbound Inspection certificate for HTTPS inspection.
  - All operations are performed over Web Services API.
  - Available from R81.20 management version.
version_added: "6.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  base64_certificate:
    description:
      - Certificate file encoded in base64.<br/>Valid file format, p12.
    type: str
  base64_password:
    description:
      - Password (encoded in Base64 with padding) for the certificate file.
    type: str
  name:
    description:
      - Object name. Must be unique in the domain.
      - Available from R82 management version.
    type: str
  tags:
    description:
      - Collection of tag identifiers.
      - Available from R82 management version.
    type: list
    elements: str
  is_default:
    description:
      - Is the certificate is the default certificate.
      - Available from R82 management version.
    type: bool
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
      - Apply changes ignoring warnings. By Setting this parameter to 'true' default outbound certificate can be replaced.
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
- name: import-outbound-inspection-certificate
  cp_mgmt_import_outbound_inspection_certificate:
    base64_certificate:
      "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"
    base64_password: bXlfcGFzc3dvcmQ=
    is_default: 'false'
    name: OutboundCertificate
"""

RETURN = """
cp_mgmt_import_outbound_inspection_certificate:
  description: The checkpoint import-outbound-inspection-certificate output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        base64_certificate=dict(type='str'),
        base64_password=dict(type='str', no_log=True),
        name=dict(type='str'),
        tags=dict(type='list', elements='str'),
        is_default=dict(type='bool'),
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

    command = "import-outbound-inspection-certificate"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
