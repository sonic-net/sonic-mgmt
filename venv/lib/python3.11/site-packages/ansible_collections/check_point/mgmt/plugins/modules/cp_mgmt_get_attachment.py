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
module: cp_mgmt_get_attachment
short_description: Retrieves a packet capture or blob data, according to the attributes of a log record.
description:
  - Retrieves a packet capture or blob data, according to the attributes of a log record.
  - All operations are performed over Web Services API.
  - Available from R80.40 JHF management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  attachment_id:
    description:
      - Attachment identifier from a log record.
    type: str
  id:
    description:
      - Log id from a log record.
    type: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: get-attachment
  cp_mgmt_get_attachment:
    attachment_id: MjY5HlNtYXJ0RGVmZW5zZR5jbj1jcF9tZ210LG89aHVnbzEtYmxvYkFwaS1uZXctdGFrZS0yLmNoZWNrcG9pbnQuY29tLnM2MjdvMx57MHg1OTg4
"""

RETURN = """
cp_mgmt_get_attachment:
  description: The checkpoint get-attachment output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        attachment_id=dict(type='str'),
        id=dict(type='str')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "get-attachment"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
