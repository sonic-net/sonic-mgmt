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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: cp_mgmt_connect_cloud_services
short_description: Securely connect the Management Server to Check Point's Infinity Portal. <br>This is a preliminary operation so that the management server
                   can use various Check Point cloud-based security services hosted in the Infinity Portal.
description:
  - Securely connect the Management Server to Check Point's Infinity Portal. <br>This is a preliminary operation so that the management server can use
    various Check Point cloud-based security services hosted in the Infinity Portal.
  - All operations are performed over Web Services API.
  - Available from R81.10 JHF management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  auth_token:
    description:
      - Copy the authentication token from the Smart-1 cloud service hosted in the Infinity Portal.
    type: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: connect-cloud-services
  cp_mgmt_connect_cloud_services:
    # sgignore next_line
    auth_token: aHR0cHM6Ly9kZXYtY2xvdWRpbmZyYS1ndy5rdWJlMS5pYWFzLmNoZWNrcG9pbnQuY29tL2FwcC9tYWFzL2FwaS92Mi9tYW5hZ2VtZW50
                cy9hZmJlYWRlYS04Y2U2LTRlYTUtOTI4OS00ZTQ0N2M0ZjgyMTvY2xvdWRBY2Nlc3MvP290cD02ZWIzNThlOS1hMzkxLTQxOGQtYjlmZ
                i0xOGIxOTQwOGJlN2Y=
"""

RETURN = """
cp_mgmt_connect_cloud_services:
  description: The checkpoint connect-cloud-services output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_commands,
    api_command,
)


def main():
    argument_spec = dict(auth_token=dict(type="str", no_log=True))
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "connect-cloud-services"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
