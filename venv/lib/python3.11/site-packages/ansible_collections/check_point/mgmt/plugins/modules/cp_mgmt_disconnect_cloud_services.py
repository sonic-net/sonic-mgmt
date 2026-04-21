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
module: cp_mgmt_disconnect_cloud_services
short_description: Disconnect the Management Server from Check Point's Infinity Portal.
description:
  - Disconnect the Management Server from Check Point's Infinity Portal.
  - All operations are performed over Web Services API.
  - Available from R81.10 JHF management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  force:
    description:
      - Disconnect the Management Server from Check Point Infinity Portal, and reset the connection locally, regardless of the result in the Infinity
        Portal. This flag can be used if the disconnect-cloud-services command failed. Since with this flag this command affects only the local configuration,
        make sure to disconnect the Management Server in the Infinity Portal as well.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: disconnect-cloud-services
  cp_mgmt_disconnect_cloud_services:
"""

RETURN = """
cp_mgmt_disconnect_cloud_services:
  description: The checkpoint disconnect-cloud-services output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_commands,
    api_command,
)


def main():
    argument_spec = dict(force=dict(type="bool"))
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "disconnect-cloud-services"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
