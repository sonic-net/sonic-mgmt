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
module: cp_mgmt_add_central_license
short_description: Add central license.
description:
  - Add central license.
  - All operations are performed over Web Services API.
  - Available from R81.20 JHF management version.
version_added: "5.2.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  license:
    description:
      - The license string received from the User Center - without 'cplic put'.
    type: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: add-central-license
  cp_mgmt_add_central_license:
    license: 192.168.1.2 never dTTTTTT-WWWWWW-SSSSSSS-QQQQQQ CPSG-VE+3 CPBS-BECE CPSB-DFW CPSM-C-2 CPSB-VPN CPSB-NPM CPSB-LOGS CPSB-IA
     CPSB-ADNC CPSB-SSLVWPN-5 CK-66666666
"""

RETURN = """
cp_mgmt_add_central_license:
  description: The checkpoint add-central-license output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        license=dict(type='str')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "add-central-license"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
