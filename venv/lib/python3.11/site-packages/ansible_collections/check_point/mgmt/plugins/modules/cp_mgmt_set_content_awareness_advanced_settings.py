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
module: cp_mgmt_set_content_awareness_advanced_settings
short_description: Edit Content Awareness Blades' Settings.
description:
  - Edit Content Awareness Blades' Settings.
  - All operations are performed over Web Services API.
  - Available from R82 management version.
version_added: "6.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  internal_error_fail_mode:
    description:
      - In case of internal system error, allow or block all connections.
    type: str
    choices: ['allow connections', 'block connections']
  supported_services:
    description:
      - Specify the services that Content Awareness inspects.
    type: list
    elements: str
  httpi_non_standard_ports:
    description:
      - Servers usually send HTTP traffic on TCP port 80. Some servers send HTTP traffic on other ports also. By default, this setting is enabled and
        Content Awareness inspects HTTP traffic on non-standard ports. You can disable this setting and configure Content Awareness to inspect HTTP traffic
        only on port 80.
    type: bool
  inspect_archives:
    description:
      - Examine the content of archive files. For example, files with the extension .zip, .gz, .tgz, .tar.Z, .tar, .lzma, .tlz, 7z, .rar.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-content-awareness-advanced-settings
  cp_mgmt_set_content_awareness_advanced_settings:
    httpi_non_standard_ports: 'false'
    inspect_archives: 'false'
    internal_error_fail_mode: block connections
    supported_services:
      - Squid_NTLM
"""

RETURN = """
cp_mgmt_set_content_awareness_advanced_settings:
  description: The checkpoint set-content-awareness-advanced-settings output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        internal_error_fail_mode=dict(type='str', choices=['allow connections', 'block connections']),
        supported_services=dict(type='list', elements='str'),
        httpi_non_standard_ports=dict(type='bool'),
        inspect_archives=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-content-awareness-advanced-settings"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
