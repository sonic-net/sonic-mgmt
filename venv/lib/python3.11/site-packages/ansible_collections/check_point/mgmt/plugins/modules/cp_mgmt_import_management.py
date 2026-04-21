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
module: cp_mgmt_import_management
short_description: Import the primary Security Management Server database or the primary Multi-Domain Server database or the single Domain database and the
                   applicable Check Point configuration.
description:
  - Import the primary Security Management Server database or the primary Multi-Domain Server database or the single Domain database and the applicable
    Check Point configuration. <br/>After the import starts, the session expires and you must login again.
  - All operations are performed over Web Services API.
  - Available from R81.10 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  file_path:
    description:
      - Path to the exported database file to be imported.
    type: str
    required: True
  domain_name:
    description:
      - Domain name to be imported. Must be unique in the Multi-Domain Server.<br><font color="red">Required only for</font> importing the Security
        Management Server into the Multi-Domain Server.
    type: str
  domain_ip_address:
    description:
      - IPv4 address for the imported Domain.<br><font color="red">Required only for</font> importing the Security Management Server into the
        Multi-Domain Server.
    type: str
  domain_server_name:
    description:
      - Multi-Domain Server name for the imported Domain.<br><font color="red">Required only for</font> importing the Security Management Server into
        the Multi-Domain Server.
    type: str
  include_logs:
    description:
      - Import logs without log indexes.
    type: bool
  include_logs_indexes:
    description:
      - Import logs with log indexes.
    type: bool
  keep_cloud_sharing:
    description:
      - Preserve the connection of the Management Server to Check Point's Infinity Portal.<br>Use this flag after ensuring that the original
        Management Server does not communicate with Infinity Portal.<br>Note, resuming the connection is also possible after import with set-cloud-services.
      - Available from R81.20 management version.
    type: bool
  include_endpoint_configuration:
    description:
      - Include import of the Endpoint Security Management configuration files.
    type: bool
  include_endpoint_database:
    description:
      - Include import of the Endpoint Security Management database.
    type: bool
  verify_domain_restore:
    description:
      - If true, verify that the restore operation is valid for this input file and this environment. <br>Note, Restore operation will not be executed.
    type: bool
  pre_import_verification_only:
    description:
      - If true, only runs the pre-import verifications instead of the full import.
    type: bool
  ignore_warnings:
    description:
      - Ignoring the verification warnings. By Setting this parameter to 'true' import will not be blocked by warnings.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: import-management
  cp_mgmt_import_management:
    file_path: /var/log/domain1_exported.tgz
"""

RETURN = """
cp_mgmt_import_management:
  description: The checkpoint import-management output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        file_path=dict(type='str', required=True),
        domain_name=dict(type='str'),
        domain_ip_address=dict(type='str'),
        domain_server_name=dict(type='str'),
        include_logs=dict(type='bool'),
        include_logs_indexes=dict(type='bool'),
        keep_cloud_sharing=dict(type='bool'),
        include_endpoint_configuration=dict(type='bool'),
        include_endpoint_database=dict(type='bool'),
        verify_domain_restore=dict(type='bool'),
        pre_import_verification_only=dict(type='bool'),
        ignore_warnings=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "import-management"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
