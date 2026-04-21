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
module: cp_mgmt_export_management
short_description: Export the primary Security Management Server database or the primary Multi-Domain Server database or the single Domain database and the
                   applicable Check Point configuration.
description:
  - Export the primary Security Management Server database or the primary Multi-Domain Server database or the single Domain database and the applicable
    Check Point configuration.
  - All operations are performed over Web Services API.
  - Available from R81.10 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  file_path:
    description:
      - Path in which the exported database file is saved.<br><font color="red">Required only</font> when not using pre-export-verification-only flag.
    type: str
  domain_name:
    description:
      - Domain name to be exported.<br><font color="red">Required only for</font> exporting a Domain from the Multi-Domain Server or backing up Domain.
    type: str
  target_version:
    description:
      - Target version.
    type: str
  include_logs:
    description:
      - Export logs without log indexes.
    type: bool
  include_logs_indexes:
    description:
      - Export logs with log indexes.
    type: bool
  include_endpoint_configuration:
    description:
      - Include export of the Endpoint Security Management configuration files.
    type: bool
  include_endpoint_database:
    description:
      - Include export of the Endpoint Security Management database.
    type: bool
  is_domain_backup:
    description:
      - If true, the exported Domain will be suitable for import on the same Multi-Domain Server only.
    type: bool
  is_smc_to_mds:
    description:
      - If true, the exported Security Management Server will be suitable for import on the Multi-Domain Server only.
    type: bool
  pre_export_verification_only:
    description:
      - If true, only runs the pre-export verifications instead of the full export.
    type: bool
  ignore_warnings:
    description:
      - Ignoring the verification warnings. By Setting this parameter to 'true' export will not be blocked by warnings.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: export-management
  cp_mgmt_export_management:
    domain_name: domain1
    file_path: /var/log/domain1_backup.tgz
    is_domain_backup: true
"""

RETURN = """
cp_mgmt_export_management:
  description: The checkpoint export-management output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        file_path=dict(type='str'),
        domain_name=dict(type='str',),
        target_version=dict(type='str'),
        include_logs=dict(type='bool'),
        include_logs_indexes=dict(type='bool'),
        include_endpoint_configuration=dict(type='bool'),
        include_endpoint_database=dict(type='bool'),
        is_domain_backup=dict(type='bool'),
        is_smc_to_mds=dict(type='bool'),
        pre_export_verification_only=dict(type='bool'),
        ignore_warnings=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "export-management"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
