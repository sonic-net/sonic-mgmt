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
module: cp_mgmt_show_azure_ad_content
short_description: Retrieve AzureAD Objects from Azure AD Server.
description:
  - Retrieve AzureAD Objects from Azure AD Server.
  - All operations are performed over Web Services API.
  - Available from R81 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  azure_ad_name:
    description:
      - Name of the Azure AD Server where to search for objects.
    type: str
  azure_ad_uid:
    description:
      - Unique identifier of the Azure AD Server where to search for objects.
    type: str
  limit:
    description:
      - The maximal number of returned results.
    type: int
  offset:
    description:
      - Number of the results to initially skip.
    type: int
  order:
    description:
      - Sorts the results by search criteria. Automatically sorts the results by Name, in the ascending order.
    type: list
    elements: dict
    suboptions:
      ASC:
        description:
          - Sorts results by the given field in ascending order.
        type: str
        choices: ['name']
      DESC:
        description:
          - Sorts results by the given field in descending order.
        type: str
        choices: ['name']
  uid_in_azure_ad:
    description:
      - Return result matching the unique identifier of the object on the Azure AD Server.
    type: str
  filter:
    description:
      - Return results matching the specified filter.
    type: dict
    suboptions:
      text:
        description:
          - Return results containing the specified text value.
        type: str
      uri:
        description:
          - Return results under the specified Data Center Object (identified by URI).
        type: str
      parent_uid_in_data_center:
        description:
          - Return results under the specified Data Center Object (identified by UID).
        type: str
  details_level:
    description:
      - Standard and Full description are the same.
    type: str
    choices: ['uid', 'standard', 'full']
  domains_to_process:
    description:
      - Indicates which domains to process the commands on. It cannot be used with the details-level full, must be run from the System Domain only and
        with ignore-warnings true. Valid values are, CURRENT_DOMAIN, ALL_DOMAINS_ON_THIS_SERVER.
    type: list
    elements: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: show-azure-ad-content
  cp_mgmt_show_azure_ad_content:
    name: my_azureAD
"""

RETURN = """
cp_mgmt_show_azure_ad_content:
  description: The checkpoint show-azure-ad-content output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        azure_ad_name=dict(type='str'),
        azure_ad_uid=dict(type='str'),
        limit=dict(type='int'),
        offset=dict(type='int'),
        order=dict(type='list', elements='dict', options=dict(
            ASC=dict(type='str', choices=['name']),
            DESC=dict(type='str', choices=['name'])
        )),
        uid_in_azure_ad=dict(type='str'),
        filter=dict(type='dict', options=dict(
            text=dict(type='str'),
            uri=dict(type='str'),
            parent_uid_in_data_center=dict(type='str')
        )),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        domains_to_process=dict(type='list', elements='str')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "show-azure-ad-content"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
