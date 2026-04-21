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
module: cp_mgmt_md_permissions_profile
short_description: Manages md-permissions-profile objects on Checkpoint over Web Services API
description:
  - Manages md-permissions-profile objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R81.20 management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  permission_level:
    description:
      - The level of the Multi Domain Permissions Profile.<br>The level cannot be changed after creation.
    type: str
    choices: ['super user', 'manager', 'domain level only']
  mds_provisioning:
    description:
      - Create and manage Multi-Domain Servers and Multi-Domain Log Servers.<br>Only a "Super User" permission-level profile can select this option.
    type: bool
  manage_admins:
    description:
      - Create and manage Multi-Domain Security Management administrators with the same or lower permission level. For example, a Domain manager
        cannot create Superusers or global managers.<br>Only a 'Manager' permission-level profile can edit this permission.
    type: bool
  manage_sessions:
    description:
      - Connect/disconnect Domain sessions, publish changes, and delete other administrator sessions.<br>Only a 'Manager' permission-level profile can
        edit this permission.
    type: bool
  management_api_login:
    description:
      - Permission to log in to the Security Management Server and run API commands using these tools, mgmt_cli (Linux and Windows binaries), Gaia CLI
        (clish) and Web Services (REST). Useful if you want to prevent administrators from running automatic scripts on the Management.<br>Note, This
        permission is not required to run commands from within the API terminal in SmartConsole.
    type: bool
  cme_operations:
    description:
      - Permission to read / edit the Cloud Management Extension (CME) configuration.
    type: str
    choices: ['read', 'write', 'disabled']
  global_vpn_management:
    description:
      - Lets the administrator select Enable global use for a Security Gateway shown in the MDS Gateways & Servers view.<br>Only a 'Manager'
        permission-level profile can edit this permission.
    type: bool
  manage_global_assignments:
    description:
      - Controls the ability to create, edit and delete global assignment and not the ability to reassign, which is set according to the specific
        Domain's permission profile.
    type: bool
  enable_default_profile_for_global_domains:
    description:
      - Enable the option to specify a default profile for all global domains.
    type: bool
  default_profile_global_domains:
    description:
      - Name or UID of the required default profile for all global domains.
    type: str
  view_global_objects_in_domain:
    description:
      - Lets an administrator with no global objects permissions view the global objects in the domain. This option is required for valid domain management.
    type: bool
  enable_default_profile_for_local_domains:
    description:
      - Enable the option to specify a default profile for all local domains.
    type: bool
  default_profile_local_domains:
    description:
      - Name or UID of the required default profile for all local domains.
    type: str
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
  color:
    description:
      - Color of the object. Should be one of existing colors.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  domains_to_process:
    description:
      - Indicates which domains to process the commands on. It cannot be used with the details-level full, must be run from the System Domain only and
        with ignore-warnings true. Valid values are, CURRENT_DOMAIN, ALL_DOMAINS_ON_THIS_SERVER.
    type: list
    elements: str
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-md-permissions-profile
  cp_mgmt_md_permissions_profile:
    name: manager profile
    state: present

- name: set-md-permissions-profile
  cp_mgmt_md_permissions_profile:
    default_profile_global_domains: read write all
    name: manager profile
    permission_level: domain level only
    state: present

- name: delete-md-permissions-profile
  cp_mgmt_md_permissions_profile:
    name: profile
    state: absent
"""

RETURN = """
cp_mgmt_md_permissions_profile:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_objects,
    api_call,
)


def main():
    argument_spec = dict(
        name=dict(type="str", required=True),
        permission_level=dict(
            type="str", choices=["super user", "manager", "domain level only"]
        ),
        mds_provisioning=dict(type="bool"),
        manage_admins=dict(type="bool"),
        manage_sessions=dict(type="bool"),
        management_api_login=dict(type="bool"),
        cme_operations=dict(type="str", choices=["read", "write", "disabled"]),
        global_vpn_management=dict(type="bool"),
        manage_global_assignments=dict(type="bool"),
        enable_default_profile_for_global_domains=dict(type="bool"),
        default_profile_global_domains=dict(type="str"),
        view_global_objects_in_domain=dict(type="bool"),
        enable_default_profile_for_local_domains=dict(type="bool"),
        default_profile_local_domains=dict(type="str"),
        tags=dict(type="list", elements="str"),
        color=dict(
            type="str",
            choices=[
                "aquamarine",
                "black",
                "blue",
                "crete blue",
                "burlywood",
                "cyan",
                "dark green",
                "khaki",
                "orchid",
                "dark orange",
                "dark sea green",
                "pink",
                "turquoise",
                "dark blue",
                "firebrick",
                "brown",
                "forest green",
                "gold",
                "dark gold",
                "gray",
                "dark gray",
                "light green",
                "lemon chiffon",
                "coral",
                "sea green",
                "sky blue",
                "magenta",
                "purple",
                "slate blue",
                "violet red",
                "navy blue",
                "olive",
                "orange",
                "red",
                "sienna",
                "yellow",
            ],
        ),
        comments=dict(type="str"),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
        domains_to_process=dict(type="list", elements="str"),
        ignore_warnings=dict(type="bool"),
        ignore_errors=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )
    api_call_object = "md-permissions-profile"

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
