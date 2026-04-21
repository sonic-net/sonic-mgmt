#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 T-Systems MMS
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
---
module: mongodb_atlas_ldap_user
short_description: Manage LDAP users in Atlas
description:
  - The mongodb_atlas_ldap_user module lets you create LDAP groups on the admin database by mapping LDAP groups to MongoDB roles on your Atlas databases.
  - Each user or group has a set of roles that provide access to the project's databases.
  - L(API Documentation,https://docs.atlas.mongodb.com/security-ldaps/)
author: "Martin Schurz (@schurzi) / Derek Giri"
extends_documentation_fragment: community.mongodb.atlas_options
options:
  database_name:
    description:
      - Database against which Atlas authenticates the user.
    choices: ["admin", "$external"]
    default: "admin"
    type: str
    aliases: [ "databaseName" ]
  ldap_auth_type:
    description:
      - Type of LDAP authorization for the user i.e. USER or GROUP
    choices: ["GROUP", "USER"]
    default: "GROUP"
    type: str
    aliases: [ "ldapAuthType" ]
  username:
    description:
      - Username for authenticating to MongoDB.
    required: true
    type: str
  roles:
    description:
      - Array of this user's roles and the databases / collections on which the roles apply.
      - A role must include folliwing elements
    suboptions:
      database_name:
        required: true
        type: str
        description:
          - Database on which the user has the specified role.
          - A role on the admin database can include privileges that apply to the other databases.
        aliases: [ "databaseName" ]
      role_name:
        required: true
        type: str
        description:
          - Name of the role. This value can either be a built-in role or a custom role.
        aliases: ["roleName" ]
    required: true
    type: list
    elements: dict
'''

EXAMPLES = '''
    - name: LDAP Group or Username
      community.mongodb.mongodb_atlas_ldap_user:
        api_username: "API_user"
        api_password: "API_passwort_or_token"
        atlas_ldap_user: "USER DN or GROUP DN"
        group_id: "GROUP_ID"
        database_name: "admin"
        username: my_app_user
        roles:
          - database_name: private_info
            role_name: read
          - database_name: public_info
            role_name: readWrite
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.mongodb.plugins.module_utils.mongodb_atlas import (
    AtlasAPIObject,
)


# ===========================================
# Module execution.
#
def main():
    # add our own arguments
    argument_spec = dict(
        state=dict(default="present", choices=["absent", "present"]),
        api_username=dict(required=True, aliases=['apiUsername']),
        api_password=dict(required=True, no_log=True, aliases=['apiPassword']),
        group_id=dict(required=True, aliases=['groupId']),
        ldap_auth_type=dict(default="GROUP", choices=["GROUP", "USER"], aliases=["ldapAuthType"]),
        database_name=dict(default="admin", choices=["admin", "$external"], aliases=["databaseName"]),
        username=dict(required=True),
        roles=dict(
            required=True,
            type="list",
            elements="dict",
            options=dict(
                database_name=dict(required=True, aliases=["databaseName"]),
                role_name=dict(required=True, aliases=["roleName"]),
            ),
        ),
    )

    # Define the main module
    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )

    data = {
        "databaseName": module.params["database_name"],
        "ldapAuthType": module.params["ldap_auth_type"],
        "username": module.params["username"],
        "roles": [],
    }

    # remap keys to API format
    for role in module.params.get("roles"):
        data["roles"].append({
            "databaseName": role.get("database_name"),
            "roleName": role.get("role_name")
        })

    try:
        atlas = AtlasAPIObject(
            module=module,
            path="/databaseUsers",
            object_name="username",
            group_id=module.params["group_id"],
            data=data,
        )
    except Exception as e:
        module.fail_json(
            msg="unable to connect to Atlas API. Exception message: %s" % e
        )

    changed, diff = atlas.update(module.params["state"])
    module.exit_json(
        changed=changed,
        data=atlas.data,
        diff=diff,
    )


# import module snippets
if __name__ == "__main__":
    main()
