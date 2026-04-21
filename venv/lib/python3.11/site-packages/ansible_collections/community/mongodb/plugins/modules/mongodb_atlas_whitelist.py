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
module: mongodb_atlas_whitelist
short_description: Manage IP whitelists in Atlas
description:
  - The mongodb_atlas_whitelist module manages a Atlas project's IP whitelist.
  - L(API Documentation,https://docs.atlas.mongodb.com/reference/api/whitelist/)
author: "Martin Schurz (@schurzi)"
extends_documentation_fragment: community.mongodb.atlas_options
options:
  cidr_block:
    description:
      - Whitelist entry in Classless Inter-Domain Routing (CIDR) notation.
    type: str
    required: True
    aliases: [ "cidrBlock" ]
  comment:
    description:
      - Optional Comment associated with the whitelist entry.
    type: str
    default: "created by Ansible"
'''

EXAMPLES = '''
    - name: test whitelist
      community.mongodb.mongodb_atlas_whitelist:
        api_username: "API_user"
        api_password: "API_passwort_or_token"
        group_id: "GROUP_ID"
        cidr_block: "192.168.0.0/24"
        comment: "test"
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
        cidr_block=dict(required=True, aliases=["cidrBlock"]),
        comment=dict(default="created by Ansible"),
    )

    # Define the main module
    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )

    data = {
        "cidrBlock": module.params["cidr_block"],
        "comment": module.params["comment"],
    }

    try:
        atlas = AtlasAPIObject(
            module=module,
            path="/whitelist",
            object_name="cidrBlock",
            group_id=module.params["group_id"],
            data=data,
            data_is_array=True,
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
