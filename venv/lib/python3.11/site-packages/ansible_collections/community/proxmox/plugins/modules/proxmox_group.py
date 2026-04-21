#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025, Jeffrey van Pelt (@Thulium-Drake) <jeff@vanpelt.one>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-FileCopyrightText: (c) 2025, Jeffrey van Pelt (Thulium-Drake) <jeff@vanpelt.one>
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_group
short_description: Group management for Proxmox VE cluster
description:
  - Create or delete a user group for Proxmox VE clusters.
author: "Jeffrey van Pelt (@Thulium-Drake) <jeff@vanpelt.one>"
version_added: "1.2.0"
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
options:
  groupid:
    description:
      - The group name.
    type: str
    aliases: ["name"]
    required: true
  state:
    description:
      - Indicate desired state of the group.
    choices: ['present', 'absent']
    default: present
    type: str
  comment:
    description:
      - Specify the description for the group.
      - Parameter is ignored when group already exists or O(state=absent).
    type: str

extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
"""

EXAMPLES = r"""
- name: Create new Proxmox VE user group
  community.proxmox.proxmox_group:
    api_host: node1
    api_user: root@pam
    api_password: password
    name: administrators
    comment: IT Admins

- name: Delete a Proxmox VE user group
  community.proxmox.proxmox_group:
    api_host: node1
    api_user: root@pam
    api_password: password
    name: administrators
    state: absent
"""

RETURN = r"""
groupid:
  description: The group name.
  returned: success
  type: str
  sample: test
msg:
  description: A short message on what the module did.
  returned: always
  type: str
  sample: "Group administrators successfully created"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (proxmox_auth_argument_spec, ProxmoxAnsible)


class ProxmoxGroupAnsible(ProxmoxAnsible):

    def is_group_existing(self, groupid):
        """Check whether group already exist

        :param groupid: str - name of the group
        :return: bool - is group exists?
        """
        try:
            groups = self.proxmox_api.access.groups.get()
            for group in groups:
                if group['groupid'] == groupid:
                    return True
            return False
        except Exception as e:
            self.module.fail_json(msg="Unable to retrieve groups: {0}".format(e))

    def create_group(self, groupid, comment=None):
        """Create Proxmox VE group

        :param groupid: str - name of the group
        :param comment: str, optional - Description of a group
        :return: None
        """
        if self.is_group_existing(groupid):
            self.module.exit_json(changed=False, groupid=groupid, msg="Group {0} already exists".format(groupid))

        if self.module.check_mode:
            return

        try:
            self.proxmox_api.access.groups.post(groupid=groupid, comment=comment)
        except Exception as e:
            self.module.fail_json(msg="Failed to create group with ID {0}: {1}".format(groupid, e))

    def delete_group(self, groupid):
        """Delete Proxmox VE group

        :param groupid: str - name of the group
        :return: None
        """
        if not self.is_group_existing(groupid):
            self.module.exit_json(changed=False, groupid=groupid, msg="Group {0} doesn't exist".format(groupid))

        if self.module.check_mode:
            return

        try:
            self.proxmox_api.access.groups(groupid).delete()
        except Exception as e:
            self.module.fail_json(msg="Failed to delete group with ID {0}: {1}".format(groupid, e))


def main():
    module_args = proxmox_auth_argument_spec()
    groups_args = dict(
        groupid=dict(type="str", aliases=["name"], required=True),
        comment=dict(type="str"),
        state=dict(default="present", choices=["present", "absent"]),
    )

    module_args.update(groups_args)

    module = AnsibleModule(
        argument_spec=module_args,
        required_together=[("api_token_id", "api_token_secret")],
        required_one_of=[("api_password", "api_token_id")],
        supports_check_mode=True
    )

    groupid = module.params["groupid"]
    comment = module.params["comment"]
    state = module.params["state"]

    proxmox = ProxmoxGroupAnsible(module)

    if state == "present":
        proxmox.create_group(groupid, comment)
        module.exit_json(changed=True, groupid=groupid, msg="Group {0} successfully created".format(groupid))
    else:
        proxmox.delete_group(groupid)
        module.exit_json(changed=True, groupid=groupid, msg="Group {0} successfully deleted".format(groupid))


if __name__ == "__main__":
    main()
