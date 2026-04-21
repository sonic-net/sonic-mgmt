#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025, Jeffrey van Pelt (@Thulium-Drake) <jeff@vanpelt.one>
# Copyright (c) 2025, Kevin Quick <kevin@overwrite.io>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-FileCopyrightText: (c) 2025, Jeffrey van Pelt (@Thulium-Drake) <jeff@vanpelt.one>
# SPDX-FileCopyrightText: (c) 2025, Kevin Quick <kevin@overwrite.io>
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_user
short_description: User management for Proxmox VE cluster
description:
  - Create or delete a user for Proxmox VE clusters.
author:
  - Jeffrey van Pelt (@Thulium-Drake)
  - Kevin Quick (@kevinquick)
version_added: "1.2.0"
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
options:
  userid:
    description:
      - The user name.
      - Must include the desired PVE authentication realm.
    type: str
    aliases: ["name"]
    required: true
  state:
    description:
      - Indicate desired state of the user.
    choices: ['present', 'absent']
    default: present
    type: str
  comment:
    description:
      - Specify the description for the user.
    type: str
  enable:
    description:
      - Whether or not the account is active.
    type: bool
    default: true
  email:
    description:
      - Email address for the user.
    type: str
  expire:
    description:
      - Expiration date of the user in seconds after epoch.
      - 0 means no expiration date.
    type: int
    default: 0
  firstname:
    description:
      - First name of the user.
    type: str
  lastname:
    description:
      - Last name of the user.
    type: str
  groups:
    description:
      - List of groups the user is a member of.
    type: list
    elements: str
  keys:
    description:
      - Keys for two factor authentication (yubico).
    type: str
  password:
    description:
      - Initial password.
      - Only for PVE Authentication Realm users.
      - Parameter is ignored when user already exists or O(state=absent).
    type: str

extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
"""

EXAMPLES = r"""
- name: Create new Proxmox VE user
  community.proxmox.proxmox_user:
    api_host: node1
    api_user: root@pam
    api_password: password
    name: user@pve
    comment: Expires on 2026-01-01 00:00:00
    email: user@example.nl
    enable: true
    expire: 1767222000
    firstname: User
    groups:
      - admins
    password: GoBananas!
    lastname: Some Guy

- name: Delete a Proxmox VE user
  community.proxmox.proxmox_user:
    api_host: node1
    api_user: root@pam
    api_password: password
    name: user@pve
    state: absent
"""

RETURN = r"""
userid:
  description: The user name.
  returned: success
  type: str
  sample: test
msg:
  description: A short message on what the module did.
  returned: always
  type: str
  sample: "User administrators successfully created"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (
    proxmox_auth_argument_spec, ProxmoxAnsible)


class ProxmoxUserAnsible(ProxmoxAnsible):

    def is_user_existing(self, userid):
        """Check whether user already exist

        :param userid: str - name of the user
        :return: dict|bool - user data if exists, False otherwise
        """
        try:
            user_data = self.proxmox_api.access.users(userid).get()
            return user_data
        except Exception as e:
            if "does not exist" in str(e).lower() or "not found" in str(e).lower() or "no such user" in str(e).lower():
                return False
            else:
                self.module.fail_json(msg="Unable to retrieve user {0}: {1}".format(userid, e))

    def _user_needs_update(self, existing_user, comment, email, enable, expire, firstname, lastname, groups, keys):
        """Check if user needs updating by comparing current vs desired state"""
        # Check standard fields
        fields = [('comment', comment, ''), ('email', email, ''), ('enable', enable, 1),
                  ('expire', expire, 0), ('firstname', firstname, ''),
                  ('lastname', lastname, ''), ('keys', keys, '')]

        for field, new_value, default in fields:
            if new_value is not None and existing_user.get(field, default) != new_value:
                return True

        # Check groups (API returns list, we send comma-separated string)
        if groups is not None:
            existing_groups_str = ','.join(existing_user.get('groups', []))
            if existing_groups_str != groups:
                return True

        return False

    def create_update_user(self, userid, comment=None, email=None, enable=True, expire=0,
                           firstname=None, groups=None, password=None, keys=None,
                           lastname=None):
        """Create or update Proxmox VE user

        :param userid: str - name of the user
        :param comment: str, optional - Description of a user
        :param email: str, optional - Email of the user
        :param enable: bool, optional - Whether or not user is active
        :param expire: str, optional - Expiration date of the user
        :param firstname: str, optional - First name of the user
        :param groups: list, optional - Groups that the user should be a member of
        :param password: str, optional - Password of the user, PVE realm only
        :param keys: str, optional - 2FA keys for the user
        :param lastname: str, optional - Lastname of the user
        :return: None
        """
        # Translate input to make API happy
        enable = int(enable)
        groups = ','.join(groups) if groups else None
        existing_user = self.is_user_existing(userid)
        if existing_user:
            needs_update = self._user_needs_update(existing_user, comment, email, enable, expire,
                                                   firstname, lastname, groups, keys)
            if not needs_update and not password:
                self.module.exit_json(changed=False, userid=userid, msg="User {0} already up to date".format(userid))
            if self.module.check_mode:
                self.module.exit_json(changed=needs_update or bool(password), userid=userid,
                                      msg="Would update {0} (check mode)".format(userid))

            if needs_update:
                try:
                    # Build update parameters - only include non-None values
                    update_params = {'enable': enable}
                    for field, value in [('comment', comment), ('email', email), ('expire', expire),
                                         ('firstname', firstname), ('lastname', lastname),
                                         ('groups', groups), ('keys', keys)]:
                        if value is not None:
                            update_params[field] = value
                    self.proxmox_api.access.users(userid).put(**update_params)
                    self.module.exit_json(changed=True, userid=userid, msg="User {0} updated".format(userid))
                except Exception as e:
                    self.module.fail_json(changed=False, userid=userid,
                                          msg="Failed to update user with ID {0}: {1}".format(userid, e))

            # We have no way of testing if the user's password needs to be changed
            # so, if it's provided we will update it anyway
            if password:
                try:
                    self.proxmox_api.access.password.put(userid=userid, password=password)
                    self.module.exit_json(changed=True, userid=userid, msg="User {0} updated".format(userid))
                except Exception as e:
                    self.module.fail_json(changed=False, userid=userid,
                                          msg="Failed to update user password for user ID {0}: {1}".format(userid, e))

        if self.module.check_mode:
            self.module.exit_json(changed=True, userid=userid, msg="Would create user {0} (check mode)".format(userid))

        # if the user is new, post it to the API
        try:
            self.proxmox_api.access.users.post(userid=userid,
                                               comment=comment,
                                               email=email,
                                               enable=enable,
                                               expire=expire,
                                               firstname=firstname,
                                               groups=groups,
                                               password=password,
                                               keys=keys,
                                               lastname=lastname)
            self.module.exit_json(changed=True, userid=userid, msg="Created user {0}".format(userid))
        except Exception as e:
            self.module.fail_json(msg="Failed to create user with ID {0}: {1}".format(userid, e))

    def delete_user(self, userid):
        """Delete Proxmox VE user

        :param userid: str - name of the user
        :return: None
        """
        if not self.is_user_existing(userid):
            self.module.exit_json(changed=False, userid=userid, msg="User {0} doesn't exist".format(userid))

        if self.module.check_mode:
            self.module.exit_json(changed=False, userid=userid,
                                  msg="Would deleted user with ID {0} (check mode)".format(userid))

        try:
            self.proxmox_api.access.users(userid).delete()
            self.module.exit_json(changed=True, userid=userid, msg="Deleted user with ID {0}".format(userid))
        except Exception as e:
            self.module.fail_json(msg="Failed to delete user with ID {0}: {1}".format(userid, e))


def main():
    module_args = proxmox_auth_argument_spec()
    users_args = dict(
        userid=dict(type="str", aliases=["name"], required=True),
        comment=dict(type="str"),
        email=dict(type="str"),
        enable=dict(default=True, type="bool"),
        expire=dict(default=0, type="int"),
        firstname=dict(type="str"),
        groups=dict(type="list", elements="str"),
        lastname=dict(type="str"),
        keys=dict(type="str", no_log=True),
        password=dict(type="str", no_log=True),
        state=dict(default="present", choices=["present", "absent"]),
    )

    module_args.update(users_args)

    module = AnsibleModule(
        argument_spec=module_args,
        required_together=[("api_token_id", "api_token_secret")],
        required_one_of=[("api_password", "api_token_id")],
        supports_check_mode=True
    )

    userid = module.params["userid"]
    comment = module.params["comment"]
    email = module.params["email"]
    enable = module.params["enable"]
    expire = module.params["expire"]
    firstname = module.params["firstname"]
    groups = module.params["groups"]
    lastname = module.params["lastname"]
    keys = module.params["keys"]
    password = module.params["password"]
    state = module.params["state"]

    proxmox = ProxmoxUserAnsible(module)

    # Convert empty strings to None for proper comparison
    for param in ['comment', 'email', 'firstname', 'lastname', 'keys']:
        if locals()[param] == "":
            locals()[param] = None

    if state == "present":
        proxmox.create_update_user(userid, comment, email, enable, expire, firstname, groups, password, keys, lastname)
    else:
        proxmox.delete_user(userid)


if __name__ == "__main__":
    main()
