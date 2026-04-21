#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_user
short_description: Manage users
description:
- Manage users on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
options:
  user:
    description:
    - The name of the user.
    type: str
    aliases: [ name ]
  user_password:
    description:
    - The password of the user.
    type: str
  first_name:
    description:
    - The first name of the user.
    - This parameter is required when creating new users.
    type: str
  last_name:
    description:
    - The last name of the user.
    - This parameter is required when creating new users.
    type: str
  email:
    description:
    - The email address of the user.
    - This parameter is required when creating new users.
    type: str
  phone:
    description:
    - The phone number of the user.
    - This parameter is required when creating new users.
    type: str
  account_status:
    description:
    - The status of the user account.
    type: str
    choices: [ active, inactive ]
  domain:
    description:
    - The domain this user belongs to.
    - When creating new users, this defaults to C(Local).
    type: str
  roles:
    description:
    - The roles for this user and their access types (read or write).
    - Access type defaults to C(write).
    type: list
    elements: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- A default installation of ACI Multi-Site ships with admin password 'we1come!' which requires a password change on first login.
  See the examples of how to change the 'admin' password using Ansible.
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Update initial admin password
  cisco.mso.mso_user:
    host: mso_host
    username: admin
    password: initialPassword
    validate_certs: false
    user: admin
    user_password: newPassword
    state: present

- name: Add a new user
  cisco.mso.mso_user:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    user: dag
    user_password: userPassword
    first_name: Dag
    last_name: Wieers
    email: dag@wieers.com
    phone: +32 478 436 299
    roles:
      - name: siteManager
        access_type: write
      - name: schemaManager
        access_type: read
    state: present

- name: Add a new user
  cisco.mso.mso_user:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    user: dag
    first_name: Dag
    last_name: Wieers
    email: dag@wieers.com
    phone: +32 478 436 299
    roles:
      - powerUser

- name: Remove a user
  cisco.mso.mso_user:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    user: dag
    state: absent

- name: Query a user
  cisco.mso.mso_user:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    user: dag
    state: query
  register: query_result

- name: Query all users
  cisco.mso.mso_user:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    state: query
  register: query_result
"""

RETURN = r""" # """

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, issubset


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        user=dict(type="str", aliases=["name"]),
        user_password=dict(type="str", no_log=True),
        first_name=dict(type="str"),
        last_name=dict(type="str"),
        email=dict(type="str"),
        phone=dict(type="str"),
        # TODO: What possible options do we have ?
        account_status=dict(type="str", choices=["active", "inactive"]),
        domain=dict(type="str"),
        roles=dict(type="list", elements="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["user"]],
            ["state", "present", ["user"]],
        ],
    )

    user_name = module.params.get("user")
    user_password = module.params.get("user_password")
    first_name = module.params.get("first_name")
    last_name = module.params.get("last_name")
    email = module.params.get("email")
    phone = module.params.get("phone")
    account_status = module.params.get("account_status")
    state = module.params.get("state")

    mso = MSOModule(module)

    roles = mso.lookup_roles(module.params.get("roles"))
    domain = mso.lookup_domain(module.params.get("domain"))

    user_id = None
    path = "users"

    # Query for existing object(s)
    if user_name:
        if mso.module._socket_path and mso.connection.get_platform() == "cisco.nd":
            mso.existing = mso.get_obj(path, loginID=user_name, api_version="v2")
            if mso.existing:
                mso.existing["id"] = mso.existing.get("userID")
                mso.existing["username"] = mso.existing.get("loginID")
        else:
            mso.existing = mso.get_obj(path, username=user_name)
        if mso.existing:
            user_id = mso.existing.get("id")
            # If we found an existing object, continue with it
            path = "users/{id}".format(id=user_id)
    else:
        mso.existing = mso.query_objs(path)

    if state == "query":
        pass

    elif state == "absent":
        mso.previous = mso.existing
        if mso.existing:
            if module.check_mode:
                mso.existing = {}
            else:
                mso.existing = mso.request(path, method="DELETE")

    elif state == "present":
        mso.previous = mso.existing

        payload = dict(
            id=user_id,
            username=user_name,
            firstName=first_name,
            lastName=last_name,
            emailAddress=email,
            phoneNumber=phone,
            accountStatus=account_status,
            domainId=domain,
            roles=roles,
            # active=True,
            # remote=True,
        )

        if user_password is not None:
            payload.update(password=user_password)

        mso.sanitize(payload, collate=True)

        if mso.sent.get("accountStatus") is None:
            mso.sent["accountStatus"] = "active"

        if mso.existing:
            if not issubset(mso.sent, mso.existing):
                # NOTE: Since MSO always returns '******' as password, we need to assume a change
                if "password" in mso.proposed:
                    mso.module.warn("A password change is assumed, as the MSO REST API does not return passwords we do not know.")
                    mso.result["changed"] = True

                if module.check_mode:
                    mso.existing = mso.proposed
                else:
                    mso.existing = mso.request(path, method="PUT", data=mso.sent)

        else:
            if user_password is None:
                mso.fail_json("The user {0} does not exist. The 'user_password' attribute is required to create a new user.".format(user_name))
            if module.check_mode:
                mso.existing = mso.proposed
            else:
                mso.existing = mso.request(path, method="POST", data=mso.sent)

    mso.exit_json()


if __name__ == "__main__":
    main()
