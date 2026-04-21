#!/usr/bin/python

# (c) 2020, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Grid-administration Users"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_user
short_description: NetApp StorageGRID manage users.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '20.6.0'
author: NetApp Ansible Team (@joshedmonds) <ng-ansibleteam@netapp.com>
description:
- Create, Update, Delete Administrative Users within NetApp StorageGRID.
options:
  state:
    description:
    - Whether the specified user should exist or not.
    type: str
    choices: ['present', 'absent']
    default: present
  full_name:
    description:
    - Full Name of the user.
    - Required for create operation
    type: str
  unique_name:
    description:
    - Unique Name for the user. Must begin with C(user/) or C(federated-user/)
    - Required for create, modify or delete operation.
    type: str
    required: true
  member_of:
    description:
    - List of C(unique_groups) that the user is a member of.
    type: list
    elements: str
  password:
    description:
    - Set a password for a local user. Does not apply to federated users.
    - Requires root privilege.
    required: false
    type: str
  update_password:
    description:
    - Choose when to update the password.
    - When set to C(always), the password will always be updated.
    - When set to C(on_create), the password will only be set upon a new user creation.
    default: on_create
    choices:
    - on_create
    - always
    type: str
  disable:
    description:
    - Disable the user from signing in. Does not apply to federated users.
    type: bool
"""

EXAMPLES = """
- name: create a user
  netapp.storagegrid.na_sg_grid_user:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    full_name: ansibleuser100
    unique_name: user/ansibleuser100
    member_of: "group/ansiblegroup100"
    disable: false
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID Grid user.
    returned: always
    type: dict
    sample: {
        "fullName": "Example User",
        "memberOf": ["00000000-0000-0000-0000-000000000000"],
        "disable": false,
        "uniqueName": "user/Example",
        "accountId": "0",
        "id": "00000000-0000-0000-0000-000000000000",
        "federated": false,
        "userURN": "urn:sgws:identity::0:user/Example"
    }
"""

import re

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgGridUser(object):
    """
    Create, modify and delete user within a StorageGRID Tenant Account
    """

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.na_storagegrid_host_argument_spec()
        self.argument_spec.update(
            dict(
                state=dict(required=False, type="str", choices=["present", "absent"], default="present"),
                full_name=dict(required=False, type="str"),
                unique_name=dict(required=True, type="str"),
                member_of=dict(required=False, type="list", elements="str"),
                disable=dict(required=False, type="bool"),
                password=dict(required=False, type="str", no_log=True),
                update_password=dict(default="on_create", choices=["on_create", "always"]),
            )
        )

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "present", ["full_name", "unique_name"])],
            supports_check_mode=True,
        )

        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Checking for the parameters passed and create new parameters list
        self.data = {}
        self.data["memberOf"] = []
        if self.parameters.get("full_name"):
            self.data["fullName"] = self.parameters["full_name"]
        if self.parameters.get("unique_name"):
            self.data["uniqueName"] = self.parameters["unique_name"]

        if self.parameters.get("disable") is not None:
            self.data["disable"] = self.parameters["disable"]

        re_local_user = re.compile("^user/")
        re_fed_user = re.compile("^federated-user/")

        if (
            re_local_user.match(self.parameters["unique_name"]) is None
            and re_fed_user.match(self.parameters["unique_name"]) is None
        ):
            self.module.fail_json(msg="unique_name must begin with 'user/' or 'federated-user/'")

        self.pw_change = {}
        if self.parameters.get("password") is not None:
            if re_fed_user.match(self.parameters["unique_name"]):
                self.module.fail_json(msg="password cannot be set for a federated user")
            self.pw_change["password"] = self.parameters["password"]

    def get_grid_groups(self):
        # Get list of admin groups
        # Retrun mapping of uniqueName to ids if found, or None
        api = "api/v3/grid/groups?limit=350"

        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        if response["data"]:
            name_to_id_map = dict(zip([i["uniqueName"] for i in response["data"]], [j["id"] for j in response["data"]]))
            return name_to_id_map

        return None

    def get_grid_user(self, unique_name):
        # Use the unique name to check if the user exists
        api = "api/v3/grid/users/%s" % unique_name
        response, error = self.rest_api.get(api)

        if error:
            if response["code"] != 404:
                self.module.fail_json(msg=error["text"])
        else:
            return response["data"]
        return None

    def create_grid_user(self):
        api = "api/v3/grid/users"

        response, error = self.rest_api.post(api, self.data)

        if error:
            self.module.fail_json(msg=error["text"])

        return response["data"]

    def delete_grid_user(self, user_id):
        api = "api/v3/grid/users/" + user_id

        self.data = None
        response, error = self.rest_api.delete(api, self.data)
        if error:
            self.module.fail_json(msg=error)

    def update_grid_user(self, user_id):
        api = "api/v3/grid/users/" + user_id

        response, error = self.rest_api.put(api, self.data)
        if error:
            self.module.fail_json(msg=error["text"])

        return response["data"]

    def set_grid_user_password(self, unique_name):
        api = "api/v3/grid/users/%s/change-password" % unique_name
        response, error = self.rest_api.post(api, self.pw_change)

        if error:
            self.module.fail_json(msg=error["text"])

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """
        grid_user = self.get_grid_user(self.parameters["unique_name"])

        if self.parameters.get("member_of"):
            grid_groups = self.get_grid_groups()
            try:
                self.data["memberOf"] = [grid_groups[x] for x in self.parameters["member_of"]]
            except KeyError as e:
                self.module.fail_json(msg="Invalid unique_group supplied: '%s' not found" % e.args[0])

        cd_action = self.na_helper.get_cd_action(grid_user, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            update = False

            if grid_user["memberOf"] is None:
                member_of_diff = []
            else:
                member_of_diff = [
                    i
                    for i in self.data["memberOf"] + grid_user["memberOf"]
                    if i not in self.data["memberOf"] or i not in grid_user["memberOf"]
                ]
            if member_of_diff:
                update = True

            if self.parameters.get("disable") is not None and self.parameters["disable"] != grid_user.get("disable"):
                update = True

            if update:
                self.na_helper.changed = True
        result_message = ""
        resp_data = grid_user
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == "delete":
                    self.delete_grid_user(grid_user["id"])
                    result_message = "Grid User deleted"

                elif cd_action == "create":
                    resp_data = self.create_grid_user()
                    result_message = "Grid User created"

                else:
                    resp_data = self.update_grid_user(grid_user["id"])
                    result_message = "Grid User updated"

        # If a password has been set
        if self.pw_change:
            if self.module.check_mode:
                pass
            else:
                # Only update the password if update_password is always, or a create activity has occurred
                if cd_action == "create" or self.parameters["update_password"] == "always":
                    self.set_grid_user_password(self.parameters["unique_name"])
                    self.na_helper.changed = True

                    results = [result_message, "Grid User password updated"]
                    result_message = "; ".join(filter(None, results))

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_user = SgGridUser()
    na_sg_grid_user.apply()


if __name__ == "__main__":
    main()
