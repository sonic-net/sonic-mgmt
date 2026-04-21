#!/usr/bin/python

# (c) 2020, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage User S3 keys"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_org_user_s3_key
short_description: Creates NetApp StorageGRID User S3 keys.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '20.6.0'
author: NetApp Ansible Team (@joshedmonds) <ng-ansibleteam@netapp.com>
description:
- Create, Delete Users S3 keys on NetApp StorageGRID.
options:
  state:
    description:
    - Whether the specified account should exist or not.
    type: str
    choices: ['present', 'absent']
    default: present
  unique_user_name:
    description:
    - Unique user name owning the S3 Key.
    required: true
    type: str
  expires:
    description:
    - Date-Time string for the key to expire.
    type: str
  access_key:
    description:
    - Access Key or S3 credential pair identifier.
    - Required for delete operation.
    type: str
"""

EXAMPLES = """
- name: create a s3 key
  netapp.storagegrid.na_sg_org_user_s3_key:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    unique_user_name: user/ansibleuser1
"""

RETURN = """
resp:
    description: Returns information about an S3 access key for the user.
    returned: always
    type: dict
    sample: {
        "id": "abcABC_01234-0123456789abcABCabc0123456789==",
        "accountId": 12345678901234567000,
        "displayName": "****************AB12",
        "userURN": "urn:sgws:identity::12345678901234567000:root",
        "userUUID": "00000000-0000-0000-0000-000000000000",
        "expires": "2020-09-04T00:00:00.000Z"
    }
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgOrgUserS3Key(object):
    """
    Create, modify and delete StorageGRID Tenant Account
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
                unique_user_name=dict(required=True, type="str"),
                expires=dict(required=False, type="str"),
                access_key=dict(required=False, type="str", no_log=False),
            )
        )

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "absent", ["access_key"])],
            supports_check_mode=False,
        )

        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Checking for the parameters passed and create new parameters list
        self.data = {}
        self.data["expires"] = self.parameters.get("expires")

    def get_org_user_id(self, unique_name):
        # Use the unique name to check if the user exists
        api = "api/v3/org/users/%s" % unique_name
        response, error = self.rest_api.get(api)

        if error:
            if response["code"] != 404:
                self.module.fail_json(msg=error)
        else:
            return response["data"]["id"]
        return None

    def get_org_user_s3_key(self, user_id, access_key):
        # Use the unique name to check if the user exists
        api = "api/v3/org/users/current-user/s3-access-keys/%s" % access_key

        if user_id:
            api = "api/v3/org/users/%s/s3-access-keys/%s" % (
                user_id,
                access_key,
            )

        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]
        return None

    def create_org_user_s3_key(self, user_id):
        api = "api/v3/org/users/current-user/s3-access-keys"

        if user_id:
            api = "api/v3/org/users/%s/s3-access-keys" % user_id

        response, error = self.rest_api.post(api, self.data)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def delete_org_user_s3_key(self, user_id, access_key):
        api = "api/v3/org/users/current-user/s3-access-keys"

        if user_id:
            api = "api/v3/org/users/%s/s3-access-keys/%s" % (
                user_id,
                access_key,
            )

        self.data = None
        response, error = self.rest_api.delete(api, self.data)
        if error:
            self.module.fail_json(msg=error)

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """
        result_message = ""
        resp_data = {}
        user_id = None

        if self.parameters.get("unique_user_name"):
            user_id = self.get_org_user_id(self.parameters["unique_user_name"])

        if self.parameters["state"] == "present":
            org_user_s3_key = None
            if self.parameters.get("access_key"):
                org_user_s3_key = self.get_org_user_s3_key(user_id, self.parameters["access_key"])
                resp_data = org_user_s3_key

            if not org_user_s3_key:  # create
                resp_data = self.create_org_user_s3_key(user_id)
                self.na_helper.changed = True

        if self.parameters["state"] == "absent":
            self.delete_org_user_s3_key(user_id, self.parameters["access_key"])
            self.na_helper.changed = True
            result_message = "Org User S3 key deleted"

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_org_user_s3_key = SgOrgUserS3Key()
    na_sg_org_user_s3_key.apply()


if __name__ == "__main__":
    main()
