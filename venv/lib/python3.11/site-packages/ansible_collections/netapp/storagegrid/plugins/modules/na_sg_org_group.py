#!/usr/bin/python

# (c) 2020, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage tenant Groups"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_org_group
short_description: NetApp StorageGRID manage groups within a tenancy.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '20.6.0'
author: NetApp Ansible Team (@joshedmonds) <ng-ansibleteam@netapp.com>
description:
- Create, Update, Delete Groups within NetApp StorageGRID tenant.
options:
  state:
    description:
    - Whether the specified group should exist or not.
    type: str
    choices: ['present', 'absent']
    default: present
  unique_name:
    description:
    - Unique Name for the group. Must begin with C(group/) or C(federated-group/).
    - Required for create, modify or delete operation.
    type: str
    required: true
  display_name:
    description:
    - Name of the group.
    - Required for create operation.
    type: str
  read_only:
    description:
    - Users can view settings and features but cannot make changes or perform operations.
    type: bool
    version_added: '21.14.0'
  management_policy:
    description:
    - Management access controls granted to the group within the tenancy.
    type: dict
    suboptions:
      manage_all_containers:
        description:
        - Allows users to manage the settings for all S3 buckets in the tenant account, regardless of S3 bucket or group policies.
        type: bool
      manage_endpoints:
        description:
        - Allows users to use the Tenant Manager or the Tenant Management API to create or edit endpoints.
        - Endpoints are used as the destination for StorageGRID platform services.
        type: bool
      manage_own_s3_credentials:
        description:
        - Allows users to create and remove their own S3 access keys.
        - Users who do not have this permission do not see the S3 > My Credentials menu option.
        type: bool
      root_access:
        description:
        - Provides full access to the Tenant Manager and the Tenant Management API.
        type: bool
  s3_policy:
    description:
    - StorageGRID S3 Group Policy.
    type: json
"""

EXAMPLES = """
- name: create a group
  netapp.storagegrid.na_sg_org_group:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    display_name: ansiblegroup1
    unique_name: group/ansiblegroup1
    management_policy:
    manage_all_containers: true
    manage_endpoints: true
    manage_own_s3_credentials: false
    root_access: false
    s3_policy: {"Statement":[{"Effect":"Deny", "Action":"s3:*", "Resource":"arn:aws:s3:::*"}]}
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID tenant group attributes.
    returned: success
    type: dict
    sample: {
        "displayName": "Example Group",
        "policies": {
            "management": {
                "manageAllContainers": true,
                "manageEndpoints": true,
                "manageOwnS3Credentials": true,
                "rootAccess": true
            },
            "s3": {...},
            "swift": {...}
        },
        "uniqueName": "group/examplegroup",
        "accountId": "12345678901234567890",
        "id": "00000000-0000-0000-0000-000000000000",
        "federated": false,
        "groupURN": "urn:sgws:identity::12345678901234567890:group/examplegroup"
    }
"""

import json
import re

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgOrgGroup(object):
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
                display_name=dict(required=False, type="str"),
                unique_name=dict(required=True, type="str"),
                read_only=dict(required=False, type="bool"),
                management_policy=dict(
                    required=False,
                    type="dict",
                    options=dict(
                        manage_all_containers=dict(required=False, type="bool"),
                        manage_endpoints=dict(required=False, type="bool"),
                        manage_own_s3_credentials=dict(required=False, type="bool"),
                        root_access=dict(required=False, type="bool"),
                    ),
                ),
                s3_policy=dict(required=False, type="json"),
            )
        )
        parameter_map = {
            "manage_all_containers": "manageAllContainers",
            "manage_endpoints": "manageEndpoints",
            "manage_own_s3_credentials": "manageOwnS3Credentials",
            "root_access": "rootAccess",
        }
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            # required_if=[("state", "present", ["display_name"])],
            supports_check_mode=True,
        )

        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Checking for the parameters passed and create new parameters list
        self.data = {}
        self.data["displayName"] = self.parameters.get("display_name")
        self.data["uniqueName"] = self.parameters["unique_name"]
        if self.parameters.get("read_only"):
            self.data["managementReadOnly"] = self.parameters["read_only"]
        # Only add the parameter if value is True, as JSON response does not include non-true objects
        self.data["policies"] = {}

        if self.parameters.get("management_policy"):
            self.data["policies"] = {
                "management": dict(
                    (parameter_map[k], v) for (k, v) in self.parameters["management_policy"].items() if v
                )
            }
        if not self.data["policies"].get("management"):
            self.data["policies"]["management"] = None

        if self.parameters.get("s3_policy"):
            try:
                self.data["policies"]["s3"] = json.loads(self.parameters["s3_policy"])
            except ValueError:
                self.module.fail_json(msg="Failed to decode s3_policy. Invalid JSON.")

        self.re_local_group = re.compile("^group/")
        self.re_fed_group = re.compile("^federated-group/")

        if (
            self.re_local_group.match(self.parameters["unique_name"]) is None
            and self.re_fed_group.match(self.parameters["unique_name"]) is None
        ):
            self.module.fail_json(msg="unique_name must begin with 'group/' or 'federated-group/'")

    def get_org_group(self, unique_name):
        # Use the unique name to check if the group exists
        api = "api/v3/org/groups/%s" % unique_name
        response, error = self.rest_api.get(api)

        if error:
            if response["code"] != 404:
                self.module.fail_json(msg=error)
        else:
            return response["data"]
        return None

    def create_org_group(self):
        api = "api/v3/org/groups"

        response, error = self.rest_api.post(api, self.data)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def delete_org_group(self, group_id):
        api = "api/v3/org/groups/" + group_id

        self.data = None
        response, error = self.rest_api.delete(api, self.data)
        if error:
            self.module.fail_json(msg=error)

    def update_org_group(self, group_id):
        api = "api/v3/org/groups/" + group_id

        response, error = self.rest_api.put(api, self.data)
        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """
        org_group = self.get_org_group(self.parameters["unique_name"])

        cd_action = self.na_helper.get_cd_action(org_group, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters

            if self.parameters.get("management_policy"):
                if org_group.get("policies") is None or org_group.get("policies", {}).get("management") != self.data["policies"]["management"]:
                    self.na_helper.changed = True
            if self.parameters.get("s3_policy"):
                if org_group.get("policies") is None or org_group.get("policies", {}).get("s3") != self.data["policies"]["s3"]:
                    self.na_helper.changed = True
            if self.parameters.get("read_only") is not None and self.parameters.get("read_only") != org_group["managementReadOnly"]:
                self.na_helper.changed = True

        result_message = ""
        resp_data = org_group
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == "delete":
                    self.delete_org_group(org_group["id"])
                    result_message = "Org Group deleted"

                elif cd_action == "create":
                    resp_data = self.create_org_group()
                    result_message = "Org Group created"

                else:
                    # for a federated group, the displayName parameter needs to be specified
                    # and must match the existing displayName
                    if self.re_fed_group.match(self.parameters["unique_name"]):
                        self.data["displayName"] = org_group["displayName"]

                    resp_data = self.update_org_group(org_group["id"])
                    result_message = "Org Group updated"

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_org_group = SgOrgGroup()
    na_sg_org_group.apply()


if __name__ == "__main__":
    main()
