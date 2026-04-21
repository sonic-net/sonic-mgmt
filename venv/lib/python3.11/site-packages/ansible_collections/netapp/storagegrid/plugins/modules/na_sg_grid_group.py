#!/usr/bin/python

# (c) 2020, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Grid Groups"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_group
short_description: NetApp StorageGRID manage groups.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '20.6.0'
author: NetApp Ansible Team (@joshedmonds) <ng-ansibleteam@netapp.com>
description:
- Create, Update, Delete Administration Groups within NetApp StorageGRID.
options:
  state:
    description:
    - Whether the specified group should exist or not.
    type: str
    choices: ['present', 'absent']
    default: present
  display_name:
    description:
    - Name of the group.
    - Required for create operation
    type: str
  unique_name:
    description:
    - Unique Name for the group. Must begin with C(group/) or C(federated-group/)
    - Required for create, modify or delete operation.
    type: str
    required: true
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
      alarm_acknowledgement:
          description:
          - Group members can have permission to acknowledge alarms.
          required: false
          type: bool
      other_grid_configuration:
          description:
          - Need to investigate.
          required: false
          type: bool
      grid_topology_page_configuration:
          description:
          - Users in this group will have permissions to change grid topology.
          required: false
          type: bool
      tenant_accounts:
          description:
          - Users in this group will have permissions to manage tenant accounts.
          required: false
          type: bool
      change_tenant_root_password:
          description:
          - Users in this group will have permissions to change tenant password.
          required: false
          type: bool
      maintenance:
          description:
          - Users in this group will have permissions to run maintenance tasks on StorageGRID.
          required: false
          type: bool
      metrics_query:
          description:
          - Users in this group will have permissions to query metrics on StorageGRID.
          required: false
          type: bool
      activate_features:
          description:
          - Users in this group will have permissions to reactivate features.
          required: false
          type: bool
      ilm:
          description:
          - Users in this group will have permissions to manage ILM rules on StorageGRID.
          required: false
          type: bool
      object_metadata:
          description:
          - Users in this group will have permissions to manage object metadata.
          required: false
          type: bool
      root_access:
          description:
          - Users in this group will have root access.
          required: false
          type: bool
"""

EXAMPLES = """
- name: create a StorageGRID group
  netapp.storagegrid.na_sg_grid_group:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    display_name: ansiblegroup100
    unique_name: group/ansiblegroup100
    management_policy:
    tenant_accounts: true
    maintenance: true
    root_access: false
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID group attributes.
    returned: success
    type: dict
    sample: {
        "displayName": "Example Group",
        "policies": {
            "management": {
                "alarmAcknowledgment": true,
                "manageAlerts": true,
                "otherGridConfiguration": true,
                "gridTopologyPageConfiguration": true,
                "tenantAccounts": true,
                "changeTenantRootPassword": true,
                "maintenance": true,
                "metricsQuery": true,
                "activateFeatures": false,
                "ilm": true,
                "objectMetadata": true,
                "storageAdmin": true,
                "rootAccess": true
            }
        },
        "uniqueName": "group/examplegroup",
        "accountId": "12345678901234567890",
        "id": "00000000-0000-0000-0000-000000000000",
        "federated": false,
        "groupURN": "urn:sgws:identity::12345678901234567890:group/examplegroup"
    }
"""

import re

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgGridGroup(object):
    """
    Create, modify and delete StorageGRID Grid-administration Group
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
                        alarm_acknowledgement=dict(required=False, type="bool"),
                        other_grid_configuration=dict(required=False, type="bool"),
                        grid_topology_page_configuration=dict(required=False, type="bool"),
                        tenant_accounts=dict(required=False, type="bool"),
                        change_tenant_root_password=dict(required=False, type="bool"),
                        maintenance=dict(required=False, type="bool"),
                        metrics_query=dict(required=False, type="bool"),
                        activate_features=dict(required=False, type="bool"),
                        ilm=dict(required=False, type="bool"),
                        object_metadata=dict(required=False, type="bool"),
                        root_access=dict(required=False, type="bool"),
                    ),
                ),
            )
        )
        parameter_map = {
            "alarm_acknowledgement": "alarmAcknowledgement",
            "other_grid_configuration": "otherGridConfiguration",
            "grid_topology_page_configuration": "gridTopologyPageConfiguration",
            "tenant_accounts": "tenantAccounts",
            "change_tenant_root_password": "changeTenantRootPassword",
            "maintenance": "maintenance",
            "metrics_query": "metricsQuery",
            "activate_features": "activateFeatures",
            "ilm": "ilm",
            "object_metadata": "objectMetadata",
            "root_access": "rootAccess",
        }
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
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

        self.re_local_group = re.compile("^group/")
        self.re_fed_group = re.compile("^federated-group/")

        if (
            self.re_local_group.match(self.parameters["unique_name"]) is None
            and self.re_fed_group.match(self.parameters["unique_name"]) is None
        ):
            self.module.fail_json(msg="unique_name must begin with 'group/' or 'federated-group/'")

    def get_grid_group(self, unique_name):
        # Use the unique name to check if the group exists
        api = "api/v3/grid/groups/%s" % unique_name
        response, error = self.rest_api.get(api)

        if error:
            if response["code"] != 404:
                self.module.fail_json(msg=error)
        else:
            return response["data"]
        return None

    def create_grid_group(self):
        api = "api/v3/grid/groups"

        response, error = self.rest_api.post(api, self.data)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def delete_grid_group(self, group_id):
        api = "api/v3/grid/groups/" + group_id

        self.data = None
        response, error = self.rest_api.delete(api, self.data)
        if error:
            self.module.fail_json(msg=error)

    def update_grid_group(self, group_id):
        api = "api/v3/grid/groups/" + group_id

        response, error = self.rest_api.put(api, self.data)
        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """
        grid_group = self.get_grid_group(self.parameters["unique_name"])

        cd_action = self.na_helper.get_cd_action(grid_group, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters

            if self.parameters.get("management_policy"):
                if grid_group.get("policies") is None or grid_group.get("policies", {}).get("management") != self.data["policies"]["management"]:
                    self.na_helper.changed = True
            if self.parameters.get("read_only") is not None and self.parameters.get("read_only") != grid_group["managementReadOnly"]:
                self.na_helper.changed = True

        result_message = ""
        resp_data = grid_group
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == "delete":
                    self.delete_grid_group(grid_group["id"])
                    result_message = "Grid Group deleted"

                elif cd_action == "create":
                    resp_data = self.create_grid_group()
                    result_message = "Grid Group created"

                else:
                    # for a federated group, the displayName parameter needs to be specified
                    # and must match the existing displayName
                    if self.re_fed_group.match(self.parameters["unique_name"]):
                        self.data["displayName"] = grid_group["displayName"]

                    resp_data = self.update_grid_group(grid_group["id"])
                    result_message = "Grid Group updated"

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_group = SgGridGroup()
    na_sg_grid_group.apply()


if __name__ == "__main__":
    main()
