#!/usr/bin/python

# (c) 2025, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Apply Hotfixes"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_hotfix
short_description: Apply hotfixes on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.15.0'
author: NetApp Ansible Team (@vinaykus) <ng-ansibleteam@netapp.com>
description:
  - Apply hotfix on NetApp StorageGRID.
options:
  state:
    description:
    - The hotfix will start applying if present.
    - If absent, it remove all nodes from the hotfix queue.
    choices: ['present', 'absent']
    default: 'present'
    type: str
  passphrase:
    description:
    - The provisioning passphrase.
    type: str
  type:
    description:
    - the type of software update to deploy.
    choices: ['hotfix']
    type: str
  file_path:
    description:
    - The path to the software update file.
    type: str
  timeout:
    description:
    - The time in seconds to wait for the software update to complete.
    type: int
    default: 20

notes:
  - It is recommend to apply the latest hotfix before and after each software upgrade.
  - Before starting the hotfix process, confirm that there are no active alerts and that all grid nodes are online and available.
  - When the primary Admin Node is updated, services are stopped and restarted. Connectivity might be interrupted until the services are back online.
"""

EXAMPLES = """
- name: Apply hotfix on StorageGRID
  na_sg_grid_hotfix:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    state: "present"
    validate_certs: false
    passphrase: "{{ storagegrid_passphrase }}"
    type: "hotfix"
    file_path: "/path/to/hotfix_file"
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID software update.
    returned: success
    type: dict
    sample: {
        "id": "software-update",
        "filePath": "/tmp/StorageGRID-Software-Update",
        "fileName": "StorageGRID-Software-Update",
        "version": "11.4.0.1",
        "restart": true,
        "startTime": "2025-03-28T06:33:58.576Z",
        "endTime": "2025-03-28T06:33:58.576Z",
        "inProgress": true,
        "stage": "applying",
        "error": "Failed to apply software update to DC1-S1",
        "validationError": "Failed to validate installer file: File is empty",
        "percent": 75,
        "type": "hotfix",
        "uploadType": "hotfix"
    }
"""

import time
import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgHotfix:
    """
    Apply hotfix on NetApp StorageGRID
    """

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.na_storagegrid_host_argument_spec()
        self.argument_spec.update(
            dict(
                state=dict(type="str", choices=["present", "absent"], default="present"),
                passphrase=dict(required=False, type="str", no_log=True),
                type=dict(required=False, type="str", choices=["hotfix"]),
                timeout=dict(required=False, type="int", default=20),
                file_path=dict(required=False, type="str"),
            )
        )

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[["state", "present", ["passphrase", "type"]]],
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Get API version
        self.rest_api.get_sg_product_version(api_root="grid")

        # Checking for the parameters passed and create new parameters list
        self.data = {}

        self.data["passphrase"] = self.parameters["passphrase"]
        self.data["type"] = self.parameters["type"]

        if "file_path" in self.parameters:
            self.rest_api.fail_if_not_sg_minimum_version("flie_path", 11, 9)

    def get_hotfix_details(self):
        """ Retrieve the status of the current software update procedure """
        api = "api/v4/private/software-update"
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]

    def start_apply_hotfix(self):
        """ Runs the software update procedure """
        api = "api/v4/private/software-update/start"
        response, error = self.rest_api.post(api, self.data)

        if error:
            self.module.fail_json(msg=error)

    def get_hotfix_node_details(self):
        """ Retrieve the list of node details """
        api = "api/v4/private/software-update/nodes"
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]

    def update_hotfix_node_queue(self, node_id):
        """ Update the node queue schedule for the software update """
        api = "api/v4/private/software-update/queue"
        body = [node_id]
        response, error = self.rest_api.post(api, body)

        if error:
            self.module.fail_json(msg=error)

    def remove_hotfix_node_queue(self, node_id):
        """ Remove the node from the hotfix queue """
        api = "api/v4/private/software-update/queue"
        body = [node_id]
        response, error = self.rest_api.delete(api, body)

        if error:
            self.module.fail_json(msg=error)

    def upload_hotfix_software_update_file(self, file_path):
        """ Upload the software update file """
        api = "api/v4/tools/upload-software-update"
        with open(file_path, "rb") as file:
            file_name = file_path.split('/')[-1]
            files = {
                "file": (file_name, file, "application/octet-stream"),
            }
            params = {"type": "hotfix"}

            response, error = self.rest_api.post(api, files=files, params=params)

        if error or response.get("status_code") != 202:
            self.module.fail_json(msg="Failed to upload hotfix file")
        # sleep for 5 seconds to allow the upload to get refreshed
        time.sleep(5)

    def wait_for_hotfix_to_complete(self, current_node):
        """ Wait for the software update procedure to complete """
        for __ in range(self.parameters["timeout"]):
            current_hotfix = self.get_hotfix_details()

            # Check for any validation errors after updating the node queue
            if current_hotfix["validationError"]:
                self.module.fail_json(msg=current_hotfix["validationError"])

            node_details = self.get_hotfix_node_details()
            if node_details:
                for node in node_details:
                    # Check if the node update is in progress
                    if node["id"] == current_node["id"] and node["progress"]["percent"] == 100:
                        return

                    elif node["progress"].get("error"):
                        self.module.fail_json(msg=node["progress"]["error"])

                    # sleep for 5 seconds before checking again
                    time.sleep(5)
            else:
                return

        self.module.fail_json(msg="Timeout waiting for hotfix to complete")

    def apply(self):
        """ Apply hotfix on NetApp StorageGRID """

        current_hotfix = self.get_hotfix_details()

        if self.parameters['state'] == 'present' and self.parameters.get("file_path") and not current_hotfix["inProgress"]:
            self.upload_hotfix_software_update_file(self.parameters["file_path"])
            # get the hotfix details again after uploading the file
            current_hotfix = self.get_hotfix_details()

        current_nodes_to_update = None

        if self.parameters['state'] == 'absent':
            if current_hotfix["inProgress"]:
                current_nodes_to_update = self.get_hotfix_node_details()
                for node in current_nodes_to_update:
                    if node["queued"]:
                        self.remove_hotfix_node_queue(node["id"])
                self.na_helper.changed = True

        if self.parameters["state"] == "present":
            if current_hotfix["uploadType"] == "hotfix" and not current_hotfix["inProgress"]:
                self.start_apply_hotfix()
                # get the nodes details after starting the hotfix
                current_nodes_to_update = self.get_hotfix_node_details()
                for current_node in current_nodes_to_update:
                    self.update_hotfix_node_queue(current_node["id"])
                    # sleep for 5 seconds before checking the status
                    time.sleep(5)
                    self.wait_for_hotfix_to_complete(current_node)
                self.na_helper.changed = True

            elif current_hotfix["inProgress"]:
                current_nodes_to_update = self.get_hotfix_node_details()
                for current_node in current_nodes_to_update:
                    self.update_hotfix_node_queue(current_node["id"])
                    # sleep for 5 seconds before checking the status
                    time.sleep(5)
                    self.wait_for_hotfix_to_complete(current_node)
                self.na_helper.changed = True

        result_message = ""
        resp_data = current_hotfix
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if self.parameters['state'] == 'absent':
                    result_message = "Hotfix node removed successfully."
                else:
                    if self.parameters["state"] == "present":
                        result_message = "Hotfix applied successfully."

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_hotfix = SgHotfix()
    na_sg_grid_hotfix.apply()


if __name__ == "__main__":
    main()
