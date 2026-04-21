#!/usr/bin/python

# (c) 2020, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Grid Regions"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_regions
short_description: NetApp StorageGRID manage Regions for the grid.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '20.6.0'
author: NetApp Ansible Team (@joshedmonds) <ng-ansibleteam@netapp.com>
description:
- Create, Update, Delete Users within a NetApp StorageGRID tenant.
options:
  state:
    description:
    - Whether the specified user should exist or not.
    type: str
    choices: ['present']
    default: present
  regions:
    description:
    - List of regions
    required: true
    type: list
    elements: str
"""

EXAMPLES = """
- name: update Regions
  netapp.storagegrid.na_sg_grid_regions:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    regions: "us-east-1"
"""

RETURN = """
resp:
    description: Returns information about the configured regions.
    returned: success
    type: list
    elements: str
    sample: ["us-east-1", "us-central-1"]
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgGridRegions(object):
    """
    Create, modify and delete Regions for StorageGRID
    """

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.na_storagegrid_host_argument_spec()
        self.argument_spec.update(
            dict(
                state=dict(required=False, type="str", choices=["present"], default="present"),
                regions=dict(required=True, type="list", elements="str"),
            )
        )

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            # required_if=[("state", "present", ["state", "name", "protocol"])],
            supports_check_mode=True,
        )

        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Checking for the parameters passed and create new parameters list
        self.data = self.parameters["regions"]

    def get_grid_regions(self):
        # Check if tenant account exists
        # Return tenant account info if found, or None
        api = "api/v3/grid/regions"

        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def update_grid_regions(self):
        api = "api/v3/grid/regions"

        response, error = self.rest_api.put(api, self.data)
        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """
        grid_regions = self.get_grid_regions()

        cd_action = self.na_helper.get_cd_action(grid_regions, self.parameters["regions"])

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            update = False

            regions_diff = [i for i in self.data + grid_regions if i not in self.data or i not in grid_regions]
            if regions_diff:
                update = True

            if update:
                self.na_helper.changed = True

        result_message = ""
        resp_data = grid_regions
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                resp_data = self.update_grid_regions()
                result_message = "Grid Regions updated"

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_regions = SgGridRegions()
    na_sg_grid_regions.apply()


if __name__ == "__main__":
    main()
