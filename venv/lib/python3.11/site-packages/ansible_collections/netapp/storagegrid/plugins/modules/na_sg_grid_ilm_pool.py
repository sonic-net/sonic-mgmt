#!/usr/bin/python

# (c) 2025, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage ILM pools"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
module: na_sg_grid_ilm_pool
short_description: Manage ILM pools on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.14.0'
author: Denis Magel (@dmagel-netapp) <denis.magel@netapp.com>
description:
- Interact with ILM pools on NetApp StorageGRID.
options:
  name:
    description:
    - The name of the storage pool
    - Must be unique
    required: true
    type: str
  disks:
    description:
    - A list of the sites and storage grades in the storage pool
    type: list
    elements: dict
    suboptions:
      description:
        description:
          - The IDs of all sites and storage grades for this storage pool.
          - The null site ("All Sites") is the default site, which includes all current sites.
          - The null storage grade ("All Storage Nodes") is the default storage grade, which includes all Storage Nodes at the selected site.
          - Use the All Sites default with care because it will automatically include new sites added in an expansion, which might not be the behavior you want.
          - To get more information about the sites and storage grades, use the ilm-grade-site and ilm-grades endpoints.
        required: false
        type: str
      group:
        description:
          - If both the group and siteId fields are provided, for a disk, the siteId will be used when creating/ editing a storage pool.
        required: false
        type: int
      grade:
        description:
          - Storage grade ID
        required: false
        type: int
      siteId:
        description:
          - If both the group and siteId fields are provided, for a disk, the siteId will be used when creating/ editing a storage pool.
        required: false
        type: str
  archives:
    description:
    - A list of the sites that use the Archive Nodes storage grade
    type: list
    elements: dict
    suboptions:
      description:
        description:
          - The IDs of all sites and storage grades for this storage pool.
          - The null site ("All Sites") is the default site, which includes all current sites.
          - The null storage grade ("All Storage Nodes") is the default storage grade, which includes all Storage Nodes at the selected site.
          - Use the All Sites default with care because it will automatically include new sites added in an expansion, which might not be the behavior you want.
          - To get more information about the sites and storage grades, use the ilm-grade-site and ilm-grades endpoints.
        required: false
        type: str
      group:
        description:
          - If both the group and siteId fields are provided, for a disk, the siteId will be used when creating/ editing a storage pool.
        required: false
        type: int
      grade:
        description:
          - Storage grade ID
        required: false
        type: int
      siteId:
        description:
          - If both the group and siteId fields are provided, for a disk, the siteId will be used when creating/ editing a storage pool.
        required: false
        type: str
  state:
    description:
    - Whether the specified pool should be created or deleted.
    required: false
    type: str
    choices: ['present', 'absent']
    default: present
  validate_certs:
    description:
    - Should https certificates be validated?
    required: false
    type: bool
    default: true
"""

EXAMPLES = """
- name: Create ILM pool
  na_sg_grid_ilm_pool:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    name: "Data Center 1"
    disks:
      - group: 10
    archives: []

- name: Delete existing ILM pool
  na_sg_grid_ilm_pool:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    name: "profile1"
    state: absent
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID ILM pool.
    returned: If state is 'present'.
    type: dict
    sample: {
        "archives": [],
        "disks": [
            {
                "grade": null,
                "group": null,
                "siteId": null
            }
        ],
        "displayName": "Data Center 1",
        "id": "p10771105546308032398",
        "name": "Data Center 1"
    }
"""

from datetime import datetime

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI
from ansible_collections.netapp.storagegrid.plugins.module_utils.tools import first_inside_second_dict_or_list

__LOGGING__ = []


class ILM_pool(object):
    """
    Create, modify and delete StorageGRID ILM pool
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
                name=dict(required=True, type="str"),
                disks=dict(
                    required=False,
                    type="list",
                    elements="dict",
                    options=dict(
                        description=dict(required=False, type="str"),
                        group=dict(required=False, type="int"),
                        grade=dict(required=False, type="int"),
                        siteId=dict(required=False, type="str"),
                    ),
                ),
                archives=dict(
                    required=False,
                    type="list",
                    elements="dict",
                    options=dict(
                        description=dict(required=False, type="str"),
                        group=dict(required=False, type="int"),
                        grade=dict(required=False, type="int"),
                        siteId=dict(required=False, type="str"),
                    ),
                ),
            )
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "present", ["disks", "archives"])],
            supports_check_mode=True,
        )
        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        __LOGGING__.append("params: %s" % self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Get API version
        self.rest_api.get_sg_product_version(api_root="grid")

        # Create body for creation request (POST with state present)
        self.data = {}
        self.data["displayName"] = self.parameters["name"]
        if self.parameters.get("disks"):
            self.data["disks"] = self.parameters["disks"]
        if self.parameters.get("archives"):
            self.data["archives"] = self.parameters["archives"]
        __LOGGING__.append("data: %s" % self.data)

    def module_logging_handler(self, log_msg):
        """Module logging handler"""
        # Create timestamp for logs
        date_now = datetime.now()
        timestamp = date_now.strftime("%Y/%m/%d-%H:%M:%S")
        # Log events
        self.module.log(log_msg)
        __LOGGING__.append("%s: %s" % (timestamp, log_msg))

    def get_ilm_pools(self):
        # Check if profile exists
        # Return info if found, or None
        api = "api/v4/private/ilm-pools"
        response, error = self.rest_api.get(api)
        if error:
            self.module.fail_json(msg=error, log=__LOGGING__)
        self.module_logging_handler("all ILM pools: %s" % response['data'])
        # if ILM pool with 'name' exists, return it, else none
        for pool in response["data"]:
            if pool["displayName"] == self.parameters["name"]:
                self.id = pool["id"]
                self.data.update({"id": pool["id"]})
                return pool
        return None

    def create_ilm_pool(self):
        __LOGGING__.append("creating ILM pool with payload: %s" % self.data)
        api = "api/v4/private/ilm-pools"
        response, error = self.rest_api.post(api, self.data)
        __LOGGING__.append("error: %s" % error)
        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)
        return response["data"]

    def delete_ilm_pool(self):
        __LOGGING__.append("deactivating ILM pool")
        api = "api/v4/private/ilm-pools/%s" % self.id
        response, error = self.rest_api.delete(api, None)
        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)

    def update_ilm_pool(self):
        __LOGGING__.append("updating ILM pool with payload: %s" % self.data)
        api = "api/v4/private/ilm-pools/%s" % self.id
        response, error = self.rest_api.put(api, self.data)
        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)
        return response["data"]

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """

        ilm_pool = self.get_ilm_pools()
        self.module_logging_handler("got matching ILM pool: %s" % ilm_pool)

        cd_action = self.na_helper.get_cd_action(ilm_pool, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            if self.data.get("disks") and not first_inside_second_dict_or_list(self.data.get("disks"), ilm_pool.get("disks")):
                self.na_helper.changed = True
            if self.data.get("archives") and not first_inside_second_dict_or_list(self.data.get("archives"), ilm_pool.get("archives")):
                self.na_helper.changed = True

        result_message = ""
        resp_data = ilm_pool
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == "delete":
                    self.delete_ilm_pool()
                    resp_data = None
                    result_message = "ILM pool deleted"
                    __LOGGING__.append("ILM pool deleted")

                elif cd_action == "create":
                    resp_data = self.create_ilm_pool()
                    result_message = "ILM pool created"
                    __LOGGING__.append("ILM pool created")

                else:
                    resp_data = self.update_ilm_pool()
                    result_message = "ILM pool updated"
                    __LOGGING__.append("ILM pool updated")

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data, log=__LOGGING__)


def main():
    """
    Main function
    """
    na_sg_ilm_pool = ILM_pool()
    na_sg_ilm_pool.apply()


if __name__ == "__main__":
    main()
