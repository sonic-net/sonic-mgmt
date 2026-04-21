#!/usr/bin/python

# (c) 2025, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage EC profiles"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
module: na_sg_grid_ec_profile
short_description: Manage EC profiles on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.14.0'
author: Denis Magel (@dmagel-netapp) <denis.magel@netapp.com>
description:
- Interact with EC profiles on NetApp StorageGRID.
options:
  name:
    description:
    - The EC Profile's name
    required: true
    type: str
  pool_id:
    description:
    - The Storage Pool ID of the selected scheme
    type: str
  scheme_id:
    description:
    - The selected scheme for the EC profile
    type: str
  state:
    description:
    - Whether the specified policy should be created or deactivated.
    - State "absent" only deactivates the EC profile.
    - Deactivated EC profiles cannot be activated
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
- name: Create EC profile
  na_sg_grid_ec_profile:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    name: "profile1"
    pool_id: p10771105546308032398
    scheme_id: "1"

- name: Deactivate existing EC profile
  na_sg_grid_ec_profile:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    name: "profile1"
    state: absent
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID EC profile.
    returned: If state is 'present'.
    type: dict
    sample: {
        "id": "5",
        "name": "EC profile 123",
        "poolId": "p10771105546308032398",
        "schemeId": "4",
        "active": true
    }
"""

from datetime import datetime

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI

__LOGGING__ = []


class EC_profile(object):
    """
    Create, modify and delete StorageGRID EC profile
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
                pool_id=dict(required=False, type="str"),
                scheme_id=dict(required=False, type="str"),
            )
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "present", ["pool_id", "scheme_id"])],
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
        self.data["name"] = self.parameters["name"]
        if self.parameters.get("pool_id"):
            self.data["poolId"] = self.parameters["pool_id"]
        if self.parameters.get("scheme_id"):
            self.data["schemeId"] = self.parameters["scheme_id"]
        __LOGGING__.append("data: %s" % self.data)

    def module_logging_handler(self, log_msg):
        """Module logging handler"""
        # Create timestamp for logs
        date_now = datetime.now()
        timestamp = date_now.strftime("%Y/%m/%d-%H:%M:%S")
        # Log events
        self.module.log(log_msg)
        __LOGGING__.append("%s: %s" % (timestamp, log_msg))

    def get_ec_profile(self):
        # Check if profile exists
        # Return info if found, or None
        api = "api/v4/grid/ec-profiles?showDeactivated=true"
        response, error = self.rest_api.get(api)
        if error:
            self.module.fail_json(msg=error, log=__LOGGING__)
        self.module_logging_handler("all EC profiles: %s" % response['data'])
        # if EC profile with 'name' exists, return it, else none
        for profile in response["data"]:
            if profile["name"] == self.parameters["name"]:
                self.id = profile["id"]
                return profile
        return None

    def create_ec_profile(self):
        __LOGGING__.append("creating EC profile with payload: %s" % self.data)
        api = "api/v4/private/ec-profiles"
        response, error = self.rest_api.post(api, self.data)
        __LOGGING__.append("error: %s" % error)
        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)
        return response["data"]

    def deactivate_ec_profile(self):
        __LOGGING__.append("deactivating EC profile")
        api = "api/v4/private/ec-profiles/%s/deactivate" % self.id
        response, error = self.rest_api.post(api, None)
        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)

    def update_ec_profile(self):
        __LOGGING__.append("updating EC profile with payload: %s" % self.data)
        api = "api/v4/private/ec-profiles/%s" % self.id
        response, error = self.rest_api.put(api, self.data)
        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)
        return response["data"]

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """

        ec_profile = self.get_ec_profile()
        self.module_logging_handler("got matching EC profile: %s" % ec_profile)

        cd_action = self.na_helper.get_cd_action(ec_profile, self.parameters)

        if self.na_helper.changed and self.parameters["state"] == "absent":
            # only change something if the EC profile is not already inactive
            if not ec_profile.get("active"):
                self.na_helper.changed = False

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            if self.data.get("poolId") and self.data.get("poolId") != ec_profile.get("poolId"):
                self.na_helper.changed = True
            if self.data.get("schemeId") and self.data.get("schemeId") != ec_profile.get("schemeId"):
                self.na_helper.changed = True

        result_message = ""
        resp_data = ec_profile
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == "delete":
                    self.deactivate_ec_profile()
                    resp_data = None
                    result_message = "EC profile deactivated"
                    __LOGGING__.append("EC profile deactivated")

                elif cd_action == "create":
                    resp_data = self.create_ec_profile()
                    result_message = "EC profile created"
                    __LOGGING__.append("EC profile created")

                else:
                    resp_data = self.update_ec_profile()
                    result_message = "EC profile updated"
                    __LOGGING__.append("EC profile updated")

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data, log=__LOGGING__)


def main():
    """
    Main function
    """
    na_sg_ec_profile = EC_profile()
    na_sg_ec_profile.apply()


if __name__ == "__main__":
    main()
