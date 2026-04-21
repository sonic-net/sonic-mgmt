#!/usr/bin/python

# (c) 2024, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage ILM policies"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
module: na_sg_grid_ilm_policy
short_description: Manage ILM policies on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.14.0'
author: Denis Magel (@dmagel-netapp) <denis.magel@netapp.com>
description:
- Interact with ILM policies on NetApp StorageGRID.
options:
  default_rule:
    description:
    - The rule ID of the defailt rule in the policy.
    - This tile ID must be included in rules
    - If compliance is enabled, this must be the compliance-compatible rule
    type: str
  name:
    description:
    - The unique name of the policy
    required: true
    type: str
  reason:
    description:
    - Policy description
    required: false
    type: str
  rules:
    description:
    - A list of ILM rule IDs, in the order in which they will be evaluated
    - This list must include the default rule
    - If compliance is enabled, the default rule for objects in non-compliant buckets should be before the compliance-compatible default rule
    type: list
    elements: str
  state:
    description:
    - Whether the specified policy should exist.
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
- name: Create ILM policy
  na_sg_grid_ilm_policy:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    name: "1 Copy Per Site"
    state: present
    reason: "The 1 Copy Per Site policy placves 1 replicated copy at each site"
    default_rule: r601033236249396421
    rules:
      - r601033236249396421

- name: Delete existing ILM policy
  na_sg_grid_ilm_policy:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    name: "1 Copy Per Site"
    state: absent
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID ILM policy.
    returned: If state is 'present'.
    type: dict
    sample: {
        "activatedBy": [],
        "active": false,
        "defaultRule": "r601033236249396421",
        "id": "f9cecfd8-fe93-4529-b883-d1707e753009",
        "name": "1 Copy Per Site",
        "reason": "The 1 Copy Per Site policy placves 1 replicated copy at each site",
        "rules": [
            "r601033236249396421"
        ]
    }
"""

from datetime import datetime

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI

__LOGGING__ = []


class ILM_policy(object):
    """
    Create, modify and delete StorageGRID ILM policy
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
                default_rule=dict(required=False, type="str"),
                reason=dict(required=False, type="str"),
                rules=dict(required=False, type="list", elements="str"),
            )
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "present", ["default_rule", "rules"])],
            supports_check_mode=True,
        )
        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        __LOGGING__.append("params: %s" % (self.module.params))
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Get API version
        self.rest_api.get_sg_product_version(api_root="grid")

        # Create body for creation request (POST with state present)
        self.data = {}
        self.data["name"] = self.parameters["name"]
        if self.parameters.get("rules"):
            self.data["rules"] = self.parameters["rules"]
        if self.parameters.get("default_rule"):
            self.data["defaultRule"] = self.parameters["default_rule"]
        # optional parameters
        if self.parameters.get("reason"):
            self.data["reason"] = self.parameters.get("reason")
        __LOGGING__.append("data: %s" % (self.data))

    def module_logging_handler(self, log_msg):
        """Module logging handler"""
        # Create timestamp for logs
        date_now = datetime.now()
        timestamp = date_now.strftime("%Y/%m/%d-%H:%M:%S")
        # Log events
        self.module.log(log_msg)
        __LOGGING__.append("%s: %s" % (timestamp, log_msg))

    def get_ilm_policy(self):
        # Check if policy exists
        # Return info if found, or None
        api = "api/v4/grid/ilm-policies"
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error, log=__LOGGING__)
        self.module_logging_handler("all ILM policies: %s" % (response['data']))
        # if policy with 'name' exists, return it, else none
        for policy in response["data"]:
            if policy["name"] == self.parameters["name"]:
                self.id = policy["id"]
                return policy

        return None

    def create_ilm_policy(self):
        __LOGGING__.append("creating ILM policy with payload: %s" % (self.data))
        api = "api/v4/grid/ilm-policies"
        response, error = self.rest_api.post(api, self.data)
        __LOGGING__.append("error: %s" % error)

        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)

        return response["data"]

    def delete_ilm_policy(self):
        __LOGGING__.append("deleting ILM policy")
        api = "api/v4/grid/ilm-policies/%s" % self.id

        response, error = self.rest_api.delete(api, None)
        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)

    def update_ilm_policy(self):
        __LOGGING__.append("updating ILM policy with payload: %s" % self.data)
        api = "api/v4/grid/ilm-policies/%s" % self.id
        response, error = self.rest_api.put(api, self.data)

        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)

        return response["data"]

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """

        ilm_policy = self.get_ilm_policy()
        self.module_logging_handler("got matching ILM policys: %s" % ilm_policy)

        cd_action = self.na_helper.get_cd_action(ilm_policy, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            if self.data.get("reason") and self.data.get("reason") != ilm_policy.get("reason"):
                self.na_helper.changed = True
            if self.data.get("rules") and self.data.get("rules") != ilm_policy.get("rules"):
                self.na_helper.changed = True
            if self.data.get("default_rule") and self.data.get("default_rule") != ilm_policy.get("defaultRule"):
                self.na_helper.changed = True

        result_message = ""
        resp_data = ilm_policy
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == "delete":
                    self.delete_ilm_policy()
                    resp_data = None
                    result_message = "ILM policy deleted"
                    __LOGGING__.append("ILM policy deleted")

                elif cd_action == "create":
                    resp_data = self.create_ilm_policy()
                    result_message = "ILM policy created"
                    __LOGGING__.append("ILM policy created")

                else:
                    resp_data = self.update_ilm_policy()
                    result_message = "ILM policy updated"
                    __LOGGING__.append("ILM policy updated")

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data, log=__LOGGING__)


def main():
    """
    Main function
    """
    na_sg_ilm_policy = ILM_policy()
    na_sg_ilm_policy.apply()


if __name__ == "__main__":
    main()
