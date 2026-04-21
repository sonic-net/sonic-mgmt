#!/usr/bin/python

# (c) 2025, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage ILM policy tags"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_ilm_policy_tag
short_description: Manage ILM policy tags on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.14.0'
author: Denis Magel (@dmagel-netapp) <denis.magel@netapp.com>
description:
- Interact with ILM policy tags on NetApp StorageGRID.
options:
  name:
    description:
    - The unique name of this tag.
    - Assigning an ILM policy to this tag applies the policy only to buckets tagged
      with NTAP-SG-ILM-BUCKET as the key and this name as the value (case-insensitive).
    - Visible to tenants, do not include sensitive information.
    required: true
    type: str
  description:
    description:
    - The description of this policy tag.
    - Visible to tenants, do not include sensitive information.
    required: false
    type: str
  policy_id:
    description:
    - The ID of the ILM policy that will use this tag.
    required: false
    type: str
  state:
    description:
    - Whether the specified ILM policy tag should be created or deleted.
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
- name: Create ILM policy tag
  na_sg_grid_ilm_policy_tag:
    auth_token: 9bcf4902-d5a3-479a-8d5e-8f98ef879f4e
    api_url: https://192.168.0.80
    name: tag1
    description: Applies ILM policy 'mypolicy'
    policy_id: r601033236249396421

- name: Delete existing ILM policy tag
  na_sg_grid_ILM_policy_tag:
    auth_token: 9bcf4902-d5a3-479a-8d5e-8f98ef879f4e
    api_url: https://192.168.0.80
    name: tag1
    state: absent
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID ILM policy tag.
    returned: If state is 'present'.
    type: dict
    sample: {
        "description": "Data Center 1",
        "id": "f9cecfd8-fe93-4529-b883-d1707e753009",
        "name": "tag1",
        "policy_id": "r601033236249396421"
    }
"""

from datetime import datetime

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI

__LOGGING__ = []


class ILM_policy_tag(object):
    """
    Create, modify and delete StorageGRID ILM policy tag
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
                description=dict(required=False, type="str"),
                policy_id=dict(required=False, type="str"),
            )
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
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
        if self.parameters.get("description"):
            self.data["description"] = self.parameters["description"]
        if self.parameters.get("policy_id"):
            self.data["policyId"] = self.parameters["policy_id"]
        __LOGGING__.append("data: %s" % (self.data))

    def module_logging_handler(self, log_msg):
        """Module logging handler"""
        # Create timestamp for logs
        date_now = datetime.now()
        timestamp = date_now.strftime("%Y/%m/%d-%H:%M:%S")
        # Log events
        self.module.log(log_msg)
        __LOGGING__.append("%s: %s" % (timestamp, log_msg))

    def get_ILM_policy_tags(self):
        # Check if policy tag exists
        # Return info if found, or None
        api = "api/v4/grid/ilm-policy-tags"
        response, error = self.rest_api.get(api)
        if error:
            self.module.fail_json(msg=error, log=__LOGGING__)
        self.module_logging_handler("all ILM policy tags: %s" % (response["data"]))
        # if ILM policy tag with 'name' exists, return it, else none
        for tag in response["data"]:
            if tag["name"] == self.parameters["name"]:
                self.id = tag["id"]
                self.data.update({"id": tag["id"]})
                return tag
        return None

    def create_ILM_policy_tag(self):
        __LOGGING__.append("creating ILM policy tag with payload: %s" % (self.data))
        api = "api/v4/grid/ilm-policy-tags"
        response, error = self.rest_api.post(api, self.data)
        __LOGGING__.append("error: %s" % (error))
        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)
        return response["data"]

    def delete_ILM_policy_tag(self):
        __LOGGING__.append("deleting ILM policy tag")
        api = "api/v4/grid/ilm-policy-tags/%s" % (self.id)
        response, error = self.rest_api.delete(api, None)
        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)

    def update_ILM_policy_tag(self):
        __LOGGING__.append("updating ILM policy tag with payload: %s" % (self.data))
        api = "api/v4/grid/ilm-policy-tags/%s" % (self.id)
        response, error = self.rest_api.put(api, self.data)
        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)
        return response["data"]

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """

        ILM_policy_tag = self.get_ILM_policy_tags()
        self.module_logging_handler("got matching ILM policy tag: %s" % (ILM_policy_tag))

        cd_action = self.na_helper.get_cd_action(ILM_policy_tag, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            if self.data.get("description") and self.data.get("description") != ILM_policy_tag.get("description"):
                self.na_helper.changed = True
            if self.data.get("policyId") and self.data.get("policyId") != ILM_policy_tag.get("policyId"):
                self.na_helper.changed = True

        result_message = ""
        resp_data = ILM_policy_tag
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == "delete":
                    self.delete_ILM_policy_tag()
                    resp_data = None
                    result_message = "ILM policy tag deleted"
                    __LOGGING__.append("ILM policy tag deleted")

                elif cd_action == "create":
                    resp_data = self.create_ILM_policy_tag()
                    result_message = "ILM policy tag created"
                    __LOGGING__.append("ILM policy tag created")

                else:
                    resp_data = self.update_ILM_policy_tag()
                    result_message = "ILM policy tag updated"
                    __LOGGING__.append("ILM policy tag updated")

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data, log=__LOGGING__)


def main():
    """
    Main function
    """
    na_sg_ILM_policy_tag = ILM_policy_tag()
    na_sg_ILM_policy_tag.apply()


if __name__ == "__main__":
    main()
