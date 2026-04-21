#!/usr/bin/python

# (c) 2025, NetApp Inc
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
module: na_sg_grid_ilm_rule
short_description: Manage ILM rules on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.14.0'
author: Denis Magel (@dmagel-netapp) <denis.magel@netapp.com>
description:
- Interact with ILM rules on NetApp StorageGRID.
options:
  bucket_filter:
    description:
    - S3 or Swift bucket(s) to which the ILM rule applies.
    - If omitted, matches all objects in any specified tenant accounts
    required: false
    type: dict
    suboptions:
      operator:
        description:
        - Operator used to match bucket(s) with the value
        required: true
        type: str
        choices: ['contains', 'endsWith', 'equals', 'startsWith']
      value:
        description:
        - str value used to match bucket(s) with the specified operator
        required: true
        type: str
  description:
    description:
    - A short description of the ILM rule to indicate its purpose
    required: false
    type: str
  filters:
    description:
    - Filtering criteria used to determine if the ILM rule shall be applied to the evaluated object.
    - An ILM rule without filters applies to all objects
    required: false
    type: list
    elements: dict
    default: []
    suboptions:
      logicalOperator:
        description:
        - Logical operator connecting filtering criteria when more than one criterion provided
        required: false
        type: str
      criteria:
        description:
        - A group of logical conditions based on object metadata
        required: false
        type: list
        elements: dict
        suboptions:
          operator:
            description:
            - Used to compare the "metadataName" with the "value" str
            required: true
            type: str
            choices: ['contains', 'notContains', 'equals', 'notEquals', 'startsWith', 'notStartsWith', 'endsWith', 'notEndsWith', 'exists', 'notExists',
              'lessThan', 'lessThanOrEquals', 'greaterThan', 'greaterThanOrEquals']
          metadataName:
            description:
            - System metadata identifier, user metadata name, or tag name
            required: true
            type: str
          metadataType:
            description:
            - Indicates the type of filtered metadata
            required: false
            type: str
          value:
            description:
            - Entry against which the metadata values specified by metadataName should be compared
            required: false
            type: str
  ingest_behavior:
    description:
    - How objects matching this rule are stored on ingest.
    - dual-commit creates interim copies and applies the rule later.
    - strict and balanced immediately create the copies specified in the rule's day 0 instructions.
    - balanced uses dual-commit if following the rule instructions is not possible.
    required: false
    type: str
    choices: ['strict', 'balanced', 'dual-commit']
    default: balanced
  name:
    description:
    - Displayed name of the ILM rule.
    - A representative and unique name for the ILM rule.
    - Immutable once the ILM rule is created
    required: true
    type: str
  placements:
    description:
    - Specifies where and how object data that matches the ILM rule is stored
    required: false
    type: list
    elements: dict
    suboptions:
      retention:
        description:
        - Specifies where and how object data that matches the ILM rule is stored over time
        required: true
        type: dict
        suboptions:
          after:
            description:
            - Day when object storage starts
            required: true
            type: int
          duration:
            description:
            - Number of days object data to be stored at the specified locations. Objects stored forever if null
            required: false
            type: int
      replicated:
        description:
        - Creates replicated copies of object data; otherwise, must be omitted
        required: false
        type: list
        elements: dict
        suboptions:
          poolId:
            description:
            - One or more storage pools where object data is saved, specified as comma-separated values. Either poolId or cloudStoragePoolId is required.
            required: false
            type: str
          temporaryPoolId:
            description:
            - Temporary locations are deprecated and should not be used for new ILM rules.
            - If you select the Strict ingest behavior, the temporary location is ignored.
            required: false
            type: str
          cloudStoragePoolId:
            description:
            - Cloud Storage Pool where object data is saved. Cloud Storage Pools cannot be used in the same placement as a storage pool.
            - Either poolId or cloudStoragePoolId is required.
            required: false
            type: str
          copies:
            description:
            - Number of replicated copies
            required: true
            type: int
      erasureCoded:
        description:
        - Creates erasure coded copies of object data; otherwise, must be omitted
        required: false
        type: list
        elements: dict
        suboptions:
          poolId:
            description:
            - Storage pool where object data is stored
            required: true
            type: str
          profileId:
            description:
            - Erasure coding profile used. Erasure coded object data only
            required: true
            type: str
  reference_time:
    description:
    - Indicates the time from which the ILM rule is applied
    required: false
    type: str
    choices: ['ingestTime', 'lastAccessTime', 'noncurrentTime', 'userDefinedCreationTime']
    default: ingestTime
  state:
    description:
    - Whether the specified rule should exist.
    required: false
    type: str
    choices: ['present', 'absent']
    default: present
  tenant_account_id:
    description:
    - One or more S3 or Swift tenant account IDs to which the ILM rule applies
    - If omitted, applies to all objects
    required: false
    type: str
  validate_certs:
    description:
    - Should https certificates be validated?
    required: false
    type: bool
    default: true
"""

EXAMPLES = """
- name: Create ILM rule with existing EC pool
  na_sg_grid_ilm_rule:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    name: "1 Copy Per Site"
    state: present
    reference_time: "ingestTime"
    ingest_behavior: "balanced"
    filters: []
    placements:
      - retention:
          after: 0
        erasureCoded:
          - profileId: "1"
            poolId: "p10771105546308032398"

- name: Delete existing ILM rule
  na_sg_grid_ilm_rule:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    name: "1 Copy Per Site"
    state: absent
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID ILM rule.
    returned: If state is 'present'.
    type: dict
    sample: {
        "active": false,
        "api": "s3OrSwift",
        "displayName": "1 Copy Per Site",
        "filters": [],
        "id": "r14896911895584977919",
        "ingestBehavior": "balanced",
        "permissions": [
            "delete",
            "edit"
        ],
        "placements": [
            {
                "erasureCoded": [
                    {
                        "poolId": "p10771105546308032398",
                        "profileld": "1"
                    }
                ],
                "retention": {
                    "after": 0
                }
            }
        ],
        "proposed": false,
        "referenceTime": "ingestTime",
        "schemaVersion": "1.0",
        "version": "1.0"
    }
"""

from datetime import datetime

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI
from ansible_collections.netapp.storagegrid.plugins.module_utils.tools import first_inside_second_dict_or_list

__LOGGING__ = []


class ILM_rule(object):
    """
    Create, modify and delete StorageGRID ILM rule
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
                bucket_filter=dict(
                    required=False,
                    type="dict",
                    options=dict(
                        operator=dict(required=True, type="str", choices=["contains", "endsWith", "equals", "startsWith"]),
                        value=dict(required=True, type="str"),
                    ),
                ),
                description=dict(required=False, type="str"),
                filters=dict(
                    required=False,
                    type="list",
                    elements="dict",
                    default=[],
                    options=dict(
                        logicalOperator=dict(required=False, type="str"),
                        criteria=dict(
                            required=False,
                            type="list",
                            elements="dict",
                            options=dict(
                                operator=dict(
                                    required=True,
                                    type="str",
                                    choices=[
                                        "contains",
                                        "notContains",
                                        "equals",
                                        "notEquals",
                                        "startsWith",
                                        "notStartsWith",
                                        "endsWith",
                                        "notEndsWith",
                                        "exists",
                                        "notExists",
                                        "lessThan",
                                        "lessThanOrEquals",
                                        "greaterThan",
                                        "greaterThanOrEquals",
                                    ],
                                ),
                                metadataName=dict(required=True, type="str"),
                                metadataType=dict(required=False, type="str"),
                                value=dict(
                                    required=False,
                                    type="str",
                                ),
                            ),
                        ),
                    ),
                ),
                ingest_behavior=dict(required=False, type="str", choices=["strict", "balanced", "dual-commit"], default="balanced"),
                placements=dict(
                    required=False,
                    type="list",
                    elements="dict",
                    options=dict(
                        retention=dict(
                            required=True,
                            type="dict",
                            options=dict(
                                after=dict(type="int", required=True),
                                duration=dict(type="int", required=False),
                            ),
                        ),
                        replicated=dict(
                            required=False,
                            type="list",
                            elements="dict",
                            options=dict(
                                poolId=dict(required=False, type="str"),
                                temporaryPoolId=dict(required=False, type="str"),
                                cloudStoragePoolId=dict(required=False, type="str"),
                                copies=dict(required=True, type="int"),
                            ),
                        ),
                        erasureCoded=dict(
                            required=False,
                            type="list",
                            elements="dict",
                            options=dict(profileId=dict(required=True, type="str"), poolId=dict(required=True, type="str")),
                        ),
                    ),
                ),
                reference_time=dict(
                    required=False, type="str", choices=["ingestTime", "lastAccessTime", "noncurrentTime", "userDefinedCreationTime"], default="ingestTime"
                ),
                tenant_account_id=dict(required=False, type="str"),
            )
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "present", ["placements"])],
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
        self.data["displayName"] = self.parameters["name"]
        self.data["filters"] = self.parameters["filters"]
        # optional parameters
        if self.parameters.get("bucket_filter"):
            self.data["bucketFilter"] = self.parameters.get("bucket_filter")
            self.data["api"] = "s3OrSwift"  # this deprecated parameter is required for PUT operations, in case "bucketFilter" is set. Dont ask me.
        if self.parameters.get("description"):
            self.data["description"] = self.parameters.get("description")
        if self.parameters.get("ingest_behavior"):
            self.data["ingestBehavior"] = self.parameters.get("ingest_behavior")
        if self.parameters.get("placements"):
            self.data["placements"] = self.parameters.get("placements")
        if self.parameters.get("reference_time"):
            self.data["referenceTime"] = self.parameters.get("reference_time")
        if self.parameters.get("tenant_account_id"):
            self.data["tenantAccountId"] = self.parameters.get("tenant_account_id")
        __LOGGING__.append("data: %s" % (self.data))

    def module_logging_handler(self, log_msg):
        """Module logging handler"""
        # Create timestamp for logs
        date_now = datetime.now()
        timestamp = date_now.strftime("%Y/%m/%d-%H:%M:%S")
        # Log events
        self.module.log(log_msg)
        __LOGGING__.append("%s: %s" % (timestamp, log_msg))

    def get_ilm_rule(self):
        # Check if rule exists
        # Return info if found, or None
        api = "api/v4/grid/ilm-rules"
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error, log=__LOGGING__)
        self.module_logging_handler("all ILM rules: %s" % (response["data"]))
        # if rule with 'name' exists, return it, else none
        for rule in response["data"]:
            if rule["displayName"] == self.parameters["name"]:
                self.id = rule["id"]
                return rule

        return None

    def create_ilm_rule(self):
        __LOGGING__.append("creating ILM rule with payload: %s" % (self.data))
        api = "api/v4/grid/ilm-rules"
        response, error = self.rest_api.post(api, self.data)
        __LOGGING__.append("error: %s" % (error))

        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)

        return response["data"]

    def delete_ilm_rule(self):
        __LOGGING__.append("deleting ILM rule")
        api = "api/v4/grid/ilm-rules/%s" % (self.id)

        response, error = self.rest_api.delete(api, None)
        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)

    def update_ilm_rule(self):
        __LOGGING__.append("updating ILM rule with payload: %s" % (self.data))
        api = "api/v4/grid/ilm-rules/%s" % (self.id)
        response, error = self.rest_api.put(api, self.data)

        if error:
            self.module.fail_json(msg=error["text"], log=__LOGGING__)

        return response["data"]

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """

        ilm_rule = self.get_ilm_rule()
        self.module_logging_handler("got matching ILM rules: %s" % (ilm_rule))

        cd_action = self.na_helper.get_cd_action(ilm_rule, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            if self.data.get("bucketFilter") and self.data.get("bucketFilter") != ilm_rule.get("bucketFilter"):
                self.na_helper.changed = True
            if self.data.get("description") and self.data.get("description") != ilm_rule.get("description"):
                self.na_helper.changed = True
            if self.data.get("filters") and not first_inside_second_dict_or_list(self.data.get("filters"), ilm_rule.get("filters")):
                self.na_helper.changed = True
            if self.data.get("ingestBehavior") and ilm_rule.get("ingestBehavior") != self.data.get("ingestBehavior"):
                self.na_helper.changed = True
            if self.data.get("placements") and not first_inside_second_dict_or_list(self.data.get("placements"), ilm_rule.get("placements")):
                self.na_helper.changed = True
            if self.data.get("referenceTime") and ilm_rule.get("referenceTime") != self.data.get("referenceTime"):
                self.na_helper.changed = True
            if self.data.get("tenantAccountId") and set(ilm_rule.get("tenantAccountId")) != set(self.data.get("tenantAccountId")):
                self.na_helper.changed = True

        result_message = ""
        resp_data = ilm_rule
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == "delete":
                    self.delete_ilm_rule()
                    resp_data = None
                    result_message = "ILM rule deleted"
                    __LOGGING__.append("ILM rule deleted")

                elif cd_action == "create":
                    resp_data = self.create_ilm_rule()
                    result_message = "ILM rule created"
                    __LOGGING__.append("ILM rule created")

                else:
                    resp_data = self.update_ilm_rule()
                    result_message = "ILM rule updated"
                    __LOGGING__.append("ILM rule updated")

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data, log=__LOGGING__)


def main():
    """
    Main function
    """
    na_sg_ilm_rule = ILM_rule()
    na_sg_ilm_rule.apply()


if __name__ == "__main__":
    main()
