#!/usr/bin/python

# (c) 2022, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Traffic Classification Policies"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: na_sg_grid_traffic_classes
short_description: Manage Traffic Classification Policy configuration on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.10.0'
author: NetApp Ansible Team (@joshedmonds) <ng-ansibleteam@netapp.com>
description:
- Create, Update, Delete Traffic Classification Policies on NetApp StorageGRID.
options:
  state:
    description:
    - Whether the specified Traffic Classification Policy should exist.
    type: str
    choices: ['present', 'absent']
    default: present
  name:
    description:
    - Name of the Traffic Classification Policy.
    type: str
  policy_id:
    description:
    - Traffic Classification Policy ID.
    - May be used for modify or delete operation.
    type: str
  description:
    description:
    - Description of the Traffic Classification Policy.
    type: str
  matchers:
    description:
    - A set of parameters to match.
    - The traffic class will match requests where any of these matchers match.
    type: list
    elements: dict
    suboptions:
      type:
        description:
        - The attribute of the request to match.
        - C(bucket) - The S3 bucket (or Swift container) being accessed.
        - C(bucket-regex) - A regular expression to evaluate against the S3 bucket (or Swift container) being accessed.
        - C(cidr) - Matches if the client request source IP is in the specified IPv4 CIDR (RFC4632).
        - C(tenant) - Matches if the S3 bucket (or Swift container) is owned by the tenant account with this ID.
        choices: ['bucket', 'bucket-regex', 'cidr', 'endpoint', 'tenant']
        type: str
        required: true
      inverse:
        description:
        - If I(true), entities that match the value are excluded.
        type: bool
        default: false
      members:
        description:
        - A list of members to match on.
        type: list
        elements: str
        required: true
  limits:
    description:
    - Optional limits to impose on client requests matched by this traffic class.
    - Only one of each limit type can be specified.
    type: list
    elements: dict
    suboptions:
      type:
        description:
        - The type of limit to apply.
        - C(aggregateBandwidthIn) - The maximum combined upload bandwidth in bytes/second of all concurrent requests that match this policy.
        - C(aggregateBandwidthOut) - The maximum combined download bandwidth in bytes/second of all concurrent requests that match this policy.
        - C(concurrentReadRequests) - The maximum number of download requests that can be in progress at the same time.
        - C(concurrentWriteRequests) - The maximum number of upload requests that can be in progress at the same time.
        - C(readRequestRate) - The maximum number of download requests that can be started each second.
        - C(writeRequestRate) - The maximum number of download requests that can be started each second.
        - C(perRequestBandwidthIn) - The maximum upload bandwidth in bytes/second allowed for each request that matches this policy.
        - C(perRequestBandwidthOut) - The maximum download bandwidth in bytes/second allowed for each request that matches this policy.
        choices: [
            'aggregateBandwidthIn',
            'aggregateBandwidthOut',
            'concurrentReadRequests',
            'concurrentWriteRequests',
            'readRequestRate',
            'writeRequestRate',
            'perRequestBandwidthIn',
            'perRequestBandwidthOut'
        ]
        type: str
        required: true
      value:
        description:
        - The limit to apply.
        - Limit values are type specific.
        type: int
        required: true
"""

EXAMPLES = """
- name: create Traffic Classification Policy with bandwidth limit on buckets
  netapp.storagegrid.na_sg_grid_traffic_classes:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    name: Traffic-Policy1
    matchers:
      - type: bucket
        members: bucket1,anotherbucket
    limits:
      - type: aggregateBandwidthOut
        value: 100000000

- name: create Traffic Classification Policy with bandwidth limits except for specific tenant account
  netapp.storagegrid.na_sg_grid_traffic_classes:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    name: Fabricpool-Policy
    description: "Limit all to 500MB/s except FabricPool tenant"
    matchers:
      - type: tenant
        inverse: true
        members: 12345678901234567890
    limits:
      - type: aggregateBandwidthIn
        value: 50000000
      - type: aggregateBandwidthOut
        value: 50000000

- name: rename Traffic Classification Policy
  netapp.storagegrid.na_sg_grid_traffic_classes:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    policy_id: 00000000-0000-0000-0000-000000000000
    name: Traffic-Policy1-New-Name
    matchers:
      - type: bucket
        members: bucket1,anotherbucket
    limits:
      - type: aggregateBandwidthOut
        value: 100000000

- name: delete Traffic Classification Policy
  netapp.storagegrid.na_sg_grid_traffic_classes:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: absent
    name: Traffic-Policy1
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID Traffic Classification Policy.
    returned: success
    type: dict
    sample: {
        "id": "6b2946e6-7fed-40d0-9262-8e922580aba7",
        "name": "Traffic-Policy1",
        "description": "Traffic Classification Policy 1",
        "matchers": [
            {
                "type": "cidr",
                "inverse": False,
                "members": [
                    "192.168.50.0/24"
                ]
            },
            {
                "type": "bucket",
                "inverse": False,
                "members": [
                    "mybucket1",
                    "mybucket2"
                ]
            },
        ],
        "limits": [
            {
                "type": "aggregateBandwidthOut",
                "value": 100000000
            }
        ],
    }
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgGridTrafficClasses:
    """
    Create, modify and delete Traffic Classification Policies for StorageGRID
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
                name=dict(required=False, type="str"),
                policy_id=dict(required=False, type="str"),
                description=dict(required=False, type="str"),
                matchers=dict(
                    required=False,
                    type="list",
                    elements="dict",
                    options=dict(
                        type=dict(
                            required=True,
                            type="str",
                            choices=["bucket", "bucket-regex", "cidr", "endpoint", "tenant"],
                        ),
                        inverse=dict(required=False, type="bool", default="false"),
                        members=dict(required=True, type="list", elements="str"),
                    ),
                ),
                limits=dict(
                    required=False,
                    type="list",
                    elements="dict",
                    options=dict(
                        type=dict(
                            required=True,
                            type="str",
                            choices=[
                                "aggregateBandwidthIn",
                                "aggregateBandwidthOut",
                                "concurrentReadRequests",
                                "concurrentWriteRequests",
                                "readRequestRate",
                                "writeRequestRate",
                                "perRequestBandwidthIn",
                                "perRequestBandwidthOut",
                            ],
                        ),
                        value=dict(required=True, type="int"),
                    ),
                ),
            )
        )

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "present", ["name"])],
            required_one_of=[("name", "policy_id")],
        )

        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Checking for the parameters passed and create new parameters list
        self.data = {}

        if self.parameters["state"] == "present":
            for k in ["name", "description", "matchers", "limits"]:
                if self.parameters.get(k) is not None:
                    self.data[k] = self.parameters[k]

    def get_traffic_class_policy_id(self):
        # Check if Traffic Classification Policy exists
        # Return policy ID if found, or None
        api = "api/v3/grid/traffic-classes/policies"
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        return next((item["id"] for item in response.get("data") if item["name"] == self.parameters["name"]), None)

    def get_traffic_class_policy(self, policy_id):
        api = "api/v3/grid/traffic-classes/policies/%s" % policy_id
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def create_traffic_class_policy(self):
        api = "api/v3/grid/traffic-classes/policies"
        # self.module.fail_json(msg=self.data)
        response, error = self.rest_api.post(api, self.data)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def delete_traffic_class_policy(self, policy_id):
        api = "api/v3/grid/traffic-classes/policies/%s" % policy_id
        dummy, error = self.rest_api.delete(api, self.data)

        if error:
            self.module.fail_json(msg=error)

    def update_traffic_class_policy(self, policy_id):
        api = "api/v3/grid/traffic-classes/policies/%s" % policy_id
        response, error = self.rest_api.put(api, self.data)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """

        traffic_class_policy = None

        if self.parameters.get("policy_id"):
            traffic_class_policy = self.get_traffic_class_policy(self.parameters["policy_id"])
        else:
            policy_id = self.get_traffic_class_policy_id()
            if policy_id:
                traffic_class_policy = self.get_traffic_class_policy(policy_id)

        cd_action = self.na_helper.get_cd_action(traffic_class_policy, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            modify = self.na_helper.get_modified_attributes(traffic_class_policy, self.data)

        result_message = ""
        resp_data = {}

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == "delete":
                self.delete_traffic_class_policy(traffic_class_policy["id"])
                result_message = "Traffic Classification Policy deleted"
            elif cd_action == "create":
                resp_data = self.create_traffic_class_policy()
                result_message = "Traffic Classification Policy created"
            elif modify:
                resp_data = self.update_traffic_class_policy(traffic_class_policy["id"])
                result_message = "Traffic Classification Policy updated"

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_traffic_classes = SgGridTrafficClasses()
    na_sg_grid_traffic_classes.apply()


if __name__ == "__main__":
    main()
