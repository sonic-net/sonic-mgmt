#!/usr/bin/python

# (c) 2025, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Autosupport configuration"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_autosupport
short_description: Configure autosupport on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.15.0'
author: NetApp Ansible Team (@vinaykus) <ng-ansibleteam@netapp.com>
description:
  - Configure autosupport on NetApp StorageGRID.
options:
  state:
    description:
    - The alert receiver should be present.
    choices: ['present']
    default: 'present'
    type: str
  aod_enable:
    description:
    - Enable or disable sending Autosupport on Demand.
    type: bool
  available_updates_enable:
    description:
    - Whether to check for software updates.
    type: bool
  event_enable:
    description:
    - Enable event-triggered AutoSupport messages.
    type: bool
  cert_enable:
    description:
    - Enable AutoSupport certificate validation.
    type: bool
  destinations:
    description:
    - AutoSupport destinations.
    type: list
    elements: dict
    suboptions:
      hostname:
        description:
        - Hostname of the destination.
        type: str
        required: true
      port:
        description:
        - The port to use to connect to the ASUP destination.
        type: int
        required: true
      ca_cert:
        description:
        - The public CA certificate bundle in Privacy-Enhanced Mail (PEM) format.
        type: str
  transport:
    description:
    - Protocol used for AutoSupport messages.
    - If you use HTTP, use a proxy to forward the data as HTTPS. NetApp's AutoSupport servers will reject HTTP messages.
    choices: ['SMTP', 'HTTP', 'HTTPS']
    type: str
  weekly_enable:
    description:
    - Enable weekly AutoSupport messages.
    type: bool
"""

EXAMPLES = """
- name: Configure autosupport
  na_sg_grid_autosupport:
    state: present
    aod_enable: true
    available_updates_enable: true
    event_enable: true
    cert_enable: true
    destinations:
      - hostname: "example.com"
        port: 443
        ca_cert: "<CA bundle in PEM-encoding>"
    transport: "SMTP"
    weekly_enable: true
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID autosupport.
    returned: If state is 'present'.
    type: dict
    sample: {
        "aodEnable": true,
        "availableUpdatesEnable": true,
        "eventEnable": true,
        "certEnable": true,
        "destinations": [
            {
                "hostname": "example.com",
                "port": 443,
                "caCert": Null
            }
        ],
        "transport": "SMTP",
        "weeklyEnable": true
    }
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgAutosupport:
    """
    Configure autosupport for StorageGRID
    """

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.na_storagegrid_host_argument_spec()
        self.argument_spec.update(
            dict(
                state=dict(type="str", choices=["present"], default="present"),
                aod_enable=dict(required=False, type="bool"),
                available_updates_enable=dict(required=False, type="bool"),
                event_enable=dict(required=False, type="bool"),
                cert_enable=dict(required=False, type="bool"),
                destinations=dict(
                    required=False,
                    type="list",
                    elements="dict",
                    options=dict(
                        hostname=dict(required=True, type="str"),
                        port=dict(required=True, type="int"),
                        ca_cert=dict(required=False, type="str"),
                    )
                ),
                transport=dict(required=False, type="str", choices=["SMTP", "HTTP", "HTTPS"]),
                weekly_enable=dict(required=False, type="bool"),
            )
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "present", ["aod_enable", "transport", "weekly_enable", "destinations", "cert_enable", "event_enable"])],
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Checking for the parameters passed and create new parameters list
        self.data = {}

        self.data["aodEnable"] = self.parameters["aod_enable"]
        self.data["eventEnable"] = self.parameters["event_enable"]
        self.data["certEnable"] = self.parameters["cert_enable"]
        if self.parameters.get("available_updates_enable") is not None:
            self.data["availableUpdatesEnable"] = self.parameters["available_updates_enable"]
        if self.parameters["destinations"]:
            self.data["destinations"] = [
                {
                    "hostname": destination["hostname"],
                    "port": destination["port"],
                    "caCert": destination.get("ca_cert"),
                }
                for destination in self.parameters["destinations"]
            ]
        self.data["transport"] = self.parameters["transport"]
        self.data["weeklyEnable"] = self.parameters["weekly_enable"]

    def get_autosupport(self):
        """ Get autosupport configuration """
        api = "api/v4/private/autosupport"
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]

    def update_autosupport(self):
        """ Update autosupport configuration """
        api = "api/v4/private/autosupport"
        response, error = self.rest_api.put(api, self.data)

        if not response or 'data' not in response:
            self.module.fail_json(msg="Invalid response from API")
        else:
            return response["data"]

    def apply(self):
        ''' Apply autosupport configuration '''

        current_autosupport = self.get_autosupport()

        if self.parameters["state"] == "present":
            # let's see if we need to update parameters
            modify = self.na_helper.get_modified_attributes(current_autosupport, self.data)

        result_message = ""
        resp_data = current_autosupport
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            elif modify:
                resp_data = self.update_autosupport()
                result_message = "Autosupport configuration updated successfully."

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_autosupport = SgAutosupport()
    na_sg_grid_autosupport.apply()


if __name__ == "__main__":
    main()
