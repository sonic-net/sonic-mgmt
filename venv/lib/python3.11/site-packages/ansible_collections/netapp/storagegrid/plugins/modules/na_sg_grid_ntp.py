#!/usr/bin/python

# (c) 2020, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Grid NTP Servers"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_ntp
short_description: NetApp StorageGRID manage external NTP servers for the grid.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '20.6.0'
author: NetApp Ansible Team (@jkandati) <ng-sg-ansibleteam@netapp.com>
description:
- Update NTP server on NetApp StorageGRID.
options:
  state:
    description:
    - Whether the specified user should exist or not.
    type: str
    choices: ['present']
    default: present
  ntp_servers:
    description:
    - List of comma separated NTP server address.
    type: list
    elements: str
    required: true
  passphrase:
    description:
    - passphrase for GRID.
    type: str
    required: true
"""

EXAMPLES = """
- name: update NTP servers
  netapp.storagegrid.na_sg_grid_ntp:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    passphrase: "{{ grid_pass }}"
    ntp_servers: "x.x.x.x,xx.x.xx.x"
"""

RETURN = """
resp:
    description: Returns information about the configured NTP servers.
    returned: success
    type: list
    elements: str
    sample: ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgGridNtp(object):
    """
    Create, modify and delete NTP entries for StorageGRID
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
                ntp_servers=dict(required=True, type="list", elements="str"),
                passphrase=dict(required=True, type="str", no_log=True),
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
        self.data = self.parameters["ntp_servers"]
        self.passphrase = self.parameters["passphrase"]
        self.ntp_input = {"passphrase": self.passphrase, "servers": self.data}

    def get_grid_ntp(self):
        # Check if tenant account exists
        # Return tenant account info if found, or None
        api = "api/v3/grid/ntp-servers"

        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def update_grid_ntp(self):
        api = "api/v3/grid/ntp-servers/update"

        response, error = self.rest_api.post(api, self.ntp_input)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """
        grid_ntp = self.get_grid_ntp()

        cd_action = self.na_helper.get_cd_action(grid_ntp, self.parameters["ntp_servers"])

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            update = False

            ntp_diff = [i for i in self.data + grid_ntp if i not in self.data or i not in grid_ntp]
            if ntp_diff:
                update = True

            if update:
                self.na_helper.changed = True

        result_message = ""
        resp_data = grid_ntp
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                resp_data = self.update_grid_ntp()
                result_message = "Grid NTP updated"

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_ntp = SgGridNtp()
    na_sg_grid_ntp.apply()


if __name__ == "__main__":
    main()
