#!/usr/bin/python

# (c) 2020, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Grid DNS Servers"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_dns
short_description: NetApp StorageGRID manage external DNS servers for the grid.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '20.6.0'
author: NetApp Ansible Team (@joshedmonds) <ng-ansibleteam@netapp.com>
description:
- Update NetApp StorageGRID DNS addresses.
options:
  state:
    description:
    - Whether the specified DNS address should exist or not.
    - Required for all operations.
    type: str
    choices: ['present']
    default: present
  dns_servers:
    description:
    - List of comma separated DNS Addresses to be updated or delete.
    type: list
    elements: str
    required: true
"""

EXAMPLES = """
- name: update DNS servers on StorageGRID
  netapp.storagegrid.na_sg_grid_dns:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    dns_servers: "x.x.x.x,xxx.xxx.xxx.xxx"
"""

RETURN = """
resp:
    description: Returns information about the configured DNS servers.
    returned: success
    type: list
    elements: str
    sample: ["8.8.8.8", "8.8.4.4"]
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgGridDns(object):
    """
    Create, modify and delete DNS entries for StorageGRID
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
                dns_servers=dict(required=True, type="list", elements="str"),
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
        self.data = self.parameters["dns_servers"]

    def get_grid_dns(self):
        # Check if tenant account exists
        # Return tenant account info if found, or None
        api = "api/v3/grid/dns-servers"

        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def update_grid_dns(self):
        api = "api/v3/grid/dns-servers"

        response, error = self.rest_api.put(api, self.data)
        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """
        grid_dns = self.get_grid_dns()

        cd_action = self.na_helper.get_cd_action(grid_dns, self.parameters["dns_servers"])

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            update = False

            dns_diff = [i for i in self.data + grid_dns if i not in self.data or i not in grid_dns]
            if dns_diff:
                update = True

            if update:
                self.na_helper.changed = True
        result_message = ""
        resp_data = grid_dns
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                resp_data = self.update_grid_dns()
                result_message = "Grid DNS updated"

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_dns = SgGridDns()
    na_sg_grid_dns.apply()


if __name__ == "__main__":
    main()
