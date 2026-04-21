#!/usr/bin/python

# (c) 2025, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage endpoint domain name"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_domain_name
short_description: Configure endpoint domain name on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.15.0'
author: NetApp Ansible Team (@vinaykus) <ng-ansibleteam@netapp.com>
description:
  - Configure endpoint domain name on NetApp StorageGRID.
options:
  state:
    description:
    - The endpoint domain name should be present.
    choices: ['present']
    default: 'present'
    type: str
  domain_name:
    description:
    - List of domain names to be configured.
    required: true
    type: list
    elements: str
"""

EXAMPLES = """
- name: Configure endpoint domain name
  na_sg_grid_domain_name:
    state: present
    validate_certs: false
    domain_name:
      - example1.com
      - example2.com
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID domain name.
    returned: If state is 'present'.
    type: dict
    sample: [
        "example1.com",
        "example2.com"
    ]
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgDomainName:
    """
    Configure endpoint domain name for StorageGRID
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
                domain_name=dict(required=True, type="list", elements="str"),
            )
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Get API version
        self.rest_api.get_sg_product_version(api_root="grid")

        # Checking for the parameters passed and create new parameters list
        self.data = []
        self.data = self.parameters["domain_name"]

    def get_domain_name(self):
        """ Get endpoint domain name """
        api = "api/v4/grid/domain-names"
        response, error = self.rest_api.get(api)

        if not response or 'data' not in response:
            self.module.fail_json(msg="Invalid response from API")
        else:
            return response["data"]

    def update_domain_name(self):
        """ Update endpoint domain name """
        api = "api/v4/grid/domain-names"
        response, error = self.rest_api.put(api, self.data)

        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]

    def apply(self):
        ''' Apply endpoint domain name '''

        current_domain_name = self.get_domain_name()

        if self.parameters["state"] == "present":
            modify = False
            # Check if domain name is not present in the current domain name list
            if not current_domain_name and self.data:
                modify = True
            else:
                for domain in current_domain_name:
                    if domain not in self.data:
                        modify = True

            if modify:
                self.na_helper.changed = True

        result_message = ""
        resp_data = current_domain_name
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            elif modify:
                resp_data = self.update_domain_name()
                result_message = "Endpoint domain name updated successfully."

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_domain_name = SgDomainName()
    na_sg_grid_domain_name.apply()


if __name__ == "__main__":
    main()
