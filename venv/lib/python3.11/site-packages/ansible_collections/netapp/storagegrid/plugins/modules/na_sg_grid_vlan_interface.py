#!/usr/bin/python

# (c) 2025, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage VLAN Interface Configuration"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_vlan_interface
short_description: Configure VLAN interface on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.15.0'
author: NetApp Ansible Team (@vinaykus) <ng-ansibleteam@netapp.com>
description:
  - Configure VLAN interface on NetApp StorageGRID.
options:
  state:
    description:
    - Whether the vlan interface should be present or absent.
    choices: ['present', 'absent']
    default: 'present'
    type: str
  vlan_id:
    description:
    - The numeric ID of the VLAN used for VLAN tagging.
    type: int
  description:
    description:
    - Description for this VLAN interface.
    type: str
  interfaces:
    description:
    - List of node interface pairs.
    type: list
    elements: dict
    suboptions:
      node_id:
        description:
        - The node UUID.
        type: str
        required: true
      interface_name:
        description:
        - The name of the interface.
        type: str
        required: true
"""

EXAMPLES = """
- name: create vlan interface
  na_sg_grid_vlan_interface:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    vlan_id: 428
    description: "vlan interface"
    interfaces:
      - node_id: 6562d5d8-f218-45ff-a466-5bb39b729288
        interface_name: eth0

- name: modify vlan interface
  na_sg_grid_vlan_interface:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    vlan_id: 428
    description: "vlan interface is modified"
    interfaces:
      - node_id: 6562d5d8-f218-45ff-a466-5bb39b729288
        interface_name: eth2

- name: delete vlan interface
  na_sg_grid_vlan_interface:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    vlan_id: 428
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID VLAN Interface.
    returned: If state is 'present'.
    type: dict
    sample: {
        "id": "12bcw2a2-7028-4d98-89f8-972414278e3c",
        "vlanId": 430,
        "description": "vlan interface",
        "interfaces": [
            {
                "nodeId": "6562d5d8-f718-45ff-a716-5bb39b729238",
                "interface": "eth0"
            }
        ]
    }
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgVLANInterface:
    """
    Configure VLAN interface on StorageGRID
    """

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.na_storagegrid_host_argument_spec()
        self.argument_spec.update(
            dict(
                state=dict(type="str", choices=["present", "absent"], default="present"),
                vlan_id=dict(required=False, type="int"),
                description=dict(required=False, type="str"),
                interfaces=dict(
                    required=False,
                    type="list",
                    elements="dict",
                    options=dict(
                        node_id=dict(required=True, type="str"),
                        interface_name=dict(required=True, type="str"),
                    )
                )
            )
        )

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "present", ["vlan_id", "interfaces"])],
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
        self.data = {}
        self.data["vlanId"] = self.parameters["vlan_id"]
        if self.parameters.get("description"):
            self.data["description"] = self.parameters["description"]
        if self.parameters.get("interfaces"):
            self.data["interfaces"] = [
                {
                    "nodeId": interface["node_id"],
                    "interface": interface["interface_name"]
                }
                for interface in self.parameters["interfaces"]
            ]

    def get_vlan_interfaces(self):
        """ Get vlan interfaces """
        api = "api/v4/private/vlan-interfaces"
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)
        # if vlan interface with 'vlan_id' exists, return it, else none
        for vlan_interface in response["data"]:
            if vlan_interface["vlanId"] == self.parameters["vlan_id"]:
                self.id = vlan_interface["id"]
                self.data.update({"id": vlan_interface["id"]})
                return vlan_interface

        return None

    def delete_vlan_interfaces(self):
        """ Delete vlan interface """
        api = "api/v4/private/vlan-interfaces/%s" % self.id
        response, error = self.rest_api.delete(api, self.data)
        if error:
            self.module.fail_json(msg=error)

    def create_vlan_interface(self):
        """ create vlan interface """
        api = "api/v4/private/vlan-interfaces"
        response, error = self.rest_api.post(api, self.data)

        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]

    def update_vlan_interfaces(self):
        """ Update vlan interface """
        api = "api/v4/private/vlan-interfaces/%s" % self.id
        response, error = self.rest_api.put(api, self.data)

        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]

    def apply(self):
        ''' Apply vlan interface configuration '''

        current_vlan_interfaces = self.get_vlan_interfaces()

        cd_action = self.na_helper.get_cd_action(current_vlan_interfaces, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            modify = self.na_helper.get_modified_attributes(current_vlan_interfaces, self.data)

        result_message = ""
        resp_data = current_vlan_interfaces
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == "delete":
                    self.delete_vlan_interfaces()
                    resp_data = None
                    result_message = "VLAN Interface deleted"
                elif cd_action == "create":
                    resp_data = self.create_vlan_interface()
                    result_message = "VLAN Interface created"
                elif modify:
                    resp_data = self.update_vlan_interfaces()
                    result_message = "VLAN Interface updated"

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_vlan_interface = SgVLANInterface()
    na_sg_grid_vlan_interface.apply()


if __name__ == "__main__":
    main()
