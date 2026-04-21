#!/usr/bin/python

# (c) 2022, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage HA Groups"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: na_sg_grid_ha_group
short_description: Manage high availability (HA) group configuration on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.10.0'
author: NetApp Ansible Team (@joshedmonds) <ng-ansibleteam@netapp.com>
description:
- Create, Update, Delete HA Groups on NetApp StorageGRID.
options:
  state:
    description:
    - Whether the specified HA Group should exist.
    type: str
    choices: ['present', 'absent']
    default: present
  name:
    description:
    - Name of the HA Group.
    type: str
  ha_group_id:
    description:
    - HA Group ID.
    - May be used for modify or delete operation.
    type: str
  description:
    description:
    - Description of the HA Group.
    type: str
  gateway_cidr:
    description:
    - CIDR for the gateway IP and VIP subnet.
    type: str
  virtual_ips:
    description:
    - A list of virtual IP addresses.
    type: list
    elements: str
  interfaces:
    description:
    - A set of StorageGRID node interface pairs.
    - The primary interface is specified first, followed by the other interface pairs in failover order.
    type: list
    elements: dict
    suboptions:
      node:
        description:
        - Name of the StorageGRID node.
        type: str
      interface:
        description:
        - The interface to bind to. eth0 corresponds to the Grid Network, eth1 to the Admin Network, and eth2 to the Client Network.
        type: str
"""

EXAMPLES = """
- name: create HA Group
  netapp.storagegrid.na_sg_grid_ha_group:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    name: Site1-HA-Group
    description: "Site 1 HA Group"
    gateway_cidr: 192.168.50.1/24
    virtual_ips: 192.168.50.5
    interfaces:
      - node: SITE1-ADM1
        interface: eth2
      - node: SITE1-G1
        interface: eth2

- name: add VIP to HA Group
  netapp.storagegrid.na_sg_grid_ha_group:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    name: Site1-HA-Group
    description: "Site 1 HA Group"
    gateway_cidr: 192.168.50.1/24
    virtual_ips: 192.168.50.5,192.168.50.6
    interfaces:
      - node: SITE1-ADM1
        interface: eth2
      - node: SITE1-G1
        interface: eth2

- name: rename HA Group
  netapp.storagegrid.na_sg_grid_ha_group:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    ha_group_id: 00000000-0000-0000-0000-000000000000
    name: Site1-HA-Group-New-Name
    description: "Site 1 HA Group"
    gateway_cidr: 192.168.50.1/24
    virtual_ips: 192.168.50.5
    interfaces:
      - node: SITE1-ADM1
        interface: eth2
      - node: SITE1-G1
        interface: eth2

- name: delete HA Group
  netapp.storagegrid.na_sg_grid_ha_group:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: absent
    name: Site1-HA-Group
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID HA Group.
    returned: success
    type: dict
    sample: {
        "description": "Site 1 HA Group",
        "gatewayCidr": "192.168.50.1/24",
        "id": "bb386f30-805d-4fec-a2c5-85790b460db0",
        "interfaces": [
            {
                "interface": "eth2",
                "nodeId": "0b1866ed-d6e7-41b4-815f-bf867348b76b"
            },
            {
                "interface": "eth2",
                "nodeId": "7bb5bf05-a04c-4344-8abd-08c5c4048666"
            }
        ],
        "name": "Site1-HA-Group",
        "virtualIps": [
            "192.168.50.5",
            "192.168.50.6"
        ]
    }
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgGridHaGroup:
    """
    Create, modify and delete HA Group configurations for StorageGRID
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
                ha_group_id=dict(required=False, type="str"),
                description=dict(required=False, type="str"),
                gateway_cidr=dict(required=False, type="str"),
                virtual_ips=dict(required=False, type="list", elements="str"),
                interfaces=dict(
                    required=False,
                    type="list",
                    elements="dict",
                    options=dict(
                        node=dict(required=False, type="str"),
                        interface=dict(required=False, type="str"),
                    ),
                ),
            )
        )

        parameter_map = {
            "name": "name",
            "description": "description",
            "gateway_cidr": "gatewayCidr",
            "virtual_ips": "virtualIps",
        }

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "present", ["name", "gateway_cidr", "virtual_ips", "interfaces"])],
            required_one_of=[("name", "ha_group_id")],
        )

        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Checking for the parameters passed and create new parameters list
        self.data = {}

        if self.parameters["state"] == "present":
            for k in parameter_map.keys():
                if self.parameters.get(k) is not None:
                    self.data[parameter_map[k]] = self.parameters[k]

            if self.parameters.get("interfaces") is not None:
                self.data["interfaces"] = self.build_node_interface_list()

    def build_node_interface_list(self):
        node_interfaces = []

        api = "api/v3/grid/node-health"
        nodes, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        for node_interface in self.parameters["interfaces"]:
            node_dict = {}
            node = next((item for item in nodes["data"] if item["name"] == node_interface["node"]), None)
            if node is not None:
                node_dict["nodeId"] = node["id"]
                node_dict["interface"] = node_interface["interface"]
                node_interfaces.append(node_dict)
            else:
                self.module.fail_json(msg="Node '%s' is invalid" % node_interface["node"])

        return node_interfaces

    def get_ha_group_id(self):
        # Check if HA Group exists
        # Return HA Group info if found, or None
        api = "api/v3/private/ha-groups"
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        return next((item["id"] for item in response.get("data") if item["name"] == self.parameters["name"]), None)

    def get_ha_group(self, ha_group_id):
        api = "api/v3/private/ha-groups/%s" % ha_group_id
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def create_ha_group(self):
        api = "api/v3/private/ha-groups"
        response, error = self.rest_api.post(api, self.data)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def delete_ha_group(self, ha_group_id):
        api = "api/v3/private/ha-groups/%s" % ha_group_id
        dummy, error = self.rest_api.delete(api, self.data)

        if error:
            self.module.fail_json(msg=error)

    def update_ha_group(self, ha_group_id):
        api = "api/v3/private/ha-groups/%s" % ha_group_id
        response, error = self.rest_api.put(api, self.data)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """

        ha_group = None

        if self.parameters.get("ha_group_id"):
            ha_group = self.get_ha_group(self.parameters["ha_group_id"])
        else:
            ha_group_id = self.get_ha_group_id()
            if ha_group_id:
                ha_group = self.get_ha_group(ha_group_id)

        cd_action = self.na_helper.get_cd_action(ha_group, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            modify = self.na_helper.get_modified_attributes(ha_group, self.data)

        result_message = ""
        resp_data = {}

        # check if we are in check mode
        if self.module.check_mode:
            if cd_action == "delete":
                self.module.exit_json(changed=True, msg="HA Group would be deleted.")
            elif cd_action == "create":
                self.module.exit_json(changed=True, msg="HA Group would be created.")
            elif modify:
                self.module.exit_json(changed=True, msg="HA Group would be updated.")
            else:
                self.module.exit_json(changed=False, msg="No changes would be made.")

        if self.na_helper.changed:
            if cd_action == "delete":
                self.delete_ha_group(ha_group["id"])
                result_message = "HA Group deleted"
            elif cd_action == "create":
                resp_data = self.create_ha_group()
                result_message = "HA Group created"
            elif modify:
                resp_data = self.update_ha_group(ha_group["id"])
                result_message = "HA Group updated"

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_ha_group = SgGridHaGroup()
    na_sg_grid_ha_group.apply()


if __name__ == "__main__":
    main()
