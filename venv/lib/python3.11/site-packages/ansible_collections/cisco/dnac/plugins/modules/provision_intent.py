#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Abinash Mishra"
DOCUMENTATION = r"""
---
module: provision_intent
short_description: Resource module for provision functions
description:
  - Manage operation related to wired and wireless provisioning
  - API to re-provision provisioned devices
  - API to un-provision provisioned devices
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.intent_params
author: Abinash Mishra (@abimishr)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst
      Center config after applying the playbook config.
    type: bool
    default: false
  state:
    description: The state of DNAC after module completion.
    type: str
    choices: [merged, deleted]
    default: merged
  config:
    description:
      - List of details of device being managed.
    type: list
    elements: dict
    required: true
    suboptions:
      management_ip_address:
        description: Management Ip Address .
        type: str
        required: true
      site_name:
        description: Name of site where the device needs
          to be added.
        type: str
      managed_ap_locations:
        description: Location of the sites allocated
          for the APs
        type: list
        elements: str
      dynamic_interfaces:
        description: Interface details of the controller
        type: list
        elements: dict
        suboptions:
          interface_ip_address:
            description: Ip Address allocated to the
              interface
            type: str
          interface_netmask_in_c_i_d_r:
            description: Ip Address allocated to the
              interface
            type: int
          interface_gateway:
            description: Ip Address allocated to the
              interface
            type: str
          lag_or_port_number:
            description: Ip Address allocated to the
              interface
            type: int
          vlan_id:
            description: Ip Address allocated to the
              interface
            type: int
          interface_name:
            description: Ip Address allocated to the
              interface
            type: str
requirements:
  - dnacentersdk == 2.4.5
  - python >= 3.9
notes:
  - SDK Methods used are sites.Sites.get_site,
    devices.Devices.get_network_device_by_ip,
    task.Task.get_task_by_id,
    sda.Sda.get_provisioned_wired_device,
    sda.Sda.re_provision_wired_device,
    sda.Sda.provision_wired_device,
    wireless.Wireless.provision
  - Paths used are
    get /dna/intent/api/v1/site get /dna/intent/api/v1/network-device/ip-address/{ipAddress}
    get /dna/intent/api/v1/task/{taskId} get /dna/intent/api/v1/business/sda/provision-device
    put /dna/intent/api/v1/business/sda/provision-device
    post /dna/intent/api/v1/business/sda/provision-device
    post /dna/intent/api/v1/wireless/provision
"""
EXAMPLES = r"""
---
- name: Create/Modify a new provision
  cisco.dnac.provision_intent:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    state: merged
    config:
      - site_name: string
        management_ip_address: string
        managed_ap_locations: list
        dynamic_interfaces:
          - vlan_id: integer
            interface_name: string
            interface_ip_address: string
            interface_gateway: string
            interface_netmask_in_c_i_d_r: integer
            lag_or_port_number: integer
"""
RETURN = r"""
# Case_1: Successful creation/updation/deletion of provision
response_1:
  description: A dictionary with details of provision is returned
  returned: always
  type: dict
  sample: >
    {
      "response":
      {
        "response": String,
        "version": String
        },
      "msg": String
    }
# Case_2: Error while creating a provision
response_2:
  description: A list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  sample: >
    {
      "response": [],
      "msg": String
    }
# Case_3: Already exists and requires no update
response_3:
  description: A dictionary with the exisiting details as returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": String,
      "msg": String
    }
"""
import time
import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)


class Dnacprovision(DnacBase):
    """
    Class containing member attributes for provision intent module
    """

    def __init__(self, module):
        super().__init__(module)

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.
        Args:
            self: The instance of the class containing the 'config' attribute to be validated.
        Returns:
            The method returns an instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either 'success' or 'failed').
                - self.validated_config: If successful, a validated version of the
                  'config' parameter.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
            If the validation succeeds, 'self.status' will be 'success' and
            'self.validated_config' will contain the validated configuration. If it fails,
            'self.status' will be 'failed', and 'self.msg' will describe the validation issues.
        """

        if not self.config:
            self.msg = "config not available in playbook for validattion"
            self.status = "success"
            return self

        provision_spec = {
            "management_ip_address": {"type": "str", "required": True},
            "site_name": {"type": "str", "required": True},
            "managed_ap_locations": {
                "type": "list",
                "required": False,
                "elements": "str",
            },
            "dynamic_interfaces": {
                "type": "list",
                "required": False,
                "elements": "dict",
            },
        }
        # Validate provision params
        valid_provision, invalid_params = validate_list_of_dicts(
            self.config, provision_spec
        )
        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(
                "\n".join(invalid_params)
            )
            self.status = "failed"
            return self

        self.validated_config = valid_provision
        self.log(str(valid_provision))
        self.msg = "Successfully validated input"
        self.status = "success"
        return self

    def get_dev_type(self):
        """
        Fetches the type of device (wired/wireless)

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - device_type: A string indicating the type of the
                       device (wired/wireless).
        Example:
          Post creation of the validated input, we this method gets the
          type of the device.
        """

        dev_response = self.dnac_apply["exec"](
            family="devices",
            function="get_network_device_by_ip",
            params={"ip_address": self.validated_config[0]["management_ip_address"]},
            op_modifies=True,
        )

        dev_dict = dev_response.get("response")
        device_family = dev_dict["family"]

        if device_family == "Wireless Controller":
            device_type = "wireless"
        elif device_family in ["Switches and Hubs", "Routers"]:
            device_type = "wired"
        else:
            device_type = None
        return device_type

    def get_task_status(self, task_id=None):
        """
        Fetches the status of the task once any provision API is called

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - result: A dict indiacting wheter the task was succesful or not
        Example:
          Post creation of the provision task, this method fetheches the task
          status.

        """
        result = False
        params = {"task_id": task_id}
        while True:
            response = self.dnac_apply["exec"](
                family="task",
                function="get_task_by_id",
                params=params,
                op_modifies=True,
            )
            response = response.response
            if response.get("isError") or re.search(
                "failed", response.get("progress"), flags=re.IGNORECASE
            ):
                msg = (
                    "Discovery task with id {0} has not completed - Reason: {1}".format(
                        task_id, response.get("failureReason")
                    )
                )
                self.module.fail_json(msg=msg)
                return False

            if response.get("progress") != "In Progress":
                result = True
                break

            time.sleep(3)
        self.result.update(dict(discovery_task=response))
        return result

    def get_site_type(self, site_name=None):
        """
        Fetches the type of site

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - site_type: A string indicating the type of the
                       site (area/building/floor).
        Example:
          Post creation of the validated input, we this method gets the
          type of the site.
        """

        try:
            response = self.dnac_apply["exec"](
                family="sites",
                function="get_site",
                params={"name": site_name},
                op_modifies=True,
            )
        except Exception:
            self.module.fail_json(msg="Site not found", response=[])

        if response:
            self.log(str(response))
            site = response.get("response")
            site_additional_info = site[0].get("additionalInfo")
            for item in site_additional_info:
                if item["nameSpace"] == "Location":
                    site_type = item.get("attributes").get("type")

        return site_type

    def get_wired_params(self):
        """
        Prepares the payload for provisioning of the wired devices

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - wired_params: A dictionary containing all the values indicating
                          management IP address of the device and the hierarchy
                          of the site.
        Example:
          Post creation of the validated input, it fetches the required
          paramters and stores it for further processing and calling the
          parameters in other APIs.
        """

        wired_params = {
            "deviceManagementIpAddress": self.validated_config[0][
                "management_ip_address"
            ],
            "siteNameHierarchy": self.validated_config[0].get("site_name"),
        }

        return wired_params

    def get_wireless_params(self):
        """
        Prepares the payload for provisioning of the wireless devices

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - wireless_params: A list of dictionary containing all the values indicating
                          management IP address of the device, hierarchy
                          of the site, AP Location of the wireless controller and details
                          of the interface
        Example:
          Post creation of the validated input, it fetches the required
          paramters and stores it for further processing and calling the
          parameters in other APIs.
        """

        wireless_params = [
            {
                "site": self.validated_config[0].get("site_name"),
                "managedAPLocations": self.validated_config[0].get(
                    "managed_ap_locations"
                ),
            }
        ]
        for ap_loc in wireless_params[0]["managedAPLocations"]:
            if self.get_site_type(site_name=ap_loc) != "floor":
                self.module.fail_json(
                    msg="Managed AP Location must be a floor", response=[]
                )

        wireless_params[0]["dynamicInterfaces"] = []
        for interface in self.validated_config[0].get("dynamic_interfaces"):
            interface_dict = {
                "interfaceIPAddress": interface.get("interface_ip_address"),
                "interfaceNetmaskInCIDR": interface.get("interface_netmask_in_c_i_d_r"),
                "interfaceGateway": interface.get("interface_gateway"),
                "lagOrPortNumber": interface.get("lag_or_port_number"),
                "vlanId": interface.get("vlan_id"),
                "interfaceName": interface.get("interface_name"),
            }
            wireless_params[0]["dynamicInterfaces"].append(interface_dict)
        response = self.dnac_apply["exec"](
            family="devices",
            function="get_network_device_by_ip",
            params={
                "management_ip_address": self.validated_config[0][
                    "management_ip_address"
                ]
            },
            op_modifies=True,
        )

        wireless_params[0]["deviceName"] = response.get("response")[0].get("hostname")
        return wireless_params

    def get_want(self):
        """
        Get all provision related informantion from the playbook
        Args:
            self: The instance of the class containing the 'config' attribute to be validated.
            config: validated config passed from the playbook
        Returns:
            The method returns an instance of the class with updated attributes:
                - self.want: A dictionary of paramters obtained from the playbook
                - self.msg: A message indicating all the paramters from the playbook are
                collected
                - self.status: Success
        Example:
            It stores all the paramters passed from the playbook for further processing
            before calling the APIs
        """

        self.want = {}
        self.want["device_type"] = self.get_dev_type()
        if self.want["device_type"] == "wired":
            self.want["prov_params"] = self.get_wired_params()
        elif self.want["device_type"] == "wireless":
            self.want["prov_params"] = self.get_wireless_params()
        else:
            self.log("Passed devices are neither wired or wireless devices")

        self.msg = (
            "Successfully collected all parameters from playbook " + "for comparison"
        )
        self.status = "success"
        return self

    def get_diff_merged(self):
        """
        Add to provision database
        Args:
            self: An instance of a class used for interacting with Cisco DNA Center.
        Returns:
            object: An instance of the class with updated results and status
            based on the processing of differences.
        Description:
            The function processes the differences and, depending on the
            changes required, it may add, update,or resynchronize devices in
            Cisco DNA Center. The updated results and status are stored in the
            class instance for further use.
        """

        device_type = self.want.get("device_type")
        if device_type == "wired":
            try:
                status_response = self.dnac_apply["exec"](
                    family="sda",
                    function="get_provisioned_wired_device",
                    op_modifies=True,
                    params={
                        "device_management_\
                        ip_address": self.validated_config[
                            0
                        ][
                            "management_ip_address"
                        ]
                    },
                )
            except Exception:
                status_response = {}

            status = status_response.get("status")

            if status == "success":
                response = self.dnac_apply["exec"](
                    family="sda",
                    function="re_provision_wired_device",
                    op_modifies=True,
                    params=self.want["prov_params"],
                )
            else:
                response = self.dnac_apply["exec"](
                    family="sda",
                    function="provision_wired_device",
                    op_modifies=True,
                    params=self.want["prov_params"],
                )

        elif device_type == "wireless":
            response = self.dnac_apply["exec"](
                family="wireless",
                function="provision",
                op_modifies=True,
                params=self.want["prov_params"],
            )

        else:
            self.result["msg"] = "Passed device is neither wired nor wireless"
            self.result["response"] = self.want["prov_params"]
            return self

        task_id = response.get("taskId")
        provision_info = self.get_task_status(task_id=task_id)
        self.result["changed"] = True
        self.result["msg"] = "Provision done Successfully"
        self.result["diff"] = self.validated_config
        self.result["response"] = task_id

        return self

    def get_diff_deleted(self):
        """
        Delete from provision database
        Args:
            self: An instance of a class used for interacting with Cisco DNA Center
        Returns:
            self: An instance of the class with updated results and status based on
            the deletion operation.
        Description:
            This function is responsible for removing devices from the Cisco DNA Center PnP GUI and
            raise Exception if any error occured.
        """

        device_type = self.want.get("device_type")

        if device_type != "wired":
            self.result["msg"] = "APIs are not supported for the device"
            return self

        try:
            status_response = self.dnac_apply["exec"](
                family="sda",
                function="get_provisioned_wired_device",
                op_modifies=True,
                params={
                    "device_management_\
                    ip_address": self.validated_config[
                        0
                    ][
                        "management_ip_address"
                    ]
                },
            )

        except Exception:
            status_response = {}

        status = status_response.get("status")

        if status != "success":
            self.result["msg"] = "Passed IP address is not provisioned"
            self.result["response"] = self.want["prov_params"]
            return self

        response = self.dnac_apply["exec"](
            family="sda",
            function="delete_provisioned_wired_device",
            op_modifies=True,
            params={
                "device_management_\
                ip_address": self.validated_config[
                    0
                ][
                    "management_ip_address"
                ]
            },
        )

        task_id = response.get("taskId")
        deletion_info = self.get_task_status(task_id=task_id)
        self.result["changed"] = True
        self.result["msg"] = "Deletion done Successfully"
        self.result["diff"] = self.validated_config
        self.result["response"] = task_id

        return self


def main():
    """
    main entry point for module execution
    """

    element_spec = {
        "dnac_host": {"required": True, "type": "str"},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": "True"},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "validate_response_schema": {"type": "bool", "default": True},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
    }
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    dnac_provision = Dnacprovision(module)

    state = dnac_provision.params.get("state")
    if state not in dnac_provision.supported_states:
        dnac_provision.status = "invalid"
        dnac_provision.msg = "State {0} is invalid".format(state)
        dnac_provision.check_return_status()

    dnac_provision.validate_input().check_return_status()

    for config in dnac_provision.validated_config:
        dnac_provision.reset_values()
        dnac_provision.get_want().check_return_status()
        dnac_provision.get_diff_state_apply[state]().check_return_status()

    module.exit_json(**dnac_provision.result)


if __name__ == "__main__":
    main()
