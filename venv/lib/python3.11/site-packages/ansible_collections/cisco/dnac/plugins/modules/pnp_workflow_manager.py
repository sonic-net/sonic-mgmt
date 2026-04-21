#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = (
    "Abinash Mishra, Madhan Sankaranarayanan, Rishita Chowdhary, A Mohamed Rafeek"
)
DOCUMENTATION = r"""
---
module: pnp_workflow_manager
short_description: Resource module for Site and PnP
  related functions
description:
  - Manage operations add device, claim device and unclaim
    device of Onboarding Configuration(PnP) resource
  - API to add device to pnp inventory and claim it
    to a site.
  - API to delete device from the pnp inventory.
  - API to reset the device from errored state.
version_added: 6.28.0
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Abinash Mishra (@abimishr)
  - Madhan Sankaranarayanan (@madhansansel)
  - Rishita Chowdhary (@rishitachowdhary)
  - A Mohamed Rafeek (@mabdulk2)
options:
  config_verify:
    description: |
      Set to True to verify the Cisco Catalyst Center config after applying the
      playbook config.
    type: bool
    default: false
  state:
    description: The state of Cisco Catalyst Center
      after module completion.
    type: str
    choices: [merged, deleted]
    default: merged
  config:
    description: |
      List of details of device being managed.
    type: list
    elements: dict
    required: true
    suboptions:
      device_info:
        description: |
          1. Provides the device-specific information required for adding devices
          to the PnP database that are not already present.
          2. For adding a single device, the list should contain exactly one set
          of device information. If a site name is also provided, the device
          can be claimed immediately after being added.
          3. For bulk import, the list must contain information for more than one
          device. Bulk import is intended solely for adding devices; claiming
          must be performed with separate tasks or configurations.
        type: list
        required: true
        elements: dict
        suboptions:
          hostname:
            description:
              - Defines the desired hostname for the
                PnP device after it has been claimed.
              - The hostname can only be assigned or
                changed during the claim process, not
                during bulk or single device additions.
            type: str
            required: false
          state:
            description:
              - Represents the onboarding state of the
                PnP device.
              - Possible values are 'Unclaimed', 'Claimed',
                or 'Provisioned'.
            type: str
            required: false
          pid:
            description: Pnp Device's pid.
            type: str
            required: true
          serial_number:
            description: Pnp Device's serial_number.
            type: str
            required: true
          is_sudi_required:
            description: Sudi Authentication requiremnet's
              flag.
            type: bool
            required: false
          authorize:
            description: |
              - Set the authorization flag for PnP devices to enable provisioning after claiming.
              - When set to true, devices in "Pending Authorization" state will be automatically authorized.
              - This flag moves devices from "Pending Authorization" to "Authorized" state, allowing them to proceed with the provisioning workflow.
              - Authorization is performed after successful device import (bulk operations) or device addition (single device operations).
              - If not specified, devices will remain in their current authorization state and may require manual authorization.
              - This parameter only applies to devices that support the authorization workflow in their PnP process.
              - Authorization is skipped for devices that are not in "Pending Authorization" state.
              - Supported from Cisco Catalyst Center release version 2.3.7.9 onwards.
            type: bool
            required: false
            default: false
      site_name:
        description: Name of the site for which the
          device will be claimed.
        type: str
        required: false
      project_name:
        description: Name of the project under which
          the template is present.
        type: str
        default: 'Onboarding Configuration'
        required: false
      template_name:
        description:
          - Name of the template to be configured on
            the device.
          - Supported for EWLC from Cisco Catalyst Center
            release version 2.3.7.x onwards.
        type: str
        required: false
      template_params:
        description:
          - Parameter values for the parameterised templates.
          - Each varibale has a value that needs to
            be passed as key-value pair in the dictionary.
            We can pass values as variable_name:variable_value.
          - Supported for EWLC from Cisco Catalyst Center
            release version 2.3.7.x onwards.
        type: dict
        required: false
      image_name:
        description: Name of the image to be configured
          on the device.
        type: str
        required: false
      golden_image:
        description: Specifies whether the configured
          image is tagged as a golden image.
        type: bool
        required: false
      pnp_type:
        description: |
          Specifies the device type for the Plug and Play (PnP) device. -
          Options include 'Default', 'CatalystWLC', 'AccessPoint', or
          'StackSwitch'. - 'Default' is applicable to switches and routers. -
          'CatalystWLC' should be selected for 9800 series wireless controllers.
          - 'AccessPoint' is used when claiming an access point. - 'StackSwitch'
          should be chosen for a group of switches that operate as a single
          switch, typically used in the access layer.
        type: str
        required: false
        choices:
          - Default
          - CatalystWLC
          - AccessPoint
          - StackSwitch
        default: Default
      static_ip:
        description: Management IP address of the Wireless
          Controller.
        type: str
        required: false
      subnet_mask:
        description: Subnet mask of the management IP
          address of the Wireless Controller.
        type: str
        required: false
      gateway:
        description: Gateway IP address of the Wireless
          Controller for connectivity.
        type: str
        required: false
      vlan_id:
        description: VLAN ID allocated for claiming
          the Wireless Controller.
        type: str
        required: false
      ip_interface_name:
        description:
          - Specifies the interface name utilized for
            Plug and Play (PnP) by the Wireless Controller.
          - Ensure this interface is pre-configured
            on the controller before device claiming.
        type: str
        required: false
      rf_profile:
        description:
          - Radio Frequecy (RF) profile of the AP being
            claimed.
          - RF Profiles allow you to tune groups of
            APs that share a common coverage zone together.
          - They selectively change how Radio Resource
            Management will operate the APs within that
            coverage zone.
          - HIGH RF profile allows you to use more power
            and allows to join AP with the client in
            an easier fashion.
          - TYPICAL RF profile is a blend of moderate
            power and moderate visibility to the client.
          - LOW RF profile allows you to consume lesser
            power and has least visibility to the client.
        type: str
        choices:
          - HIGH
          - LOW
          - TYPICAL
        required: false
requirements:
  - dnacentersdk == 2.6.10
  - python >= 3.9
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.add_device,
    device_onboarding_pnp.DeviceOnboardingPnp.get_device_list,
    device_onboarding_pnp.DeviceOnboardingPnp.claim_a_device_to_a_site,
    device_onboarding_pnp.DeviceOnboardingPnp.delete_device_by_id_from_pnp,
    device_onboarding_pnp.DeviceOnboardingPnp.get_device_count,
    device_onboarding_pnp.DeviceOnboardingPnp.get_device_by_id,
    device_onboarding_pnp.DeviceOnboardingPnp.update_device,
    sites.Sites.get_site,
    software_image_management_swim.SoftwareImageManagementSwim.get_software_image_details,
    configuration_templates.ConfigurationTemplates.gets_the_templates_available

  - Paths used are
    post /dna/intent/api/v1/onboarding/pnp-device
    post /dna/intent/api/v1/onboarding/pnp-device/site-claim
    post /dna/intent/api/v1/onboarding/pnp-device/{id}
    get /dna/intent/api/v1/onboarding/pnp-device/count
    get /dna/intent/api/v1/onboarding/pnp-device
    put /onboarding/pnp-device/${id} get /dna/intent/api/v1/site
    get /dna/intent/api/v1/image/importation get /dna/intent/api/v1/template-programmer/template
    post /api/v1/onboarding/pnp-device/authorize

"""
EXAMPLES = r"""
---
- name: Import multiple switches in bulk only
  cisco.dnac.pnp_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    state: merged
    config_verify: true
    config:
      - device_info:
          - serial_number: QD2425L8M7
            state: Unclaimed
            pid: c9300-24P
            is_sudi_required: false
          - serial_number: QTC2320E0H9
            state: Unclaimed
            pid: c9300-24P
            hostname: Test-123
          - serial_number: ETC2320E0HB
            state: Unclaimed
            pid: c9300-24P
- name: Add a new EWLC and claim it
  cisco.dnac.pnp_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    state: merged
    config_verify: true
    config:
      - device_info:
          - serial_number: FOX2639PAY7
            hostname: New_WLC
            state: Unclaimed
            pid: C9800-CL-K9
            authorize: true
        site_name: Global/USA/San Francisco/BGL_18
        template_name: Ansible_PNP_WLC
        template_params:
          hostname: IAC-EWLC-Claimed
        project_name: Onboarding Configuration
        image_name: C9800-40-universalk9_wlc.17.12.01.SPA.bin
        golden_image: true
        pnp_type: CatalystWLC
        static_ip: 204.192.101.10
        subnet_mask: 255.255.255.0
        gateway: 204.192.101.1
        vlan_id: 1101
        ip_interface_name: TenGigabitEthernet0/0/0
- name: Claim a pre-added switch, apply a template,
    and perform an image upgrade for a specific site
  cisco.dnac.pnp_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    state: merged
    config_verify: true
    config:
      - device_info:
          - serial_number: FJC271924EQ
            hostname: Switch
            state: Unclaimed
            pid: C9300-48UXM
        site_name: Global/USA/San Francisco/BGL_18
        template_name: "Ansible_PNP_Switch"
        image_name: cat9k_iosxe_npe.17.03.07.SPA.bin
        project_name: Onboarding Configuration
        template_params:
          hostname: SJC-Switch-1
          interface: TwoGigabitEthernet1/0/2
- name: Remove multiple devices from the PnP dashboard
    safely (ignores non-existent devices)
  cisco.dnac.pnp_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    state: deleted
    config_verify: true
    config:
      - device_info:
          - serial_number: QD2425L8M7
          - serial_number: FTC2320E0HA
          - serial_number: FKC2310E0HB
"""
RETURN = r"""
#Case_1: When the device is claimed successfully.
response_1:
  description: A dictionary with the response returned by the Cisco Catalyst Center Python SDK
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
#Case_2: Given site/image/template/project not found or Device is not found for deletion
response_2:
  description: A list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: list
  sample: >
    {
      "response": [],
      "msg": String
    }
#Case_3: Error while deleting/claiming a device
response_3:
  description: A string with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": String,
      "msg": String
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
)


class PnP(DnacBase):
    """Class containing member attributes for PNP workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]

    def validate_input(self):
        """
        Validate the fields provided in the playbook.  Checks the
        configuration provided in the playbook against a predefined
        specification to ensure it adheres to the expected structure
        and data types.

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - self.msg: A message describing the validation result.
          - self.status: The status of the validation (either 'success' or 'failed').
          - self.validated_config: If successful, a validated version of the
                                   'config' parameter.
        Example:
          To use this method, create an instance of the class and call
          'validate_input' on it.If the validation succeeds, 'self.status'
          will be 'success'and 'self.validated_config' will contain the
          validated configuration. If it fails, 'self.status' will be
          'failed', and 'self.msg' will describe the validation issues.
        """

        if not self.config:
            self.msg = "config not available in playbook for validation"
            self.status = "success"
            return self

        pnp_spec = {
            "template_name": {"type": "str", "required": False},
            "template_params": {"type": "dict", "required": False},
            "project_name": {
                "type": "str",
                "required": False,
                "default": "Onboarding Configuration",
            },
            "site_name": {"type": "str", "required": False},
            "image_name": {"type": "str", "required": False},
            "golden_image": {"type": "bool", "required": False},
            "device_info": {"type": "list", "required": True, "elements": "dict"},
            "pnp_type": {"type": "str", "required": False, "default": "Default"},
            "rf_profile": {"type": "str", "required": False},
            "static_ip": {"type": "str", "required": False},
            "subnet_mask": {"type": "str", "required": False},
            "gateway": {"type": "str", "required": False},
            "vlan_id": {"type": "str", "required": False},
            "ip_interface_name": {"type": "str", "required": False},
            "sensorProfile": {"type": "str", "required": False},
        }

        # Validate pnp params
        valid_pnp, invalid_params = validate_list_of_dicts(self.config, pnp_spec)

        if valid_pnp and isinstance(valid_pnp, list):
            self.log(
                "Valid PnP configurations received: {0}".format(len(valid_pnp)), "DEBUG"
            )

            for index, each_config in enumerate(valid_pnp, 1):
                self.log(
                    "Processing PnP config #{0}: {1}".format(index, each_config),
                    "DEBUG",
                )
                device_info = each_config.get("device_info")
                if device_info and isinstance(device_info, list):
                    for device in device_info:

                        serial_number = device.get("serial_number")
                        if not serial_number:
                            msg = "Serial Number missing in the Playbook config: {0}.".format(
                                str(device)
                            )
                            self.log(msg, "ERROR")
                            invalid_params.append(msg)

                        product_id = device.get("pid")
                        if not product_id and self.payload.get("state") != "deleted":
                            msg = "Product ID missing in the Playbook config: {0}.".format(
                                str(device)
                            )
                            self.log(msg, "ERROR")
                            invalid_params.append(msg)

            duplicate_serial_numbers = self.find_duplicate_serial_numbers(valid_pnp)
            if duplicate_serial_numbers:
                msg = "Duplicate serial numbers found in the playbook config: {0}".format(
                    ", ".join(duplicate_serial_numbers)
                )
                self.log(msg, "ERROR")
                invalid_params.append(msg)

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(
                "\n".join(invalid_params)
            )
            self.log(str(self.msg), "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        self.validated_config = valid_pnp
        self.msg = "Successfully validated playbook config params: {0}".format(
            str(valid_pnp)
        )
        self.log(str(self.msg), "INFO")
        self.status = "success"

        return self

    def find_duplicate_serial_numbers(self, input_config):
        """
        Identifies duplicate serial numbers from a list of device dictionaries.

        Args:
            input_config (list): A list of dictionaries, where each dictionary
                                contains device information.

        Returns:
            list: A list of serial numbers that appear more than once.
                Returns an empty list if no duplicates are found.
        """
        self.log("Starting the process to find duplicate serial numbers.", "INFO")
        seen_serials = set()
        duplicates = set()

        # Iterate through each device dictionary in the input list
        for idx, device in enumerate(input_config):
            self.log("Processing device at index {0}: {1}".format(idx, device), "DEBUG")
            # The "device_info" key contains a list, so we loop through it
            for info in device.get("device_info", []):
                serial_number = info.get("serial_number")

                if not serial_number:
                    self.log("No serial number found in device info: {0}".format(info), "WARNING")
                    continue

                if serial_number in seen_serials:
                    # If we've seen this serial number before, it's a duplicate
                    self.log("Duplicate serial number found: {0}".format(
                        serial_number), "ERROR")
                    duplicates.add(serial_number)
                else:
                    # If this is the first time, add it to our set of seen serials
                    self.log("Adding serial number to seen list: {0}".format(
                        serial_number), "DEBUG")
                    seen_serials.add(serial_number)

        self.log("Duplicate serial numbers found: {0}".format(list(duplicates)), "INFO")
        self.log("Completed the process to find duplicate serial numbers.", "INFO")

        return list(duplicates)

    def get_site_details(self):
        """
        Check whether the site exists or not, along with side id

        Parameters:
          - self: The instance of the class containing the 'config'
                  attribute to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - site_exits: A boolean value indicating the existence of the site.
          - site_id: The Id of the site i.e. required to claim device to site.
        Example:
          Post creation of the validated input, we this method gets the
          site_id and checks whether the site exists or not
        """
        site_exists = False
        site_id = None
        response = None

        try:
            site_name = self.want.get("site_name")
            response = self.get_site(site_name)
            self.log("Response from get_site for the site '{0}': {1}".format(
                site_name, self.pprint(response)), "DEBUG")

            if not response:
                self.msg = "No site details found for site name: '{0}'.".format(
                    site_name
                )
                self.log(self.msg, "CRITICAL")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
                return self

            self.log(
                "Received site details for '{0}': {1}".format(
                    site_name, str(response)
                ),
                "DEBUG",
            )
            site = response.get("response")
            if len(site) == 1:
                site_id = site[0].get("id")
                site_exists = True
                self.log(
                    "Site Name: {1}, Site ID: {0}".format(
                        site_id, self.want.get("site_name")
                    ),
                    "INFO",
                )
            return (site_exists, site_id)

        except Exception:
            self.msg = "Exception occurred as site '{0}' was not found".format(
                self.want.get("site_name")
            )
            self.log(self.msg, "CRITICAL")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

    def get_site_type(self):
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
            response = self.get_site(self.want.get("site_name"))
            if response:
                self.log(
                    "Received site details for '{0}': {1}".format(
                        self.want.get("site_name"), str(response)
                    ),
                    "DEBUG",
                )
                site = response.get("response")
                site_type = None

                if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:
                    site_additional_info = site[0].get("additionalInfo")
                    for item in site_additional_info:
                        if item["nameSpace"] == "Location":
                            site_type = item.get("attributes").get("type")
                            self.log(
                                "Site type for site name '{1}' : {0}".format(
                                    site_type, self.want.get("site_name")
                                ),
                                "INFO",
                            )
                else:
                    site_type = site[0].get("type")
                    self.log(
                        "Site type for site name '{1}' : {0}".format(
                            site_type, self.want.get("site_name")
                        ),
                        "INFO",
                    )

                return site_type
        except Exception:
            self.msg = "Exception occurred as site '{0}' was not found".format(
                self.want.get("site_name")
            )
            self.log(self.msg, "CRITICAL")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

    def get_pnp_params(self, params):
        """
        Store pnp parameters from the playbook for pnp processing in Cisco Catalyst Center.

        Parameters:
          - self: The instance of the class containing the 'config'
                  attribute to be validated.
          - params: The validated params passed from the playbook.
        Returns:
          The method returns an instance of the class with updated attributes:
          - pnp_params: A dictionary containing all the values indicating
                        the type of the site (area/building/floor).
        Example:
          Post creation of the validated input, it fetches the required paramters
          and stores it for further processing and calling the parameters in
          other APIs.
        """

        params_list = params["device_info"]
        device_info_list = []
        for param in params_list:
            device_dict = {}
            param["serialNumber"] = param.pop("serial_number")
            if "is_sudi_required" in param:
                param["isSudiRequired"] = param.pop("is_sudi_required")

            if "authorize" in param:
                param["authorize"] = param.pop("authorize")

            device_dict["deviceInfo"] = param
            device_info_list.append(device_dict)

        self.log("PnP paramters passed are {0}".format(str(params_list)), "INFO")
        return device_info_list

    def get_image_params(self, params):
        """
        Get image name and the confirmation whether it's tagged golden or not

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
          - params: The validated params passed from the playbook.
        Returns:
          The method returns an instance of the class with updated attributes:
          - image_params: A dictionary containing all the values indicating
                          name of the image and its golden image status.
        Example:
          Post creation of the validated input, it fetches the required
          paramters and stores it for further processing and calling the
          parameters in other APIs.
        """

        image_params = {
            "image_name": params.get("image_name"),
            "is_tagged_golden": params.get("golden_image"),
        }

        self.log("Image details are {0}".format(str(image_params)), "INFO")
        return image_params

    def pnp_cred_failure(self, msg=None):
        """
        Method for failing discovery if there is any discrepancy in the PnP credentials
        passed by the user
        """

        self.log(msg, "CRITICAL")
        self.module.fail_json(msg=msg)

    def get_claim_params(self):
        """
        Get the paramters needed for claiming the device to site.
        Parameters:
          - self: The instance of the class containing the 'config'
                  attribute to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - claim_params: A dictionary needed for calling the POST call
                          for claim a device to a site API.
        Example:
          The stored dictionary can be used to call the API claim a device
          to a site via SDK
        """

        imageinfo = {"imageId": self.have.get("image_id")}
        template_params = self.validated_config[0].get("template_params")
        configinfo = {
            "configId": self.have.get("template_id"),
            "configParameters": [{"key": "", "value": ""}],
        }

        if configinfo.get("configId") and template_params:
            if isinstance(template_params, dict):
                if len(template_params) > 0:
                    configinfo["configParameters"] = []
                    for key, value in template_params.items():
                        config_dict = {"key": key, "value": value}
                        configinfo["configParameters"].append(config_dict)

        claim_params = {
            "deviceId": self.have.get("device_id"),
            "siteId": self.have.get("site_id"),
            "type": self.want.get("pnp_type"),
            "hostname": self.want.get("hostname"),
            "imageInfo": imageinfo,
            "configInfo": configinfo,
        }

        if claim_params["type"] == "CatalystWLC":
            if not (self.validated_config[0].get("static_ip")):
                msg = "A static IP address is required to claim a wireless controller. Please provide one."
                self.pnp_cred_failure(msg=msg)
            if not (self.validated_config[0].get("subnet_mask")):
                msg = (
                    "Please provide a subnet mask to claim a wireless controller. "
                    "This information is mandatory for the configuration."
                )
                self.pnp_cred_failure(msg=msg)
            if not (self.validated_config[0].get("gateway")):
                msg = "A gateway IP is required to claim a wireless controller. Please ensure to provide it."
                self.pnp_cred_failure(msg=msg)
            if not (self.validated_config[0].get("ip_interface_name")):
                msg = (
                    "Please provide the Interface Name to claim a wireless controller. This information is necessary"
                    " for making it a logical interface post claiming which can used to help manage the Wireless SSIDs "
                    "broadcasted by the access points, manage the controller, access point and user data, plus more."
                )
                self.pnp_cred_failure(msg=msg)
            if not (self.validated_config[0].get("vlan_id")):
                msg = (
                    "Please provide the Vlan ID to claim a wireless controller. This is a required field for the process"
                    " to create and set the specified port as trunk during PnP."
                )
                self.pnp_cred_failure(msg=msg)
            claim_params["staticIP"] = self.validated_config[0]["static_ip"]
            claim_params["subnetMask"] = self.validated_config[0]["subnet_mask"]
            claim_params["gateway"] = self.validated_config[0]["gateway"]
            claim_params["vlanId"] = str(self.validated_config[0].get("vlan_id"))
            claim_params["ipInterfaceName"] = self.validated_config[0][
                "ip_interface_name"
            ]

        if claim_params["type"] == "AccessPoint":
            if not (self.validated_config[0].get("rf_profile")):
                msg = "The RF Profile for claiming an AP must be passed"
                self.pnp_cred_failure(msg=msg)
            claim_params["rfProfile"] = self.validated_config[0]["rf_profile"]

        self.log(
            "Parameters used for claiming are {0}".format(str(claim_params)), "INFO"
        )
        return claim_params

    def get_reset_params(self):
        """
        Get the paramters needed for resetting the device in an errored state.
        Parameters:
          - self: The instance of the class containing the 'config'
                  attribute to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - reset_params: A dictionary needed for calling the PUT call
                          for update device details API.
        Example:
          The stored dictionary can be used to call the API update device details
        """

        reset_params = {
            "deviceResetList": [
                {
                    "configList": [
                        {
                            "configId": self.have.get("template_id"),
                            "configParameters": [{"key": "", "value": ""}],
                        }
                    ],
                    "deviceId": self.have.get("device_id"),
                    "licenseLevel": "",
                    "licenseType": "",
                    "topOfStackSerialNumber": "",
                }
            ]
        }

        self.log(
            "Paramters used for resetting from errored state:{0}".format(
                self.pprint(reset_params)
            ),
            "INFO",
        )
        return reset_params

    def authorize_device(self, device_id):
        """
        Sets the authorization flag for a device on Cisco Catalyst Center.

        Parameters:
            device_id (str): The ID of the device to authorize.

        Returns:
            dict: The API response if the authorization is successful.
            None: If the authorization fails or an unexpected response is received.

        Description:
            This function authorizes a PnP device by setting the authorization flag, which moves the device
            from "Pending Authorization" state to "Authorized" state. This is required for devices to be
            provisioned after being claimed to a site. The function is supported from Cisco Catalyst Center
            release version 2.3.7.9 onwards and handles both successful and failed authorization scenarios.
        """
        self.log("Initiating device authorization process for device ID: '{0}'".format(
            device_id), "DEBUG")

        if not device_id:
            self.msg = "No device ID provided for authorization."
            self.log(self.msg, "ERROR")
            return None

        authorize_payload = {
            "deviceIdList": [device_id]
        }
        try:
            authorize_response = self.dnac_apply['exec'](
                family="device_onboarding_pnp",
                function="authorize_device",
                params=authorize_payload,
                op_modifies=True
            )
            self.log(
                "Received API response from 'authorize_device' for device ID '{0}': {1}".format(
                    device_id,
                    self.pprint(authorize_response)
                ),
                "DEBUG",
            )

            if authorize_response and isinstance(authorize_response, dict):
                self.log("Device authorization completed successfully for device ID: '{0}'".format(
                    device_id), "INFO")
                return authorize_response

            self.log(
                "Received unexpected response format from 'authorize_device' API for device ID '{0}' - expected dict, got: {1}".format(
                    device_id, type(authorize_response).__name__
                ),
                "ERROR"
            )

        except Exception as e:
            self.msg = "Exception occurred while executing 'authorize_device' for device ID: '{0}' - {1}".format(
                device_id, str(e)
            )
            self.log(self.msg, "ERROR")

        return None

    def bulk_devices_import(self, add_devices):
        """
        Add Multiple devices to the Cisco Catalyst Center.

        Parameters:
            self: An instance of a class used for interacting with Cisco Catalyst Center.
            add_devices (list): List contains new devices with serial number.

        Returns:
            self: The method returns an instance of the class with updated attributes:
        """
        self.log(
            "Starting bulk import of {0} device(s).".format(len(add_devices)), "INFO"
        )

        for index, device in enumerate(add_devices, 1):
            device_info = device.get("deviceInfo", {})

            if not device_info:
                self.msg = "device_info: missing in the Playbook config: {0}.".format(
                    self.pprint(add_devices)
                )
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

            serial_number = device_info.get("serialNumber")
            if not serial_number:
                self.msg = (
                    "Serial Number missing in Playbook config at index {0}: {1}".format(
                        index, str(device)
                    )
                )
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

            product_id = device_info.get("pid")
            if not product_id:
                self.msg = (
                    "Product ID missing in Playbook config at index {0}: {1}".format(
                        index, str(device)
                    )
                )
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

            self.log(
                "Validated device #{0}: Serial - {1}, PID - {2}".format(
                    index, serial_number, product_id
                ),
                "DEBUG",
            )

        self.log(
            "Payload devices data to process bulk import: {0}.".format(
                self.pprint(add_devices)
            ),
            "DEBUG",
        )

        try:
            bulk_params = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="import_devices_in_bulk",
                params={"payload": add_devices},
                op_modifies=True,
            )
            self.log(
                "Response from API 'import_devices_in_bulk' for imported devices: {0}".format(
                    bulk_params
                ),
                "DEBUG",
            )

            if bulk_params.get("failureList"):
                self.msg = "Unable to import below {0} device(s). ".format(
                    len(bulk_params.get("failureList"))
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR", bulk_params
                ).check_return_status()

            self.result['msg'] = "{0} device(s) imported successfully".format(
                len(bulk_params.get("successList")))
            self.log(self.result['msg'], "INFO")
            self.result['response'] = bulk_params
            self.result['diff'] = self.validated_config
            self.result['changed'] = True

            # Check for authorization support and process if applicable
            current_version = self.get_ccc_version()
            if self.compare_dnac_versions(current_version, "2.3.7.9") >= 0:
                self.log("Cisco Catalyst Center version {0} supports device authorization. Checking for authorization requirements.".format(
                    current_version), "DEBUG")

                authorize_status, serial_number_list = self.bulk_authorize_devices(add_devices)

                if authorize_status:
                    auth_count = len(serial_number_list)
                    auth_msg = " {0} device(s) authorized successfully".format(auth_count)
                    self.result['msg'] += auth_msg
                    self.log("Device authorization completed successfully: {0} devices authorized".format(
                        auth_count), "INFO")
                else:
                    if serial_number_list:
                        auth_msg = " Unable to authorize the device(s): {0}".format(serial_number_list)
                        self.log("Device authorization failed for devices: {0}".format(
                            serial_number_list), "WARNING")
                    else:
                        self.log("No devices required authorization or authorization was skipped", "INFO")
            else:
                self.log("Cisco Catalyst Center version {0} does not support device authorization feature (requires 2.3.7.9+)".format(
                    current_version), "INFO")

            return self

        except Exception as e:
            msg = "Unable execute the function 'import_devices_in_bulk' for the payload: '{0}'. ".format(
                self.pprint(add_devices)
            )
            self.log(msg + str(e), "ERROR")
            self.fail_and_exit(msg)

        self.msg = "Bulk import failed"
        self.log(self.msg, "CRITICAL")
        self.set_operation_result(
            "failed", False, self.msg, "ERROR"
        ).check_return_status()
        return self

    def bulk_authorize_devices(self, processed_devices):
        """
        Authorizes multiple devices after bulk import is completed based on authorization flag.

        Parameters:
            processed_devices (list): A list of dictionaries containing bulk device information.

        Returns:
            tuple:
                bool: True if all devices are successfully authorized, False otherwise.
                list: A list of serial numbers of the authorized or unauthorized devices.

        Description:
            This function processes device authorization for devices that have the 'authorize' flag set to True
            in the configuration. It checks each device's state and attempts authorization only for devices
            in "Pending Authorization" state. The function is supported from Cisco Catalyst Center release
            version 2.3.7.9 onwards and provides comprehensive status reporting for bulk authorization operations.
        """
        self.log("Initiating bulk device authorization process for {0} devices".format(
            len(processed_devices)), "DEBUG")

        if not processed_devices:
            self.log("No devices provided for bulk authorization - skipping process", "INFO")
            return True, []

        authorized_devices = []
        unauthorized_devices = []
        devices_requiring_auth = []

        # First, identify devices that need authorization based on config
        for device in processed_devices:
            device_info = device.get("deviceInfo", {})
            serial_number = device_info.get("serialNumber")

            if not serial_number:
                self.log("Device missing serial number - skipping authorization check: {0}".format(device), "WARNING")
                continue

            self.log("Checking authorization requirements for device: '{0}'".format(serial_number), "DEBUG")

            # Check if this device has authorize flag set in config
            authorization_required = False
            for each_config in self.config:
                input_device_info = each_config.get("device_info", [])
                for each_info in input_device_info:
                    if (each_info.get("serialNumber") == serial_number and
                       each_info.get("authorize") is True):
                        authorization_required = True
                        self.log("Device '{0}' requires authorization based on config".format(
                            serial_number), "DEBUG")
                        break
                if authorization_required:
                    break

            if authorization_required:
                devices_requiring_auth.append(serial_number)
            else:
                self.log("Device '{0}' does not require authorization (authorize flag not set)".format(serial_number), "DEBUG")

        if not devices_requiring_auth:
            self.log("No devices require authorization based on configuration", "INFO")
            return True, []

        self.log("Found {0} device(s) requiring authorization: {1}".format(
            len(devices_requiring_auth), devices_requiring_auth), "INFO")

        # Process authorization for devices that require it
        for serial_number in devices_requiring_auth:
            self.log("Processing authorization for device: '{0}'".format(serial_number), "DEBUG")

            device_response = self.get_device_list_pnp(serial_number)
            if not device_response or not isinstance(device_response, dict):
                self.log("Unable to retrieve device details for serial number: '{0}' - skipping authorization".format(
                    serial_number), "WARNING")
                unauthorized_devices.append(serial_number)
                continue

            device_info = device_response.get("deviceInfo", {})
            current_state = device_info.get("state")
            device_id = device_response.get("id")

            self.log("Device '{0}' current state: '{1}'".format(serial_number, current_state), "DEBUG")

            if current_state != "Pending Authorization":
                self.log("Device '{0}' is not in 'Pending Authorization' state (current: '{1}') - skipping authorization".format(
                    serial_number, current_state), "INFO")
                unauthorized_devices.append(serial_number)
                continue

            if not device_id:
                self.log("Device '{0}' missing device ID - cannot authorize".format(serial_number), "ERROR")
                unauthorized_devices.append(serial_number)
                continue

            # Attempt device authorization
            self.log("Attempting to authorize device '{0}' with ID '{1}'".format(serial_number, device_id), "INFO")
            authorize_response = self.authorize_device(device_id)

            self.log("Authorization response for device '{0}': {1}".format(
                serial_number, self.pprint(authorize_response)), "DEBUG")

            if authorize_response and isinstance(authorize_response, dict):
                self.log("Device '{0}' authorized successfully".format(serial_number), "INFO")
                authorized_devices.append(serial_number)
            else:
                error_msg = str(authorize_response) if authorize_response else "No response received"
                self.log("Failed to authorize device '{0}': {1}".format(serial_number, error_msg), "ERROR")
                unauthorized_devices.append(serial_number)

        # Generate final status summary
        total_auth_required = len(devices_requiring_auth)
        auth_success_count = len(authorized_devices)
        auth_failed_count = len(unauthorized_devices)

        self.log("Bulk authorization completed - Required: {0}, Successful: {1}, Failed: {2}".format(
            total_auth_required, auth_success_count, auth_failed_count), "INFO")

        if authorized_devices:
            self.log("Successfully authorized devices: {0}".format(authorized_devices), "INFO")

        if unauthorized_devices:
            self.log("Failed to authorize devices: {0}".format(unauthorized_devices), "WARNING")

        # Return success status and appropriate device list
        if authorized_devices and not unauthorized_devices:
            self.log("All devices requiring authorization were successfully authorized", "INFO")
            return True, authorized_devices

        if unauthorized_devices:
            self.log("Some devices failed authorization or were not eligible", "WARNING")
            return False, unauthorized_devices

        # This should not be reached, but included for completeness
        self.log("No authorization operations were performed", "INFO")
        return True, []

    def compare_config_with_device_info(self, input_config, device_info):
        """
        Compare the input config with the device info.

        Parameters:
            self: An instance of a class used for interacting with Cisco Catalyst Center.
            input_config (dict): Dictionary containing each config element from the playbook.
            device_info (dict): Dictionary containing PnP device details to compare.

        Returns:
            tuple:
                bool: True if all input config values match the device info, False otherwise.
                int: The number of keys with mismatched values.
        """
        self.log("Starting comparison between input config and device info.", "INFO")
        self.log("Input Config: {0}, Device Info: {1}".format(
            self.pprint(input_config), self.pprint(device_info)), "INFO")
        unmatch_count = 0
        for key, value in input_config.items():
            device_value = device_info.get(key)

            if value != device_value and key == "hostname":
                self.log(
                    "Mismatch found for key '{0}': expected '{1}', got '{2}'".format(
                        key, value, device_value
                    ),
                    "DEBUG",
                )
                unmatch_count += 1

        if unmatch_count > 0:
            self.log(
                "{0} mismatched key(s) found between input config and device info.".format(
                    unmatch_count
                ),
                "INFO",
            )
            return False, unmatch_count

        self.log("Input config matches device info.", "DEBUG")
        return True, 0

    def update_device_info(self, input_config, device_info, device_id):
        """
        Update the input configuration with device information and stack status,
        then push to Cisco Catalyst Center.

        Parameters:
            self: An instance of a class used for interacting with Cisco Catalyst Center.
            input_config (dict): Dictionary containing each configuration element from the playbook.
            device_info (dict): Dictionary containing PnP device details used to verify stack information.
            device_id (str): ID of the device to be updated in Cisco Catalyst Center.

        Returns:
            dict: Response from the 'update_device' API after attempting to update the device.
            If update fails, it logs the error and exits the execution.
        """
        update_payload = {}
        if not input_config:
            self.msg = "No input_config provided for update."
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        is_stack = device_info.get("deviceInfo", {}).get("stack", False)
        update_payload = {"deviceInfo": input_config.copy()}
        update_payload["deviceInfo"]["stack"] = is_stack

        self.log(
            "The request sent for 'update_device' API for device ID {0}: {1}".format(
                device_id, self.pprint(update_payload)
            ),
            "DEBUG",
        )

        try:
            update_response = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="update_device",
                params={"id": device_id, "payload": update_payload},
                op_modifies=True,
            )
            self.log(
                "Response from 'update_device' API for device's config update: {0}".format(
                    self.pprint(update_response)
                ),
                "DEBUG",
            )

            if update_response and isinstance(update_response, dict):
                self.msg = "Successfully updated device configuration for device ID {0}. ".format(
                    device_id
                )
                self.log(self.msg, "INFO")
                return update_response

            self.log(
                "Received unexpected response from 'update_device' API for device ID {0}".format(
                    device_id
                ),
                "ERROR",
            )

        except Exception as e:
            self.msg = "Unable execute the function 'update_device' for the payload: '{0}'. ".format(
                self.pprint(update_payload)
            )
            self.log(self.msg + str(e), "ERROR")
            self.fail_and_exit(self.msg)

    def reset_error_device(self, device_id):
        """
        Reset the error-state device configuration to resynchronize with Cisco Catalyst Center.

        Parameters:
            self: An instance of a class used for interacting with Cisco Catalyst Center.
            device_id (str): The unique identifier of the device to be reset.

        Returns:
            dict: The response returned after attempting to reset the device.
        """
        try:
            reset_parameters = self.get_reset_params()
            if device_id:
                reset_parameters["deviceResetList"][0]["deviceId"] = device_id
            self.log(
                "Starting to reset the error device: {0}".format(
                    self.pprint(reset_parameters)
                ),
                "INFO",
            )
            reset_response = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="reset_device",
                params={"payload": reset_parameters},
                op_modifies=True,
            )
            self.log(
                "Response from 'update_device' API for errored state resolution: {0}".format(
                    str(reset_response)
                ),
                "DEBUG",
            )
            if reset_response and isinstance(reset_response, dict):
                self.log(
                    "Device '{0}' reset completed successfully.".format(device_id),
                    "INFO",
                )
                return reset_response
            else:
                msg = "Failed to reset device with ID: {0}".format(device_id)
                self.log(msg, "INFO")
                self.fail_and_exit(msg)

        except Exception as e:
            self.msg = "Failed to execute 'reset_device' for device ID '{0}': ".format(
                device_id
            )
            self.log(self.msg + str(e), "ERROR")
            self.fail_and_exit(self.msg)

    def get_have(self):
        """
        Get the current image, template and site details from the Cisco Catalyst Center.

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - self.image_response: A list of image passed by the user
          - self.template_list: A list of template under project
          - self.device_response: Gets the device_id and stores it
        Example:
          Stored paramters are used to call the APIs to get the current image,
          template and site details to call the API for various types of devices
        """
        have = {}

        # Claiming is only allowed for single addition of devices
        if len(self.want.get("pnp_params")) == 1:
            # check if given device exists in pnp inventory, store device Id
            device_response = self.get_device_list_pnp(self.want.get("serial_number"))
            self.log(
                "Device details for the device with serial number '{0}': {1}".format(
                    self.want.get("serial_number"), self.pprint(device_response)
                ),
                "DEBUG",
            )

            if not device_response:
                self.log(
                    "Device with serial number {0} is not found in the inventory".format(
                        self.want.get("serial_number")
                    ),
                    "WARNING",
                )
                self.msg = "Adding the device to database"
                self.status = "success"
                self.have = have
                have["device_found"] = False
                return self

            have["device_found"] = True
            have["device_id"] = device_response.get("id")
            self.log("Device Id: " + str(have["device_id"]))

            if self.params.get("state") == "merged":
                # check if given image exists, if exists store image_id
                image_response = self.dnac_apply["exec"](
                    family="software_image_management_swim",
                    function="get_software_image_details",
                    params=self.want.get("image_params"),
                )
                image_list = image_response.get("response")
                self.log(
                    "Image details obtained from the API 'get_software_image_details': {0}".format(
                        self.pprint(image_response)
                    ),
                    "DEBUG",
                )

                # check if project has templates or not
                template_list = self.dnac_apply["exec"](
                    family="configuration_templates",
                    function="gets_the_templates_available",
                    params={"project_names": self.want.get("project_name")},
                )
                self.log(
                    "List of templates under the project '{0}': {1}".format(
                        self.want.get("project_name"), self.pprint(template_list)
                    ),
                    "DEBUG",
                )

                dev_details_response = self.get_device_by_id_pnp(
                    device_response.get("id")
                )
                self.log(
                    "Device details retrieved after calling the 'get_device_by_id' API: {0}".format(
                        self.pprint(dev_details_response)
                    ),
                    "DEBUG",
                )

                install_mode = dev_details_response.get("deviceInfo").get("mode")
                self.log(
                    "Installation mode of the device with the serial no. '{0}':{1}".format(
                        self.want.get("serial_number"), install_mode
                    ),
                    "INFO",
                )
                onb_state = dev_details_response.get("deviceInfo").get("onbState")
                self.log(
                    "Onboarding status of the device with the serial no. '{0}':{1}".format(
                        self.want.get("serial_number"), onb_state
                    ),
                    "INFO",
                )

                # check if given site exits, if exists store current site info
                site_exists = False
                if not isinstance(
                    self.want.get("site_name"), str
                ) and not self.want.get("pnp_params")[0].get("deviceInfo"):
                    self.msg = "The site name must be a string"
                    self.log(str(self.msg), "ERROR")
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                site_name = self.want.get("site_name")
                (site_exists, site_id) = self.get_site_details()

                if site_exists:
                    have["site_id"] = site_id
                    self.log(
                        "Site Exists: {0}\nSite Name: {1}\nSite ID: {2}".format(
                            site_exists, site_name, site_id
                        ),
                        "INFO",
                    )
                    if self.want.get("pnp_type") == "AccessPoint":
                        if self.get_site_type() != "floor":
                            self.msg = (
                                "Please ensure that the site type is specified as 'floor' when claiming an AP."
                                " The site type is given as '{0}'. Please change the 'site_type' into 'floor' to "
                                "proceed.".format(self.get_site_type())
                            )
                            self.log(str(self.msg), "ERROR")
                            self.status = "failed"
                            return self

                    if len(image_list) == 0:
                        self.msg = (
                            "The image '{0}' is either not present or not tagged as 'Golden' in the Cisco Catalyst Center."
                            " Please verify its existence and its tag status.".format(
                                self.validated_config[0].get("image_name")
                            )
                        )
                        self.log(self.msg, "CRITICAL")
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()

                    if len(image_list) == 1:
                        if install_mode != "INSTALL" and onb_state != "Not Contacted":
                            self.msg = (
                                "The system must be in INSTALL mode to upgrade the image. The current mode is '{0}'."
                                " Please switch to INSTALL mode to proceed.".format(
                                    install_mode
                                )
                            )
                            self.log(str(self.msg), "CRITICAL")
                            self.set_operation_result(
                                "failed", False, self.msg, "ERROR"
                            ).check_return_status()

                        have["image_id"] = image_list[0].get("imageUuid")
                        self.log(
                            "Image ID for the image '{0}': {1}".format(
                                self.want.get("image_params").get("image_name"),
                                str(have["image_id"]),
                            ),
                            "INFO",
                        )

                    template_name = self.want.get("template_name")
                    if template_name:
                        if not (template_list and isinstance(template_list, list)):
                            self.msg = "Either project not found or it is Empty."
                            self.log(self.msg, "CRITICAL")
                            self.set_operation_result(
                                "failed", False, self.msg, "ERROR"
                            ).check_return_status()

                        template_details = get_dict_result(
                            template_list, "name", template_name
                        )
                        if template_details:
                            have["template_id"] = template_details.get("templateId")
                        else:
                            self.msg = "Template '{0}' is not found.".format(
                                template_name
                            )
                            self.log(self.msg, "CRITICAL")
                            self.set_operation_result(
                                "failed", False, self.msg, "ERROR"
                            ).check_return_status()

                else:
                    if not self.want.get("pnp_params")[0].get("deviceInfo"):
                        self.msg = "Either Site Name or Device details must be added."
                        self.log(self.msg, "ERROR")
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()

        self.msg = "Successfully collected all project and template \
                    parameters from Cisco Catalyst Center for comparison"
        self.log(self.msg, "INFO")
        self.status = "success"
        self.have = have
        self.log("Current State (have): {0}".format(self.pprint(self.have)), "DEBUG")
        return self

    def get_want(self, config):
        """
        Get all the image, template and site and pnp related
        information from playbook that is needed to be created in Cisco Catalyst Center.

        Parameters:
          - self: The instance of the class containing the 'config'
                  attribute to be validated.
          - config: validated config passed from the playbook
        Returns:
          The method returns an instance of the class with updated attributes:
          - self.want: A dictionary of paramters obtained from the playbook.
          - self.msg: A message indicating all the paramters from the playbook
                      are collected.
          - self.status: Success.
        Example:
            It stores all the paramters passed from the playbook for further
            processing before calling the APIs
        """

        self.want = {
            "image_params": self.get_image_params(config),
            "pnp_params": self.get_pnp_params(config),
            "pnp_type": config.get("pnp_type"),
            "site_name": config.get("site_name"),
            "project_name": config.get("project_name"),
            "template_name": config.get("template_name"),
        }
        if len(self.want.get("pnp_params")) == 1:
            self.want["serial_number"] = self.want["pnp_params"][0]["deviceInfo"].get(
                "serialNumber"
            )
            self.want["hostname"] = self.want["pnp_params"][0]["deviceInfo"].get(
                "hostname"
            )

        if self.want["pnp_type"] == "CatalystWLC":
            self.want["static_ip"] = config.get("static_ip")
            self.want["subnet_mask"] = config.get("subnet_mask")
            self.want["gateway"] = config.get("gateway")
            self.want["vlan_id"] = config.get("vlan_id")
            self.want["ip_interface_name"] = config.get("ip_interface_name")

        elif self.want["pnp_type"] == "AccessPoint":
            self.want["rf_profile"] = config.get("rf_profile")
        self.msg = (
            "Successfully collected all parameters from playbook " + "for comparison"
        )
        self.log(self.msg, "INFO")
        self.log("Desired State (want): {0}".format(self.pprint(self.want)), "DEBUG")
        self.status = "success"

        return self

    def get_diff_merged(self):
        """
        If given device doesnot exist
        then add it to pnp database and get the device id
        Args:
            self: An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            object: An instance of the class with updated results and status
            based on the processing of differences. Based on the length of devices passed
            it adds/claims or does both.
        Description:
            The function processes the differences and, depending on the
            changes required, it may add, update,or resynchronize devices in
            Cisco Catalyst Center. The updated results and status are stored in the
            class instance for further use.
        """

        if not isinstance(self.want.get("pnp_params"), list):
            self.msg = "Device Info must be passed as a list"
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        # Check the device already added and claimed for idempotent or import devices
        if self.want.get("pnp_params"):
            devices_exists, devices_not_exist, reset_devices = [], [], []
            device_updated_list, devices_reclaimed = [], []
            site = self.want.get("site_name")
            template_name = self.want.get("template_name")
            image_name = self.want.get("image_params", {}).get("image_name")
            self.log(
                "Provisioning context - Site: '{0}', Template: '{1}', Image: '{2}'".format(
                    site, template_name, image_name
                ),
                "DEBUG",
            )

            pnp_devices = self.want.get("pnp_params")
            self.log("Total devices to process: {0}".format(len(pnp_devices)), "DEBUG")

            for each_device in pnp_devices:
                serial_number = each_device.get("deviceInfo", {}).get("serialNumber")
                authorize_flag = each_device.get("deviceInfo", {}).get("authorize")

                if not serial_number:
                    self.log(
                        "Skipping device entry due to missing serial number: {0}".format(
                            self.pprint(each_device.get("deviceInfo"))
                        ),
                        "WARNING",
                    )
                    continue

                device_response = self.get_device_list_pnp(serial_number)
                self.log(
                    "Response of PNP Device info of: '{0}': {1}".format(
                        serial_number, self.pprint(device_response)
                    ),
                    "DEBUG",
                )

                if device_response and isinstance(device_response, dict):
                    device_info = device_response.get("deviceInfo", {})
                    input_device_info = each_device.get("deviceInfo")
                    match_stat, un_match = self.compare_config_with_device_info(
                        input_device_info, device_info
                    )
                    claim_stat = device_info.get("state")

                    self.log(
                        "Device '{0}': Claim Status = '{1}', Config Match = '{2}'".format(
                            serial_number, claim_stat, match_stat
                        ),
                        "DEBUG",
                    )

                    if claim_stat != "Provisioned" and not match_stat:
                        self.log(
                            "Updating device info for serial: '{0}' as it's not provisioned or config doesn't match.".format(
                                serial_number
                            ),
                            "DEBUG"
                        )
                        device_update_response = self.update_device_info(
                            input_device_info, device_info, device_response.get("id")
                        )
                        if device_update_response:
                            device_updated_list.append(serial_number)
                            self.log(
                                "Device '{0}' updated successfully.".format(serial_number),
                                "INFO",
                            )

                        current_version = self.get_ccc_version()
                        if authorize_flag and self.compare_dnac_versions(current_version, "2.3.7.9") >= 0 \
                           and claim_stat == "Pending Authorization":
                            self.log("Initiating device authorization process for device '{0}' - Version: {1}, State: {2}".format(
                                serial_number, current_version, claim_stat), "INFO")

                            device_id = device_response.get("id")
                            if not device_id:
                                self.log("Device ID not found for device '{0}' - cannot proceed with authorization".format(
                                    serial_number), "ERROR")
                            else:
                                authorize_response = self.authorize_device(device_id)
                                self.log("Authorization API response for device '{0}': {1}".format(
                                    serial_number, self.pprint(authorize_response)), "DEBUG")

                                if authorize_response and isinstance(authorize_response, dict):
                                    self.log("Device '{0}' authorized successfully and moved from 'Pending Authorization' state".format(
                                        serial_number), "INFO")
                                else:
                                    error_msg = str(authorize_response) if authorize_response else "No response received"
                                    self.log("Failed to authorize device '{0}': {1}".format(
                                        serial_number, error_msg), "ERROR")

                    else:
                        self.log(
                            "Device '{0}' already provisioned with matching config. No update needed.".format(
                                serial_number
                            ),
                            "DEBUG",
                        )

                    if claim_stat == "Error" and not site:
                        self.log(
                            "Device '{0}' is in 'Error' state and has no site. Attempting reset.".format(
                                serial_number
                            ),
                            "DEBUG",
                        )
                        reset_response = self.reset_error_device(
                            device_response.get("id")
                        )
                        if reset_response:
                            self.log(
                                "Device '{0}' reset successful.".format(serial_number),
                                "DEBUG",
                            )
                            reset_devices.append(serial_number)
                        else:
                            self.log(
                                "Device '{0}' reset failed or skipped.".format(
                                    serial_number
                                ),
                                "DEBUG",
                            )

                    if claim_stat in ("Claimed", "Planned") and site:
                        device_site = device_info.get("siteName")
                        if site != device_site:
                            self.log(
                                "Device '{0}' site mismatch: expected '{1}', got '{2}'. Updating site.".format(
                                    serial_number, site, device_site
                                ),
                                "DEBUG",
                            )
                            self.log(
                                "Device '{0}' is eligible for reclaiming (State: '{1}').".format(
                                    serial_number, claim_stat
                                ),
                                "DEBUG",
                            )
                            claim_params = self.get_claim_params()
                            claim_response = self.claim_device_site(claim_params)
                            self.log(
                                "Response from API 'claim a device to a site' for a single claiming: {0}".format(
                                    str(claim_response)
                                ),
                                "DEBUG",
                            )

                            if claim_response.get("response") == "Device Claimed":
                                self.log(
                                    "Device '{0}' reclaimed successfully to site '{1}'.".format(
                                        serial_number, site
                                    ),
                                    "INFO",
                                )
                                devices_reclaimed.append(serial_number)

                    if claim_stat in ("Provisioned", "Claimed", "Planned") or (
                        claim_stat in ("Unclaimed", "Error") and not site
                    ):
                        self.log(
                            "Device '{0}' considered as existing based on claim status '{1}'.".format(
                                serial_number, claim_stat
                            ),
                            "DEBUG",
                        )
                        devices_exists.append(serial_number)
                else:
                    self.log(
                        "No valid device info returned for serial: '{0}'. Marking as not existing.".format(
                            serial_number
                        ),
                        "DEBUG",
                    )
                    devices_not_exist.append(each_device)

            self.log(
                "Device check summary - Exists: {0}, Not Exists: {1}".format(
                    len(devices_exists), len(devices_not_exist)
                ),
                "DEBUG",
            )

            if devices_exists and len(devices_exists) == len(
                self.want.get("pnp_params")
            ):
                self.msg = "All specified devices already exist and cannot be imported again: {0}.".format(
                    devices_exists
                )
                changed = False
                if reset_devices:
                    self.msg = self.msg + " Devices reset done ({0})".format(
                        str(reset_devices)
                    )
                    changed = True
                self.log(self.msg, "INFO")

                if device_updated_list:
                    changed = True
                    self.msg += " and Device information updated successfully."

                if devices_reclaimed:
                    changed = True
                    self.msg += " and Devices reclaimed successfully to the new site."

                self.set_operation_result(
                    "success", changed, self.msg, "INFO", devices_exists
                ).check_return_status()
                return self

            if devices_not_exist and not site:
                self.log(
                    "Initiating bulk import for devices not found in PnP list.", "DEBUG"
                )
                return self.bulk_devices_import(devices_not_exist)

        provisioned_count_params = {
            "serial_number": self.want.get("serial_number"),
            "state": "Provisioned",
        }

        planned_count_params = {
            "serial_number": self.want.get("serial_number"),
            "state": "Planned",
        }

        if not self.have.get("device_found"):
            if not self.want["pnp_params"]:
                self.msg = (
                    "Device needs to be added before claiming. Please add device_info"
                )
                self.log(self.msg, "ERROR")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            if not self.want["site_name"]:
                self.log("Adding device to pnp database", "INFO")
                dev_add_response = self.add_pnp_device(self.want.get("pnp_params")[0])
                self.have["deviceInfo"] = dev_add_response.get("deviceInfo")
                self.log(
                    "Response from API 'add device' for a single device addition: {0}".format(
                        str(dev_add_response)
                    ),
                    "DEBUG",
                )

                if self.have["deviceInfo"]:
                    self.result["msg"] = "Only Device Added Successfully"
                    self.log("Device successfully added to PnP database", "INFO")

                    # Check if device requires authorization based on state and version compatibility
                    device_state = self.have["deviceInfo"].get("state")
                    current_version = self.get_ccc_version()
                    device_id = dev_add_response.get("id")
                    serial_number = self.want.get("serial_number")

                    self.log("Device '{0}' current state: '{1}', Catalyst Center version: '{2}'".format(
                        serial_number, device_state, current_version), "DEBUG")

                    # Check authorization requirements
                    if (device_state == "Pending Authorization" and
                       self.compare_dnac_versions(current_version, "2.3.7.9") >= 0):

                        self.log("Device '{0}' is in 'Pending Authorization' state and version supports authorization - proceeding with authorization".format(
                            serial_number), "INFO")

                        if not device_id:
                            self.log("Device ID not found for device '{0}' - cannot proceed with authorization".format(
                                serial_number), "ERROR")
                            self.result["msg"] += ". Unable to authorize Device '{0}' - missing device ID.".format(
                                serial_number)
                        else:
                            self.log("Initiating authorization process for device '{0}' with ID '{1}'".format(
                                serial_number, device_id), "DEBUG")

                            authorize_response = self.authorize_device(device_id)
                            self.log("Authorization API response for device '{0}': {1}".format(
                                serial_number, self.pprint(authorize_response)), "DEBUG")

                            if authorize_response and isinstance(authorize_response, dict):
                                self.log("Device '{0}' authorization completed successfully".format(
                                    serial_number), "INFO")
                                self.result["msg"] += ". Device '{0}' authorized successfully.".format(
                                    serial_number)
                            else:
                                error_msg = str(authorize_response) if authorize_response else "No response received"
                                self.log("Failed to authorize device '{0}': {1}".format(serial_number, error_msg), "ERROR")
                                self.result["msg"] += ". Unable to authorize Device '{0}' - {1}.".format(
                                    serial_number, error_msg)

                    self.log(self.result["msg"], "INFO")
                    self.result["response"] = dev_add_response
                    self.result["diff"] = self.validated_config
                    self.result["changed"] = True
                else:
                    self.msg = "Device Addition Failed"
                    self.log(self.result["msg"], "CRITICAL")
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                return self

            else:
                self.log("Adding device to pnp database")
                dev_add_response = self.add_pnp_device(self.want.get("pnp_params")[0])
                self.get_have().check_return_status()
                self.have["deviceInfo"] = dev_add_response.get("deviceInfo")
                self.log(
                    "Response from API 'add device' for single device addition: {0}".format(
                        str(dev_add_response)
                    ),
                    "DEBUG",
                )
                claim_params = self.get_claim_params()
                claim_params["deviceId"] = dev_add_response.get("id")

                # Check if device requires authorization based on state and version compatibility
                device_state = self.have["deviceInfo"].get("state")
                current_version = self.get_ccc_version()
                device_id = dev_add_response.get("id")
                serial_number = self.want.get("serial_number")

                self.log("Device addition completed - checking authorization requirements for device '{0}'".format(
                    serial_number), "DEBUG")
                self.log("Device '{0}' current state: '{1}', Catalyst Center version: '{2}'".format(
                    serial_number, device_state, current_version), "DEBUG")

                # Process device authorization if conditions are met
                if (device_state == "Pending Authorization" and
                   self.compare_dnac_versions(current_version, "2.3.7.9") >= 0):

                    self.log("Device '{0}' is in 'Pending Authorization' state and version supports authorization - initiating authorization process".format(
                        serial_number), "INFO")

                    if not device_id:
                        self.log("Device ID not found for device '{0}' - cannot proceed with authorization".format(
                            serial_number), "ERROR")
                        self.result["msg"] += ". Unable to authorize Device '{0}' - missing device ID.".format(serial_number)
                    else:
                        self.log("Attempting device authorization for device '{0}' with ID '{1}'".format(
                            serial_number, device_id), "DEBUG")

                        authorize_response = self.authorize_device(device_id)
                        self.log("Authorization API response for device '{0}': {1}".format(
                            serial_number, self.pprint(authorize_response)), "DEBUG")

                        if authorize_response and isinstance(authorize_response, dict):
                            self.log("Device '{0}' authorization completed successfully and moved from 'Pending Authorization' state".format(
                                serial_number), "INFO")
                            self.result["msg"] += ". Device '{0}' authorized successfully.".format(serial_number)
                        else:
                            error_msg = str(authorize_response) if authorize_response else "No response received"
                            self.log("Failed to authorize device '{0}': {1}".format(serial_number, error_msg), "ERROR")
                            self.result["msg"] += ". Unable to authorize Device '{0}' - {1}.".format(serial_number, error_msg)

                claim_response = self.claim_device_site(claim_params)
                self.log(
                    "Response from API 'claim a device to a site' for a single claiming: {0}".format(
                        str(claim_response)
                    ),
                    "DEBUG",
                )

                if (
                    claim_response.get("response") == "Device Claimed"
                    and self.have["deviceInfo"]
                ):
                    self.result["msg"] = "Device Added and Claimed Successfully"
                    self.log(self.result["msg"], "INFO")
                    self.result["response"] = claim_response
                    self.result["diff"] = self.validated_config
                    self.result["changed"] = True

                else:
                    self.msg = "Device Claim Failed"
                    self.log(self.msg, "CRITICAL")
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                return self

        prov_dev_response = self.pnp_device_count(provisioned_count_params)
        self.log(
            "Response from 'get device count' API for provisioned devices: {0}".format(
                str(prov_dev_response)
            ),
            "DEBUG",
        )

        plan_dev_response = self.pnp_device_count(planned_count_params)
        self.log(
            "Response from 'get_device_count' API for devices in planned state: {0}".format(
                str(plan_dev_response)
            ),
            "DEBUG",
        )

        dev_details_response = self.get_device_by_id_pnp(self.have["device_id"])
        self.log(
            "Response from 'get_device_by_id' API for device details: {0}".format(
                str(dev_details_response)
            ),
            "DEBUG",
        )

        pnp_state = dev_details_response.get("deviceInfo", {}).get("state")
        self.log("PnP state of the device: {0}".format(pnp_state), "INFO")

        device_info = self.want.get("pnp_params")[0].get("deviceInfo")
        match_stat, un_match = self.compare_config_with_device_info(
            device_info, dev_details_response
        )

        update_response = {}
        if not match_stat:
            self.log(
                "Updating device info for serial: '{0}' as config doesn't match.".format(
                    self.want.get("serial_number")
                ),
                "DEBUG"
            )
            update_response = self.update_device_info(
                device_info,
                dev_details_response,
                self.have["device_id"],
            )
            if update_response:
                self.log(
                    "Device '{0}' updated successfully.".format(
                        self.want.get("serial_number")
                    ),
                    "INFO",
                )

        if not self.want["site_name"]:
            self.result["response"] = self.have.get("device_found")
            self.result["msg"] = "Device is already added"
            self.log(self.result["msg"], "WARNING")
            if update_response.get("deviceInfo"):
                self.result["changed"] = True
                self.result["msg"] += " and Device '{0}' updated successfully.".format(
                    serial_number
                )
            return self

        if pnp_state == "Error":
            reset_response = self.reset_error_device(self.have["device_id"])
            if reset_response:
                self.msg = "Device reset done Successfully"
                self.log(self.msg, "INFO")
                self.result["diff"] = self.validated_config

                if update_response.get("deviceInfo"):
                    self.result["msg"] += " and Device '{0}' updated successfully.".format(
                        serial_number)

                self.set_operation_result(
                    "success", True, self.msg, "INFO", reset_response
                ).check_return_status()
                return self

        if not (
            prov_dev_response.get("response") == 0
            and plan_dev_response.get("response") == 0
            and pnp_state == "Unclaimed"
        ):
            self.result["response"] = self.have.get("device_found")
            self.result["msg"] = "Device is already claimed"
            self.log(self.result["msg"], "WARNING")
            if update_response.get("deviceInfo"):
                self.result["changed"] = True
                self.result["msg"] += " and Device '{0}' updated successfully.".format(
                    serial_number
                )
                return self

        claim_params = self.get_claim_params()
        self.log(
            "Parameters for claiming the device: {0}".format(str(claim_params)), "DEBUG"
        )

        claim_response = self.claim_device_site(claim_params)
        self.log(
            "Response from 'claim_a_device_to_a_site' API for claiming: {0}".format(
                str(claim_response)
            ),
            "DEBUG",
        )

        if claim_response.get("response") == "Device Claimed":
            self.result["msg"] = "Only Device Claimed Successfully"
            self.log(self.result["msg"], "INFO")
            self.result["response"] = claim_response
            self.result["diff"] = self.validated_config
            self.result["changed"] = True
            if update_response.get("deviceInfo"):
                self.result["msg"] += " and Device '{0}' updated successfully.".format(
                    serial_number
                )

        return self

    def get_diff_deleted(self):
        """
        If the given device is added to pnp database
        and is in unclaimed or failed state delete the
        given device
        Args:
            self: An instance of a class used for interacting with Cisco Catalyst Center.
            Here we pass a list of device info to be deleted
        Returns:
            self: An instance of the class with updated results and status based on
            the deletion operation. It tells us the number of devices deleted if any of the devices
            get deleted
        Description:
            This function is responsible for removing devices from the Cisco Catalyst Center PnP GUI and
            pass new changes if devices are already deleted.
        """
        devices_deleted = []
        devices_to_delete = self.want.get("pnp_params")[:]
        for device in devices_to_delete:
            multi_device_response = self.get_device_list_pnp(
                device["deviceInfo"]["serialNumber"]
            )
            self.log(
                "Response from 'get_device_list' API for claiming: {0}".format(
                    str(multi_device_response)
                ),
                "DEBUG",
            )

            if multi_device_response:
                device_id = multi_device_response.get("id")

                response = self.dnac_apply["exec"](
                    family="device_onboarding_pnp",
                    function="delete_device_by_id_from_pnp",
                    op_modifies=True,
                    params={"id": device_id},
                )
                self.log(
                    "Device details for the deleted device with \
                        serial number '{0}': {1}".format(
                        device["deviceInfo"]["serialNumber"], str(response)
                    ),
                    "DEBUG",
                )
                if response.get("deviceInfo", {}).get("state") == "Deleted":
                    devices_deleted.append(device["deviceInfo"]["serialNumber"])
                    self.want.get("pnp_params").remove(device)
                else:
                    self.result["response"] = response
                    self.result["msg"] = "Error while deleting the device"
                    self.log(self.result["msg"], "CRITICAL")

        if len(devices_deleted) > 0:
            self.result["changed"] = True
            self.result["response"] = devices_deleted
            self.result["diff"] = self.want.get("pnp_params")
            self.result["msg"] = "{0} Device(s) Deleted Successfully".format(
                len(devices_deleted)
            )
            self.log(self.result["msg"], "INFO")
        else:
            self.result["msg"] = "Device(s) Not Found"
            self.log(self.result["msg"], "WARNING")
            self.result["response"] = devices_deleted

        return self

    def verify_diff_merged(self, config):
        """
        Verify the merged status(Creation/Updation) of PnP configuration in Cisco Catalyst Center.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.
        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the merged status of a configuration in Cisco Catalyst Center by
            retrieving the current state (have) and desired state (want) of the configuration,
            logs the states, and validates whether the specified device(s) exists in the DNA
            Center configuration's PnP Database.
        """
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(config)), "INFO")
        # Code to validate Cisco Catalyst Center config for merged state
        for device in self.want.get("pnp_params"):
            device_response = self.get_device_list_pnp(
                device["deviceInfo"]["serialNumber"]
            )

            if device_response and (len(device_response) == 1):
                msg = (
                    "Requested Device with Serial No. {0} is "
                    "present in Cisco Catalyst Center and"
                    " addition verified.".format(device["deviceInfo"]["serialNumber"])
                )
                self.log(msg, "INFO")
            else:
                msg = (
                    "Requested Device with Serial No. {0} is "
                    "not present in Cisco Catalyst Center"
                    "Center".format(device["deviceInfo"]["serialNumber"])
                )
                self.log(msg, "WARNING")

        self.status = "success"
        return self

    def verify_diff_deleted(self, config):
        """
        Verify the deletion status of PnP configuration in Cisco Catalyst Center.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.
        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the deletion status of a configuration in Cisco Catalyst Center.
            It validates whether the specified device(s) exists in the Cisco Catalyst Center configuration's
            PnP Database.
        """
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(config)), "INFO")
        # Code to validate Cisco Catalyst Center config for deleted state
        for device in self.want.get("pnp_params"):
            device_response = self.get_device_list_pnp(
                device["deviceInfo"]["serialNumber"]
            )

            if not (device_response and (len(device_response) == 1)):
                msg = (
                    "Requested Device with Serial No. {0} is "
                    "not present in the Cisco DNA"
                    "Center.".format(device["deviceInfo"]["serialNumber"])
                )
                self.log(msg, "INFO")
            else:
                msg = (
                    "Requested Device with Serial No. {0} is "
                    "present in Cisco Catalyst Center".format(
                        device["deviceInfo"]["serialNumber"]
                    )
                )
                self.log(msg, "WARNING")

        self.status = "success"
        return self

    def get_device_list_pnp(self, serial_number):
        """
        Get the PNP device list from the Cisco Catalyst Center.

        Parameters:
          - self (object): An instance of the class containing the method.
          - serial_number (str): Serial number contains string from the device data.
        Returns:
          The method returns an instance of the class with updated attributes:
          - self.device_response: Gets the device_id and stores it

        Example:
          passing device details and getting pnp device details response
        """
        try:
            response = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="get_device_list",
                params={"serial_number": serial_number},
            )

            if response and isinstance(response, list) and len(response) == 1:
                self.device_response = response[0]
                self.log(
                    "Successfully retrieved PNP device details for serial number: {0}".format(
                        serial_number
                    ),
                    "INFO",
                )
                return self.device_response

            msg = "No device found with serial number: {0}".format(serial_number)
            self.log(msg, "WARNING")
            return None

        except Exception as e:
            msg = "An error occurred while retrieving device with serial number {0}: {1}".format(
                serial_number, str(e)
            )
            self.log(msg + str(e), "WARNING")
            self.set_operation_result(
                "failed", False, msg, "ERROR"
            ).check_return_status()

    def get_device_by_id_pnp(self, device_id):
        """
        Get the PNP device details using by device id from the Cisco Catalyst Center.

        Parameters:
        - self (object): An instance of the class containing the method.
        - device_id (str): Device id contains id from the device data
        Returns:
        The method returns an instance of the class with updated attributes:
        - self.device_response: Gets the device_id and stores it

        Example:
        passing device details and getting pnp device details response
        """
        self.log(
            "Attempting to retrieve PNP device details for device id: {0}".format(
                device_id
            ),
            "INFO",
        )
        try:
            device_details_response = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="get_device_by_id",
                params={"id": device_id},
            )
            # Check if the response contains the expected data
            if device_details_response:
                self.device_response = (
                    device_details_response  # Update the instance attribute
                )
                self.log(
                    "Successfully retrieved PNP device details for device id: {0}".format(
                        device_id
                    ),
                    "INFO",
                )
                return self.device_response

            # If no device found, raise an error
            msg = "No device found with device id: {0}".format(device_id)
            self.log(msg, "WARNING")
            self.set_operation_result(
                "failed", False, msg, "ERROR"
            ).check_return_status()

        except Exception as e:
            msg = "An error occurred while retrieving device with device id {0}: {1}".format(
                device_id, str(e)
            )
            self.log(msg + str(e), "WARNING")
            self.set_operation_result(
                "failed", False, msg, "ERROR"
            ).check_return_status()

    def add_pnp_device(self, pnp_params):
        """
        Add the PNP device in the Cisco Catalyst Center.

        Parameters:
        - self (object): An instance of the class containing the method.
        - pnp_params (dict): Device infomation to add in the inventry
        Returns:
        The method returns an instance of the class with updated attributes:
        - self.device_response: Gets the device_id and stores it

        Example:
        passing device details and getting pnp device details response
        """
        self.log(
            "Attempting to add PNP device with parameters: {0}".format(pnp_params),
            "INFO",
        )
        try:
            device_add_response = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="add_device",
                params=pnp_params,
                op_modifies=True,
            )
            if device_add_response:
                self.device_response = (
                    device_add_response  # Update the instance attribute
                )
                self.log(
                    "Successfully added PNP device with parameters: {0}".format(
                        pnp_params
                    ),
                    "INFO",
                )
                return self.device_response

            # If the response is empty, log a warning
            msg = "No response received when trying to add the PNP device with parameters: {0}".format(
                pnp_params
            )
            self.log(msg, "WARNING")
            self.module.fail_json(msg=msg)

        except Exception as e:
            msg = (
                "Unable to add the PNP device with parameters: {0}. Error: {1}".format(
                    pnp_params, str(e)
                )
            )
            self.log(msg + str(e), "WARNING")
            self.set_operation_result(
                "failed", False, msg, "ERROR"
            ).check_return_status()

    def pnp_device_count(self, pnp_params):
        """
        Get the PNP device count from the Cisco Catalyst Center.

        Parameters:
            - self (object): An instance of the class containing the method.
            - pnp_params (dict): Device infomation to get the pnp device fields
        Returns:
            The method returns an instance of the class with count attributes:
            - prov_dev_response: Show the count of the pnp devices

        Example:
            passing device param and getting pnp device count response
        """
        self.log(
            "Attempting to get PNP device count with parameters: {0}".format(
                pnp_params
            ),
            "INFO",
        )
        try:
            prov_dev_response = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="get_device_count",
                params=pnp_params,
            )
            if prov_dev_response:
                self.log(
                    "Successfully retrieved PNP device count: {0}".format(
                        prov_dev_response
                    ),
                    "INFO",
                )
                return prov_dev_response

            # If the response is empty, log a warning
            msg = "No response received when trying to get the PNP device count for parameters: {0}".format(
                pnp_params
            )
            self.log(msg, "WARNING")
            self.set_operation_result(
                "failed", False, msg, "ERROR"
            ).check_return_status()

        except Exception as e:
            msg = "Unable to get the PNP device count for parameters: {0}. Error: {1}".format(
                pnp_params, str(e)
            )
            self.log(msg + str(e), "WARNING")
            self.set_operation_result(
                "failed", False, msg, "ERROR"
            ).check_return_status()

    def claim_device_site(self, claim_params):
        """
        Claim the PNP device from the Cisco Catalyst Center.

        Parameters:
            - self (object): An instance of the class containing the method.
            - claim_params (dict): Device infomation to get the pnp device fields
        Returns:
            The method returns an instance of the class with count attributes:
            - claim_response: Show the count of the pnp devices

        Example:
            passing device claim param and getting pnp claim response
        """
        self.log(
            "Attempting to claim device to site with parameters: {0}".format(
                claim_params
            ),
            "INFO",
        )
        try:
            claim_response = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="claim_a_device_to_a_site",
                op_modifies=True,
                params=claim_params,
            )
            if claim_response:
                self.log(
                    "Successfully claimed device to site: {0}".format(claim_response),
                    "INFO",
                )
                return claim_response

            # If the response is empty, log a warning
            msg = "No response received when trying to claim the device to site with parameters: {0}".format(
                claim_params
            )
            self.log(msg, "WARNING")
            self.set_operation_result(
                "failed", False, msg, "ERROR"
            ).check_return_status()

        except Exception as e:
            msg = "Unable to claim the device to site with parameters: {0}. Error: {1}".format(
                claim_params, str(e)
            )
            self.log(msg + str(e), "WARNING")
            self.set_operation_result(
                "failed", False, msg, "ERROR"
            ).check_return_status()


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
        "validate_response_schema": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
    }

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    ccc_pnp = PnP(module)
    state = ccc_pnp.params.get("state")

    if ccc_pnp.compare_dnac_versions(ccc_pnp.get_ccc_version(), "2.3.5.3") < 0:
        ccc_pnp.status = "failed"
        ccc_pnp.msg = (
            "The specified version '{0}' does not support the PNP workflow feature."
            "Supported version(s) start from '2.3.5.3' onwards.".format(
                ccc_pnp.get_ccc_version()
            )
        )
        ccc_pnp.log(ccc_pnp.msg, "ERROR")
        ccc_pnp.check_return_status()

    if state not in ccc_pnp.supported_states:
        ccc_pnp.status = "invalid"
        ccc_pnp.msg = "State {0} is invalid".format(state)
        ccc_pnp.check_return_status()

    ccc_pnp.validate_input().check_return_status()
    config_verify = ccc_pnp.params.get("config_verify")

    for config in ccc_pnp.validated_config:
        ccc_pnp.reset_values()
        ccc_pnp.get_want(config).check_return_status()
        ccc_pnp.get_have().check_return_status()
        ccc_pnp.get_diff_state_apply[state]().check_return_status()
        if config_verify:
            ccc_pnp.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_pnp.result)


if __name__ == "__main__":
    main()
