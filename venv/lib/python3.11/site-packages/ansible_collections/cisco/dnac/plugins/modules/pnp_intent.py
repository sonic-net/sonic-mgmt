#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Abinash Mishra, Madhan Sankaranarayanan, Rishita Chowdhary"
DOCUMENTATION = r"""
---
module: pnp_intent
short_description: Resource module for Site and PnP
  related functions
description:
  - Manage operations add device, claim device and unclaim
    device of Onboarding Configuration(PnP) resource
  - API to add device to pnp inventory and claim it
    to a site.
  - API to delete device from the pnp inventory.
  - API to reset the device from errored state.
version_added: 6.6.0
extends_documentation_fragment:
  - cisco.dnac.intent_params
author: Abinash Mishra (@abimishr) Madhan Sankaranarayanan
  (@madhansansel) Rishita Chowdhary (@rishitachowdhary)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst
      Center config after applying the playbook config.
    type: bool
    default: false
  state:
    description: The state of Cisco Catalyst Center
      after module completion.
    type: str
    choices:
      - merged
      - deleted
    default: merged
  config:
    description:
      - List of details of device being managed.
    type: list
    elements: dict
    required: true
    suboptions:
      device_info:
        description:
          - Provides the device-specific information
            required for adding devices to the PnP database
            that are not already present.
          - For adding a single device, the list should
            contain exactly one set of device information.
            If a site name is also provided, the device
            can be claimed immediately after being added.
          - For bulk import, the list must contain information
            for more than one device. Bulk import is
            intended solely for adding devices; claiming
            must be performed with separate tasks or
            configurations.
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
          state:
            description:
              - Represents the onboarding state of the
                PnP device.
              - Possible values are 'Unclaimed', 'Claimed',
                or 'Provisioned'.
            type: str
          pid:
            description: Pnp Device's pid.
            type: str
          serial_number:
            description: Pnp Device's serial_number.
            type: str
          is_sudi_required:
            description: Sudi Authentication requiremnet's
              flag.
            type: bool
      site_name:
        description: Name of the site for which device
          will be claimed.
        type: str
      project_name:
        description: Name of the project under which
          the template is present
        type: str
        default: Onboarding Configuration
      template_name:
        description:
          - Name of template to be configured on the
            device.
          - Supported for EWLC from Cisco Catalyst Center
            release version 2.3.7.x onwards.
        type: str
      template_params:
        description:
          - Parameter values for the parameterised templates.
          - Each varibale has a value that needs to
            be passed as key-value pair in the dictionary.
            We can pass values as variable_name:variable_value.
          - Supported for EWLC from Cisco Catalyst Center
            release version 2.3.7.x onwards.
        type: dict
      image_name:
        description: Name of image to be configured
          on the device
        type: str
      golden_image:
        description: Is the image to be condifgured
          tagged as golden image
        type: bool
      pnp_type:
        description: Specifies the device type for the
          Plug and Play (PnP) device. - Options include
          'Default', 'CatalystWLC', 'AccessPoint', or
          'StackSwitch'. - 'Default' is applicable to
          switches and routers. - 'CatalystWLC' should
          be selected for 9800 series wireless controllers.
          - 'AccessPoint' is used when claiming an access
          point. - 'StackSwitch' should be chosen for
          a group of switches that operate as a single
          switch, typically used in the access layer.
        type: str
        choices:
          - Default
          - CatalystWLC
          - AccessPoint
          - StackSwitch
        default: Default
      static_ip:
        description: Management IP address of the Wireless
          Controller
        type: str
      subnet_mask:
        description: Subnet Mask of the Management IP
          address of the Wireless Controller
        type: str
      gateway:
        description: Gateway IP address of the Wireless
          Controller for getting pinged
        type: str
      vlan_id:
        description: Vlan Id allocated for claimimg
          of Wireless Controller
        type: str
      ip_interface_name:
        description: Specifies the interface name utilized
          for Plug and Play (PnP) by the Wireless Controller.
          Ensure this interface is pre-configured on
          the Controller prior to device claiming.
        type: str
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
    get /dna/intent/api/v1/onboarding/pnp-device put
    /onboarding/pnp-device/${id} get /dna/intent/api/v1/site
    get /dna/intent/api/v1/image/importation get /dna/intent/api/v1/template-programmer/template
"""
EXAMPLES = r"""
---
- name: Import multiple switches in bulk only
  cisco.dnac.pnp_intent:
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
  cisco.dnac.pnp_intent:
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
  cisco.dnac.pnp_intent:
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
  cisco.dnac.pnp_intent:
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
    def __init__(self, module):
        super().__init__(module)

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
        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(
                "\n".join(invalid_params)
            )
            self.log(str(self.msg), "ERROR")
            self.status = "failed"
            return self
        self.validated_config = valid_pnp
        self.msg = "Successfully validated playbook config params: {0}".format(
            str(valid_pnp)
        )
        self.log(str(self.msg), "INFO")
        self.status = "success"

        return self

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
            response = self.dnac_apply["exec"](
                family="sites",
                function="get_site",
                params={"name": self.want.get("site_name")},
                op_modifies=True,
            )
        except Exception:
            self.log(
                "Exception occurred as site \
                '{0}' was not found".format(
                    self.want.get("site_name")
                ),
                "CRITICAL",
            )
            self.module.fail_json(msg="Site not found", response=[])

        if response:
            self.log(
                "Received site details \
                for '{0}': {1}".format(
                    self.want.get("site_name"), str(response)
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
            response = self.dnac_apply["exec"](
                family="sites",
                function="get_site",
                params={"name": self.want.get("site_name")},
                op_modifies=True,
            )
        except Exception:
            self.log(
                "Exception occurred as \
                site '{0}' was not found".format(
                    self.want.get("site_name")
                ),
                "CRITICAL",
            )
            self.module.fail_json(msg="Site not found", response=[])

        if response:
            self.log(
                "Received site details\
                for '{0}': {1}".format(
                    self.want.get("site_name"), str(response)
                ),
                "DEBUG",
            )
            site = response.get("response")
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

        return site_type

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
                str(reset_params)
            ),
            "INFO",
        )
        return reset_params

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
            device_response = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="get_device_list",
                params={"serial_number": self.want.get("serial_number")},
                op_modifies=True,
            )
            self.log(
                "Device details for the device with serial \
                number '{0}': {1}".format(
                    self.want.get("serial_number"), str(device_response)
                ),
                "DEBUG",
            )

            if not (device_response and (len(device_response) == 1)):
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
            have["device_id"] = device_response[0].get("id")
            self.log("Device Id: " + str(have["device_id"]))

            if self.params.get("state") == "merged":
                # check if given image exists, if exists store image_id
                image_response = self.dnac_apply["exec"](
                    family="software_image_management_swim",
                    function="get_software_image_details",
                    params=self.want.get("image_params"),
                    op_modifies=True,
                )
                image_list = image_response.get("response")
                self.log(
                    "Image details obtained from the API 'get_software_image_details': {0}".format(
                        str(image_response)
                    ),
                    "DEBUG",
                )

                # check if project has templates or not
                template_list = self.dnac_apply["exec"](
                    family="configuration_templates",
                    function="gets_the_templates_available",
                    params={"project_names": self.want.get("project_name")},
                    op_modifies=True,
                )
                self.log(
                    "List of templates under the project '{0}': {1}".format(
                        self.want.get("project_name"), str(template_list)
                    ),
                    "DEBUG",
                )

                dev_details_response = self.dnac_apply["exec"](
                    family="device_onboarding_pnp",
                    function="get_device_by_id",
                    params={"id": device_response[0].get("id")},
                    op_modifies=True,
                )
                self.log(
                    "Device details retrieved after calling the 'get_device_by_id' API: {0}".format(
                        str(dev_details_response)
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

                # check if given site exits, if exists store current site info
                site_exists = False
                if not isinstance(
                    self.want.get("site_name"), str
                ) and not self.want.get("pnp_params")[0].get("deviceInfo"):
                    self.msg = "The site name must be a string"
                    self.log(str(self.msg), "ERROR")
                    self.status = "failed"
                    return self

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
                        self.status = "failed"
                        return self

                    if len(image_list) == 1:
                        if install_mode != "INSTALL":
                            self.msg = (
                                "The system must be in INSTALL mode to upgrade the image. The current mode is '{0}'."
                                " Please switch to INSTALL mode to proceed.".format(
                                    install_mode
                                )
                            )
                            self.log(str(self.msg), "CRITICAL")
                            self.status = "failed"
                            return self

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
                            self.status = "failed"
                            return self

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
                            self.status = "failed"
                            return self

                else:
                    if not self.want.get("pnp_params")[0].get("deviceInfo"):
                        self.msg = "Either Site Name or Device details must be added."
                        self.log(self.msg, "ERROR")
                        self.status = "failed"
                        return self

        self.msg = "Successfully collected all project and template \
                    parameters from Cisco Catalyst Center for comparison"
        self.log(self.msg, "INFO")
        self.status = "success"
        self.have = have
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
            self.status = "failed"
            return self

        if len(self.want.get("pnp_params")) > 1:
            devices_added = []
            for device in self.want.get("pnp_params"):
                multi_device_response = self.dnac_apply["exec"](
                    family="device_onboarding_pnp",
                    function="get_device_list",
                    params={"serial_number": device["deviceInfo"]["serialNumber"]},
                    op_modifies=True,
                )
                self.log(
                    "Device details for serial number {0} \
                        obtained from the API 'get_device_list': {1}".format(
                        device["deviceInfo"]["serialNumber"], str(multi_device_response)
                    ),
                    "DEBUG",
                )
                if multi_device_response and (len(multi_device_response) == 1):
                    devices_added.append(device)
                    self.log(
                        "Details of the added device:{0}".format(str(device)), "INFO"
                    )
            if (len(self.want.get("pnp_params")) - len(devices_added)) == 0:
                self.result["response"] = []
                self.result["msg"] = "Devices are already added"
                self.log(self.result["msg"], "WARNING")
                return self

            bulk_list = [
                device
                for device in self.want.get("pnp_params")
                if device not in devices_added
            ]
            bulk_params = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="import_devices_in_bulk",
                params={"payload": bulk_list},
                op_modifies=True,
            )
            self.log(
                "Response from API 'import_devices_in_bulk' for imported devices: {0}".format(
                    bulk_params
                ),
                "DEBUG",
            )
            if len(bulk_params.get("successList")) > 0:
                self.result["msg"] = "{0} device(s) imported successfully".format(
                    len(bulk_params.get("successList"))
                )
                self.log(self.result["msg"], "INFO")
                self.result["response"] = bulk_params
                self.result["diff"] = self.validated_config
                self.result["changed"] = True
                return self

            self.msg = "Bulk import failed"
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self

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
                self.status = "failed"
                return self

            if not self.want["site_name"]:
                self.log("Adding device to pnp database", "INFO")
                dev_add_response = self.dnac_apply["exec"](
                    family="device_onboarding_pnp",
                    function="add_device",
                    params=self.want.get("pnp_params")[0],
                    op_modifies=True,
                )

                self.have["deviceInfo"] = dev_add_response.get("deviceInfo")
                self.log(
                    "Response from API 'add device' for a single device addition: {0}".format(
                        str(dev_add_response)
                    ),
                    "DEBUG",
                )
                if self.have["deviceInfo"]:
                    self.result["msg"] = "Only Device Added Successfully"
                    self.log(self.result["msg"], "INFO")
                    self.result["response"] = dev_add_response
                    self.result["diff"] = self.validated_config
                    self.result["changed"] = True

                else:
                    self.msg = "Device Addition Failed"
                    self.log(self.result["msg"], "CRITICAL")
                    self.status = "failed"

                return self

            else:
                self.log("Adding device to pnp database")
                dev_add_response = self.dnac_apply["exec"](
                    family="device_onboarding_pnp",
                    function="add_device",
                    params=self.want.get("pnp_params")[0],
                    op_modifies=True,
                )
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
                claim_response = self.dnac_apply["exec"](
                    family="device_onboarding_pnp",
                    function="claim_a_device_to_a_site",
                    op_modifies=True,
                    params=claim_params,
                )

                self.log(
                    "Response from API 'claim a device to a site' for a single claiming: {0}".format(
                        str(dev_add_response)
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
                    self.log(self.result["msg"], "CRITICAL")
                    self.status = "failed"

                return self

        prov_dev_response = self.dnac_apply["exec"](
            family="device_onboarding_pnp",
            function="get_device_count",
            op_modifies=True,
            params=provisioned_count_params,
        )
        self.log(
            "Response from 'get device count' API for provisioned devices: {0}".format(
                str(prov_dev_response)
            ),
            "DEBUG",
        )

        plan_dev_response = self.dnac_apply["exec"](
            family="device_onboarding_pnp",
            function="get_device_count",
            op_modifies=True,
            params=planned_count_params,
        )
        self.log(
            "Response from 'get_device_count' API for devices in planned state: {0}".format(
                str(plan_dev_response)
            ),
            "DEBUG",
        )

        dev_details_response = self.dnac_apply["exec"](
            family="device_onboarding_pnp",
            function="get_device_by_id",
            params={"id": self.have["device_id"]},
            op_modifies=True,
        )
        self.log(
            "Response from 'get_device_by_id' API for device details: {0}".format(
                str(dev_details_response)
            ),
            "DEBUG",
        )

        is_stack = False
        if dev_details_response.get("deviceInfo").get("stack"):
            is_stack = dev_details_response.get("deviceInfo").get("stack")
        pnp_state = dev_details_response.get("deviceInfo").get("state")
        self.log("PnP state of the device: {0}".format(pnp_state), "INFO")

        if not self.want["site_name"]:
            self.result["response"] = self.have.get("device_found")
            self.result["msg"] = "Device is already added"
            self.log(self.result["msg"], "WARNING")
            return self

        update_payload = {
            "deviceInfo": self.want.get("pnp_params")[0].get("deviceInfo")
        }
        update_payload["deviceInfo"]["stack"] = is_stack

        self.log(
            "The request sent for 'update_device' API for device's config update: {0}".format(
                update_payload
            ),
            "DEBUG",
        )
        update_response = self.dnac_apply["exec"](
            family="device_onboarding_pnp",
            function="update_device",
            params={"id": self.have["device_id"], "payload": update_payload},
            op_modifies=True,
        )
        self.log(
            "Response from 'update_device' API for device's config update: {0}".format(
                str(update_response)
            ),
            "DEBUG",
        )

        if pnp_state == "Error":
            reset_paramters = self.get_reset_params()
            reset_response = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="reset_device",
                params={"payload": reset_paramters},
                op_modifies=True,
            )
            self.log(
                "Response from 'update_device' API for errored state resolution: {0}".format(
                    str(reset_response)
                ),
                "DEBUG",
            )
            self.result["msg"] = "Device reset done Successfully"
            self.log(self.result["msg"], "INFO")
            self.result["response"] = reset_response
            self.result["diff"] = self.validated_config
            self.result["changed"] = True

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
                return self

        claim_params = self.get_claim_params()
        self.log(
            "Parameters for claiming the device: {0}".format(str(claim_params)), "DEBUG"
        )

        claim_response = self.dnac_apply["exec"](
            family="device_onboarding_pnp",
            function="claim_a_device_to_a_site",
            op_modifies=True,
            params=claim_params,
        )
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
            multi_device_response = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="get_device_list",
                params={"serial_number": device["deviceInfo"]["serialNumber"]},
                op_modifies=True,
            )
            self.log(
                "Response from 'get_device_list' API for claiming: {0}".format(
                    str(multi_device_response)
                ),
                "DEBUG",
            )
            if multi_device_response and len(multi_device_response) == 1:
                device_id = multi_device_response[0].get("id")

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
            device_response = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="get_device_list",
                params={"serial_number": device["deviceInfo"]["serialNumber"]},
                op_modifies=True,
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
            device_response = self.dnac_apply["exec"](
                family="device_onboarding_pnp",
                function="get_device_list",
                params={"serial_number": device["deviceInfo"]["serialNumber"]},
                op_modifies=True,
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
