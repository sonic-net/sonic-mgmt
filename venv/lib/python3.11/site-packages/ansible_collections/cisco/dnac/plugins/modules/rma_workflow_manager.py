#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Trupti A Shetty, Mohamed Rafeek, Madhan Sankaranarayanan, Ajith Andrew J"
DOCUMENTATION = r"""
---
module: rma_workflow_manager
short_description: Manage device replacement workflows
  in Cisco Catalyst Center.
description:
  - The purpose of this workflow is to provide a streamlined
    and efficient process for network administrators,
    to initiate Return Material Authorization (RMA)
    requests for faulty network devices. This automation
    aims to simplify the RMA process, reduce manual
    effort, and enhance overall operational efficiency.
  - Implement an RMA (Return Material Authorization)
    workflow within Cisco Catalyst Center, enabling
    a seamless process for returning and replacing faulty
    network devices.
  - The RMA workflow facilitates the replacement of
    routers, switches, and Access Points (APs).
  - Allows administrators to mark devices for replacement
    and track the entire replacement workflow.
  - For routers and switches, the software image, configuration,
    and licenses are restored from the failed device
    to the replacement device, ensuring minimal disruption.
  - For wireless APs, the replacement device is assigned
    to the same site, provisioned with the primary wireless
    controller, RF profile, and AP group settings, and
    placed on the same floor map location in Cisco Catalyst
    Center as the failed AP.
  - Need to consider the following before doing RMA,
    - Ensure the software image version of the faulty
    device is imported into the image repository before
    initiating the replacement process. - The faulty
    device must be in an unreachable state to be eligible
    for RMA. - If the replacement device onboards Cisco
    Catalyst Center through Plug and Play (PnP), ensure
    the faulty device is assigned to a user-defined
    site. - The replacement device must not be in a
    provisioning state during the initiation of the
    RMA workflow. - The AP RMA feature supports only
    like-to-like replacements, meaning the replacement
    AP must have the same model number and Product ID
    (PID) as the faulty AP. - The replacement AP must
    have joined the same Cisco Wireless Controller as
    the faulty AP. - Cisco Mobility Express APs acting
    as wireless controllers are not eligible for replacement
    through this RMA workflow. - Ensure the software
    image version of the faulty AP is imported into
    the image repository before initiating the replacement
    process. - The faulty device must be assigned to
    a user-defined site if the replacement device onboards
    Cisco Catalyst Center through Plug and Play (PnP).
    - The replacement AP must not be in a provisioning
    state during the initiation of the RMA workflow.
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Trupti A Shetty (@TruptiAShetty)
  - A Mohamed Rafeek (@mohamedrafeek)
  - Madhan Sankaranarayanan (@madhansansel)
  - Ajith Andrew J (@ajithandrewj)
options:
  config_verify:
    description: |
      Set to True to verify the Cisco Catalyst Center configuration after applying the playbook config.
    type: bool
    default: false
  state:
    description: |
      The 'replaced' state is used to indicate the replacement of faulty network devices with
      replacement network device in the workflow.
      The 'deleted' state is used to unmark the faulty network devices in the workflow.
    type: str
    choices: ['replaced', 'deleted']
    default: replaced
  ccc_poll_interval:
    description: |
      The interval, in seconds, for polling Cisco Catalyst Center.
    type: int
    default: 2
  resync_retry_count:
    description: |
      The number of times to retry resynchronization.
    type: int
    default: 1000
  resync_retry_interval:
    description: |
      The interval, in seconds, between resynchronization retries.
    type: int
    default: 30
  timeout_interval:
    description: |
      The timeout interval, in seconds, for operations.
    type: int
    default: 100
  config:
    description: |
      A list of faulty and replacement device details for initiating the RMA workflow.
    type: list
    elements: dict
    required: true
    suboptions:
      faulty_device_name:
        description: |
          The name or hostname of the faulty device.
          Example: SJ-EN-9300.cisco.local
        type: str
      faulty_device_ip_address:
        description: |
          The IP address of the faulty device.
          Example: 204.192.3.40
        type: str
      faulty_device_serial_number:
        description: |
          The serial number of the faulty device.
          Example: FJC2327U0S2
        type: str
      replacement_device_ip_address:
        description: |
          The IP address of the replacement device.
          Example: 204.1.2.5
        type: str
      replacement_device_name:
        description: |
          The name or hostname of the replacement device.
          Example: SJ-EN-9300.cisco.local
        type: str
      replacement_device_serial_number:
        description: |
          The serial number of the replacement device.
          Example: FCW2225C020
        type: str
requirements:
  - dnacentersdk >= 2.7.2
  - python >= 3.10
notes:
  - SDK Method used is - devices.get_device_detail -
    device_replacement.mark_device_for_replacement -
    device_replacement.deploy_device_replacement_workflow
    - device_replacement.unmark_device_for_replacement
  - Path used is - post /dna/intent/api/v1/device-replacement/workflow
    - put  /dna/intent/api/v1/device-replacement/ -
    post /dna/intent/api/v1/device-replacement/
  - limitations
  - RMA supports the replacement of similar devices
    only. For instance,
    a Cisco Catalyst 3650 switch
    can only be replaced with another Cisco Catalyst
    3650 switch. The platform IDs of the faulty and
    replacement devices must match. The model number
    of a Cisco device can be fetched using the `show
    version` command.
  - RMA supports the replacement of all switches,
    routers,
    and Cisco SD-Access devices,
    except for the following,
    - Chassis-based Nexus 7700 Series Switches - Devices
    with embedded wireless controllers - Cisco Wireless
    Controllers
  - RMA supports devices with an external SCEP broker
    PKI certificate. The PKI certificate is created
    and authenticated for the replacement device during
    the RMA workflow. The PKI certificate of the replaced
    faulty device must be manually deleted from the
    certificate server.
  - The RMA workflow supports device replacement only
    if the following conditions are met,
    - Faulty and
    replacement devices must have the same extension
    cards. - The faulty device must be managed by Catalyst
    Center with a static IP. (RMA is not supported for
    devices managed by Catalyst Center with a DHCP IP.)
    - The number of ports in both devices must not vary
    due to the extension cards. - The replacement device
    must be connected to the same port to which the
    faulty device was connected.
  - Cisco Catalyst Center does not support legacy license
    deployment.
  - If the software image installed on the faulty device
    is earlier than Cisco IOS XE 16.8,
    the same legacy
    network license must be manually installed on the
    replacement device.
  - The RMA workflow deregisters the faulty device from
    Cisco SSM and registers the replacement device with
    Cisco SSM.
  - Cisco Catalyst Center supports PnP onboarding of
    the replacement device in a fabric network,
    except
    for the following,
    - The faulty device is connected
    to an uplink device using multiple interfaces. -
    LAN automation using an overlapping pool.
  - If the replacement device onboards through PnP-DHCP
    functionality,
    ensure the device receives the same
    IP address after every reload and that the DHCP
    lease timeout is longer than two hours.
"""
"""
- User can use either one of the below playbook.
"""
EXAMPLES = r"""
---
- name: RMA workflow for faulty device replacement using
    device names
  cisco.dnac.rma_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    resync_retry_count: 1000
    resync_retry_interval: 30
    ccc_poll_interval: 2
    timeout_interval: 100
    state: replaced
    config:
      - faulty_device_name: "SJ-EN-9300.cisco.local"
        replacement_device_name: "SJ-EN-9300.cisco-1.local"
  register: result
- name: RMA workflow for faulty device replacement using
    IP addresses
  cisco.dnac.rma_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    resync_retry_count: 1000
    resync_retry_interval: 30
    ccc_poll_interval: 2
    timeout_interval: 100
    state: replaced
    config:
      - faulty_device_ip_address: "204.192.3.40"
        replacement_device_ip_address: "204.1.2.5"
  register: result
- name: RMA workflow for faulty device replacement using
    serial numbers
  cisco.dnac.rma_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    resync_retry_count: 1000
    resync_retry_interval: 30
    ccc_poll_interval: 2
    timeout_interval: 100
    state: replaced
    config:
      - faulty_device_serial_number: "FJC2327U0S2"
        replacement_device_serial_number: "FCW2225C020"
  register: result
- name: RMA workflow for unmark faulty device using
    device names
  cisco.dnac.rma_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    resync_retry_count: 1000
    resync_retry_interval: 30
    ccc_poll_interval: 2
    timeout_interval: 100
    state: deleted
    config:
      - faulty_device_name: "SJ-EN-9300.cisco.local"
  register: result
- name: RMA workflow for unmark faulty device using
    IP addresses
  cisco.dnac.rma_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    resync_retry_count: 1000
    resync_retry_interval: 30
    ccc_poll_interval: 2
    timeout_interval: 100
    state: deleted
    config:
      - faulty_device_ip_address: 204.1.2.9
  register: result
- name: RMA workflow for unmark faulty device using
    serial numbers
  cisco.dnac.rma_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    resync_retry_count: 1000
    resync_retry_interval: 30
    ccc_poll_interval: 2
    timeout_interval: 100
    state: deleted
    config:
      - faulty_device_serial_number: "FJC2327U0S2"
  register: result
- name: RMA workflow for unmark faulty device using
    all
  cisco.dnac.rma_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    resync_retry_count: 1000
    resync_retry_interval: 30
    ccc_poll_interval: 2
    timeout_interval: 100
    state: deleted
    config:
      - faulty_device_name: "SJ-EN-9300.cisco.local"
      - faulty_device_ip_address: 204.1.2.9
      - faulty_device_serial_number: "FJC2327U0S2"
  register: result
"""
RETURN = r"""
#Case_1: Marks device for replacement
response_1:
  description: >
    Object with API execution details as returned by the Cisco Catalyst Center Python SDK.
  returned: always
  type: dict
  sample: |
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
#Case_2: Error while marking device for Replacement.
response_2:
  description: >
    Object with API execution details as returned by the Cisco Catalyst Center Python SDK.
  returned: always
  type: dict
  sample: |
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
#Case_3: API to trigger RMA workflow that will replace faulty device with replacement device with same configuration and images
response_3:
  description: >
    Object with API execution details as returned by the Cisco Catalyst Center Python SDK.
  returned: always
  type: dict
  sample: |
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
#Case_4: RMA workflow failed to replace faulty device with replacement device.
response_4:
  description: >
    Object with API execution details as returned by the Cisco Catalyst Center Python SDK.
  returned: always
  type: dict
  sample: |
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""

import re
import json
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    validate_str,
)
from ansible.module_utils.basic import AnsibleModule
import time


class DeviceReplacement(DnacBase):
    """Class containing member attributes for rma_workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.result["response"] = []
        self.supported_states = ["replaced", "deleted"]
        self.payload = module.params
        self.keymap = {}
        self.faulty_device, self.replacement_device = [], []

    def pprint(self, jsondata):
        return json.dumps(jsondata, indent=4, separators=(",", ": "))

    def validate_input(self):
        """
        Validate the fields provided in the yml files for RMA workflow.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types based on input.
        Parameters:
            - self (object): An instance of a class used for interacting with the RMA workflow.
        Returns:
            self: An instance of the class with updated attributes:
                - self.msg (str): A message describing the validation result.
                - self.status (str): The status of the validation (either 'success' or 'failed').
                - self.validated_config (list): If successful, a validated version of the 'device_replacements' parameter.
        Description:
            - To use this method, create an instance of the class and call `validate_input` on it.
            - If the validation succeeds, it returns "success" and allows proceeding to the next step.
            - If it fails, `self.status` will be "failed", and `self.msg` will describe the validation issues.
            - The method checks for the presence and validity of various device-related fields such as
            device names, IP addresses, and serial numbers.
            - It removes any None values from the validated configuration.
            - If no configuration is available in the playbook, it returns success with an appropriate message.
        """

        self.log("Validating the Playbook YAML File..", "INFO")

        if not self.config:
            self.status = "success"
            self.msg = "Configuration is not available in the playbook for validation"
            self.log(self.msg, "ERROR")
            return self

        device_list = self.payload.get("config")
        device_list = self.camel_to_snake_case(device_list)

        # Define the expected specification for RMA parameters
        rma_spec = {
            "faulty_device_name": {"required": False, "type": "str"},
            "faulty_device_ip_address": {"required": False, "type": "str"},
            "replacement_device_name": {"required": False, "type": "str"},
            "replacement_device_ip_address": {"required": False, "type": "str"},
            "faulty_device_serial_number": {"required": False, "type": "str"},
            "replacement_device_serial_number": {"required": False, "type": "str"},
        }

        valid_param, invalid_params = validate_list_of_dicts(device_list, rma_spec)
        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(
                "\n".join(invalid_params)
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        # Remove None values from valid_param
        self.validated_config = []

        for config in valid_param:
            filtered_config = {}
            for key in config:
                if config[key] is not None:
                    filtered_config[key] = config[key]
            self.validated_config.append(filtered_config)

        self.log(
            "Validated config: {0}".format(self.pprint(self.validated_config)), "INFO"
        )
        self.msg = "Successfully validated playbook config params:{0}".format(
            str(self.validated_config[0])
        )
        self.log(self.msg, "INFO")
        self.status = "success"
        return self

    def get_want(self, config):
        """
        Get all faulty and replacement device related information from the playbook needed for the RMA workflow
        in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing configuration information for device replacement.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            Retrieves all device replacement configuration details from the playbook config,
            excluding any fields not directly related to the device replacement workflow.
            The extracted information is stored in the 'want' attribute of the instance for
            later use in the workflow. It also performs validation on the configuration parameters.
        """

        want = {}
        want["config"] = {}

        for key in config:
            if config[key] is not None:
                want["config"][key] = config[key]
        self.want = want

        # Perform config validation
        self.validate_device_replacement_params()

        if self.status == "failed":
            self.log("Validation failed. Returning with status 'failed'.", "ERROR")
            return self

        self.log(
            "Desired State (want): {0}".format(str(self.pprint(self.want))), "INFO"
        )
        return self

    def get_have(self):
        """
        Retrieves the current faulty and replacemnet device details from Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of the class with updated attributes:
                - self.have: A dictionary containing the current details of the faulty and replacement devices.
                - self.status: The status of the retrieval operation (either 'success' or 'failed').
        Description:
            This method queries Cisco Catalyst Center to check if the specified faulty and
            replacement devices exist. If the devices exist, it retrieves details about them,
            including their IDs and serial numbers. The results are stored in the 'have'
            attribute for later reference in the RMA workflow. If any device is not found
            or an error occurs, it logs the error and updates the status accordingly.
        """

        # Check if 'want' dictionary is valid
        if not self.want or not self.want.get("config"):
            self.msg = "Invalid or missing 'want' dictionary"
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        have = {}
        config = self.want["config"]
        if self.payload.get("state") == "replaced":
            identifier_keys = [
                ("faulty_device_serial_number", "replacement_device_serial_number"),
                ("faulty_device_serial_number", "replacement_device_name"),
                ("faulty_device_serial_number", "replacement_device_ip_address"),
                ("faulty_device_name", "replacement_device_serial_number"),
                ("faulty_device_name", "replacement_device_name"),
                ("faulty_device_name", "replacement_device_ip_address"),
                ("faulty_device_ip_address", "replacement_device_ip_address"),
                ("faulty_device_ip_address", "replacement_device_name"),
                ("faulty_device_ip_address", "replacement_device_serial_number"),
            ]

            valid_identifier_found = False

            # Iterate through identifier keys to find valid device combinations
            for faulty_key, replacement_key in identifier_keys:
                faulty_identifier = config.get(faulty_key)
                replacement_identifier = config.get(replacement_key)

                if faulty_identifier and replacement_identifier:
                    valid_identifier_found = True

                    # Check if faulty device exists
                    faulty_device = self.device_exists(faulty_identifier, faulty_key)

                    if not faulty_device:
                        self.msg = "Faulty device '{0}' not found in Cisco Catalyst Center".format(
                            faulty_identifier
                        )
                        self.log(self.msg, "ERROR")
                        self.status = "failed"
                        return self

                    have["faulty_device_id"] = faulty_device.get("device_id")
                    have["faulty_device_serial_number"] = faulty_device.get(
                        "serial_number"
                    )
                    have["faulty_device_name"] = faulty_device.get("device_name")
                    have["faulty_device_reachability_status"] = faulty_device.get(
                        "reachability_status"
                    )
                    have["faulty_device_platform_id"] = faulty_device.get("platform_id")
                    have[faulty_key] = faulty_identifier
                    have["faulty_device_exists"] = True
                    self.log(
                        "Faulty device '{0}' found in Cisco Catalyst Center".format(
                            faulty_identifier
                        ),
                        "INFO",
                    )

                    # Check if replacement device exists
                    replacement_device = self.device_exists(
                        replacement_identifier, replacement_key
                    )

                    if not replacement_device:
                        self.log(
                            "Replacement device '{0}' not found in inventory, checking in PnP...",
                            "DEBUG",
                        )
                        replacement_device = self.pnp_device_exists(
                            replacement_identifier, replacement_key
                        )

                        if not replacement_device:
                            self.msg = (
                                "Replacement device '{0}' not found in PnP".format(
                                    replacement_identifier
                                )
                            )
                            self.log(self.msg, "ERROR")
                            self.status = "failed"
                            return self

                    have["replacement_device_id"] = replacement_device.get("device_id")
                    have["replacement_device_serial_number"] = replacement_device.get(
                        "serial_number"
                    )
                    have["replacement_device_name"] = replacement_device.get(
                        "device_name"
                    )
                    have["replacement_device_reachability_status"] = (
                        replacement_device.get("reachability_status")
                    )
                    have["replacement_device_platform_id"] = replacement_device.get(
                        "platform_id"
                    )
                    have["is_pnp_replacement_device"] = replacement_device.get(
                        "is_pnp_device"
                    )
                    have[replacement_key] = replacement_identifier
                    have["replacement_device_exists"] = True
                    self.log(
                        "Replacement device '{0}' found in Cisco Catalyst Center".format(
                            replacement_identifier
                        ),
                        "INFO",
                    )
                    break

            # Check if any valid identifier combination was not found
            if not valid_identifier_found:
                provided_identifiers = {
                    key: value
                    for key, value in config.items()
                    if key in [item for sublist in identifier_keys for item in sublist]
                    and value
                }
                self.msg = "No valid device combination found in config. Provided values in config: {0}".format(
                    provided_identifiers
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self
        else:
            identifier_keys = [
                "faulty_device_serial_number",
                "faulty_device_name",
                "faulty_device_ip_address",
            ]

            for faulty_key in identifier_keys:
                faulty_identifier = config.get(faulty_key)

                if faulty_identifier:
                    # Check if faulty device exists
                    faulty_device = self.device_exists(faulty_identifier, faulty_key)

                    if not faulty_device:
                        self.msg = "Faulty device '{0}' not found in Cisco Catalyst Center".format(
                            faulty_identifier
                        )
                        self.log(self.msg, "ERROR")
                        self.status = "failed"
                        return self

                    have["faulty_device_id"] = faulty_device.get("device_id")
                    have["faulty_device_serial_number"] = faulty_device.get(
                        "serial_number"
                    )
                    have["faulty_device_name"] = faulty_device.get("device_name")
                    have["faulty_device_reachability_status"] = faulty_device.get(
                        "reachability_status"
                    )
                    have["faulty_device_platform_id"] = faulty_device.get("platform_id")
                    have[faulty_key] = faulty_identifier
                    have["faulty_device_exists"] = True
                    self.log(
                        "Faulty device '{0}' found in Cisco Catalyst Center".format(
                            faulty_identifier
                        ),
                        "INFO",
                    )

        self.have = have

        if not self.have:
            self.msg = "No valid device information found in config"
            self.log(self.msg, "ERROR")
            self.status = "failed"
        else:
            self.msg = "Successfully retrieved device details: {0}".format(
                self.pprint(config)
            )
            self.log("Current State (have): {0}".format(self.pprint(self.have)), "INFO")
            self.log(self.msg, "INFO")
            self.status = "success"

        return self

    def rma_device_replacement_pre_check(self):
        """
        Performs a pre-check for RMA device replacement to ensure compatibility and reachability.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies that the faulty device and the replacement device belong to the same family and series,
            ensuring they are compatible for replacement. It also checks the network reachability of the replacement device.
            If both checks pass, the method logs a success message and proceeds. If either check fails, it logs an error,
            updates the status to 'failed', and returns the instance for further handling in the RMA workflow.
        """

        if (
            self.have["faulty_device_platform_id"]
            != self.have["replacement_device_platform_id"]
        ):
            self.msg = (
                "The faulty device and the replacement device do not belong to the same platform, family and series."
                " These attributes must match for a valid replacement."
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.log(
            "The faulty device and the replacement device belong to the same platform, family and series.",
            "DEBUG",
        )

        if not self.have["is_pnp_replacement_device"]:
            if self.have["replacement_device_reachability_status"] != "Reachable":
                self.msg = "The replacement device is not reachable. Unable to proceed with the RMA device replacement."
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            self.log(
                "The replacement device '{0}' is reachable.".format(
                    self.have.get("replacement_device_name")
                ),
                "DEBUG",
            )

        return self

    def pnp_device_exists(self, identifier, identifier_type):
        """
        Check if a pnp device exists in Cisco Catalyst Center and return its device ID, device_name, serial_number and platform_id.
        Parameters:
            - self (object): An instance of the class containing the method.
            - identifier (str): The identifier of the device to check.
            - identifier_type (str): The type of identifier (name, ip_address, or serial_number).
        Returns:
            - dict: A dict containing the device ID, device_name, serial_number and platform_id if the device
              is found or empty dict if device not found.
        Description:
            This method queries Cisco Catalyst Center to check if a specified device exists based on the provided identifier.
            It constructs the appropriate query parameters based on the identifier type (hostname, IP address, or serial number).
            The method then sends a request to Cisco Catalyst Center using the 'get_device_list' function.
            If the device is found and both ID and serial number are available, it returns these as a tuple.
            If the device is not found, lacks necessary information, or if an error occurs during the process,
            it logs an appropriate error message and returns empty dict.
            This method is used to verify the existence of both faulty and replacement devices in the RMA workflow.
        """
        params = {}

        if identifier_type.endswith("_name"):
            params["hostname"] = identifier
        elif identifier_type.endswith("_serial_number"):
            params["serialNumber"] = identifier
        else:
            self.log("Invalid identifier type provided", "ERROR")
            return {}

        try:
            response = self.dnac._exec(
                family="device_onboarding_pnp",
                function="get_device_list",
                op_modifies=False,
                params=params,
            )
            self.log(
                "Received API response from 'get_device_list': {0}".format(
                    self.pprint(response)
                ),
                "DEBUG",
            )

            if response:
                device = response[0]
                device_info = device.get("deviceInfo", {})
                device_param_list = {
                    "device_id": device.get("id"),
                    "serial_number": device_info.get("serialNumber"),
                    "device_name": device_info.get("hostname"),
                    "platform_id": device_info.get("pid"),
                    "is_pnp_device": True,
                }

                if device_param_list:
                    return device_param_list
                self.log("Device found but ID or serial number missing", "ERROR")
            else:
                self.log("Device not found in Cisco Catalyst Center", "ERROR")
        except Exception as e:
            self.log(
                "Exception occurred while querying device: {0}".format(str(e)), "ERROR"
            )

        return {}

    def device_exists(self, identifier, identifier_type):
        """
        Check if a device exists in Cisco Catalyst Center and return its device ID, serial_number, device_name, reachability_status, platform_id.
        Parameters:
            - self (object): An instance of the class containing the method.
            - identifier (str): The identifier of the device to check.
            - identifier_type (str): The type of identifier (name, ip_address, or serial_number).
        Returns:
            - dict: A dict containing the device ID, serial_number, device_name, reachability_status, platform_id if the device
              is found or empty dict if device not found.
        Description:
            This method queries Cisco Catalyst Center to check if a specified device exists based on the provided identifier.
            It constructs the appropriate query parameters based on the identifier type (hostname, IP address, or serial number).
            The method then sends a request to Cisco Catalyst Center using the 'get_device_list' function.
            If the device is found and both ID and serial number are available, it returns these as a tuple.
            If the device is not found, lacks necessary information, or if an error occurs during the process,
            it logs an appropriate error message and returns empty dict.
            This method is used to verify the existence of both faulty and replacement devices in the RMA workflow.
        """
        params = {}
        if identifier_type.endswith("_name"):
            params["hostname"] = identifier
        elif identifier_type.endswith("_ip_address"):
            params["managementIpAddress"] = identifier
        elif identifier_type.endswith("_serial_number"):
            params["serialNumber"] = identifier
        else:
            self.log("Invalid identifier type provided", "ERROR")
            return {}

        try:
            response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                op_modifies=False,
                params=params,
            )
            self.log(
                "Received API response from 'get_device_list': {0}".format(
                    self.pprint(response)
                ),
                "DEBUG",
            )
            device_param_list = {}

            if response and response.get("response"):
                if len(response["response"]) > 0:
                    device = response["response"][0]
                    device_param_list["device_id"] = device.get("id")
                    device_param_list["serial_number"] = device.get("serialNumber")
                    device_param_list["device_name"] = device.get("hostname")
                    device_param_list["reachability_status"] = device.get(
                        "reachabilityStatus"
                    )
                    device_param_list["platform_id"] = device.get("platformId")
                    device_param_list["is_pnp_device"] = False

                    if device_param_list:
                        return device_param_list
                    self.log("Device found but ID or serial number missing", "ERROR")
                else:
                    self.log("Device not found in Cisco Catalyst Center", "ERROR")
            else:
                self.log(
                    "No valid response received from Cisco Catalyst Center", "ERROR"
                )
        except Exception as e:
            self.log(
                "Exception occurred while querying device: {0}".format(str(e)), "ERROR"
            )

        return {}

    def validate_device_replacement_params(self):
        """
        Addtional validation for the faulty and replacemnet device parameters.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): A dictionary containing the faulty and replacement device details.
        Returns:
           The method returns an instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either 'success' or 'failed').
        Description:
            This method validates the configuration parameters for the faulty and replacement devices.
            It checks the device names, IP addresses, and serial numbers for correctness. If validation
            fails, it updates 'self.status' to 'failed' and logs the issues in 'self.msg'. If validation
            succeeds, it sets 'self.status' to 'success'.
        """

        errormsg = []
        config = self.want.get("config", {})

        # Validate device names
        for name_field in ["faulty_device_name", "replacement_device_name"]:
            if config.get(name_field):
                param_spec = dict(type="str", length_max=255)
                validate_str(config[name_field], param_spec, name_field, errormsg)

        # Validate IP addresses
        for ip_field in ["faulty_device_ip_address", "replacement_device_ip_address"]:
            if config.get(ip_field):
                if not self.is_valid_ipv4(config[ip_field]):
                    errormsg.append(
                        "{0}: Invalid IP Address '{1}' in playbook".format(
                            ip_field, config[ip_field]
                        )
                    )

        # Validate serial numbers
        serial_regex = re.compile(r"^[A-Z0-9]{11}$")
        for serial_field in [
            "faulty_device_serial_number",
            "replacement_device_serial_number",
        ]:
            if config.get(serial_field):
                if not serial_regex.match(config[serial_field]):
                    errormsg.append(
                        "{0}: Invalid Serial Number '{1}' in playbook.".format(
                            serial_field, config[serial_field]
                        )
                    )

        if errormsg:
            self.msg = "Invalid parameters in playbook config: '{0}' ".format(
                str("\n".join(errormsg))
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.msg = "Successfully validated config params:{0}".format(
            self.pprint(config)
        )
        self.log(self.msg, "INFO")
        self.status = "success"
        return self

    def device_ready_for_replacement_check(self):
        """
        Checks if the faulty device is ready for replacement.
        Parameters:
            - self (object): An instance of the class that interacts with Cisco Catalyst Center and contains device details.
        Returns:
            bool:
                - True if the faulty device is found and is in the "READY-FOR-REPLACEMENT" state.
                - False if the faulty device is not found or is not in the "READY-FOR-REPLACEMENT" state.
        Description:
            This method retrieves a list of devices marked for replacement from Cisco Catalyst Center
            using the `device_replacement` API. It iterates through the returned devices to find
            the specified faulty device based on its serial number, which is stored in the `self.have` attribute.
            If the faulty device is found and its status is "READY-FOR-REPLACEMENT", the method logs a debug message
            indicating that the device is already marked for replacement and returns `True`.
            If the device is not in the "READY-FOR-REPLACEMENT" state or is not found, it returns `False`.
        """
        response = self.dnac._exec(
            family="device_replacement",
            function="return_replacement_devices_with_details",
        )
        devices = response.get("response", [])
        self.log(
            "Received API response from 'return_replacement_devices_with_details': {0}".format(
                self.pprint(response)
            ),
            "DEBUG",
        )

        for device in devices:
            if device.get("faultyDeviceSerialNumber") == self.have.get(
                "faulty_device_serial_number"
            ):
                if device.get("replacementStatus") == "READY-FOR-REPLACEMENT":
                    self.have["device_replacement_id"] = device.get("id")
                    return True

        return False

    def mark_faulty_device_for_replacement(self):
        """
        Mark the faulty device for replacement in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method marks a faulty device for replacement in Cisco Catalyst Center. It performs the following steps:
            - Checks if the faulty device ID is available.
            - Prepares the payload for the API call.
            - Sends a request to Cisco Catalyst Center to mark the device for replacement.
            - Processes the API response and extracts the task ID.
            - Uses the check_rma_task_status method to monitor the task status.
            - Updates the status, msg, and result attributes based on the task result.
            - Handles any exceptions that occur during the process.
        """
        is_ready_for_replacement = self.device_ready_for_replacement_check()
        if not is_ready_for_replacement:
            import_params = dict(
                payload=[
                    {
                        "faultyDeviceId": self.have.get("faulty_device_id"),
                        "replacementStatus": "MARKED-FOR-REPLACEMENT",
                    }
                ],
            )

            try:
                response = self.dnac._exec(
                    family="device_replacement",
                    function="mark_device_for_replacement",
                    params=import_params,
                )
                self.log(
                    "Received API response from 'mark_device_for_replacement': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )
                task_id = response.get("response", {}).get("taskId")
                task_result = self.check_rma_task_status(
                    task_id,
                    "Device marked for replacement successfully",
                    "Error while marking device for replacement",
                )
                self.status = task_result["status"]
                self.msg = task_result["msg"]
                if self.status == "success":
                    self.result["changed"] = True
                self.device_ready_for_replacement_check()
                return self

            except Exception as e:
                self.status = "failed"
                self.msg = "Exception occurred while marking device for replacement: {0}".format(
                    str(e)
                )
                self.log(self.msg, "ERROR")

        self.log(
            "The device '{0}' is already in the 'READY-FOR-REPLACEMENT' state.".format(
                self.have.get("faulty_device_name")
            ),
            "DEBUG",
        )
        return self

    def get_diff_replaced(self, config):
        """
        Replace a faulty device with a new device in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): Configuration dictionary (not used in this method, but included for consistency).
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method replaces a faulty device with a new device in Cisco Catalyst Center. It performs the following steps:
            - Checks if both faulty and replacement device serial numbers are available.
            - Prepares the payload for the API call.
            - Sends a request to Cisco Catalyst Center to deploy the device replacement workflow.
            - Processes the API response and extracts the task ID.
            - Uses the check_replacement_status method to monitor the replacement status.
            - Uses the check_rma_task_status method to monitor the task status.
            - Updates the status, msg, and result attributes based on the task result.
            - If the replacement fails, it attempts to unmark the faulty device.
            - Handles any exceptions that occur during the process.
        """

        import_params = dict(
            payload={
                "faultyDeviceSerialNumber": self.have.get(
                    "faulty_device_serial_number"
                ),
                "replacementDeviceSerialNumber": self.have.get(
                    "replacement_device_serial_number"
                ),
            }
        )

        self.log(
            "Replacing device with parameters: {0}".format(self.pprint(import_params)),
            "INFO",
        )

        try:
            response = self.dnac._exec(
                family="device_replacement",
                function="deploy_device_replacement_workflow",
                op_modifies=True,
                params=import_params,
            )
            self.log(
                "Received API response from 'deploy_device_replacement_workflow': {0}".format(
                    self.pprint(response)
                ),
                "DEBUG",
            )
            task_id = response.get("response", {}).get("taskId")

            # Monitor the task status using check_rma_task_status
            task_result = self.check_rma_task_status(
                task_id,
                "Device replacement task initiated successfully",
                "Error in device replacement task initiation",
            )
            if task_result["status"] != "success":
                self.status = "failed"
                error_msg = "Device replacement task failed: {0}".format(
                    task_result["msg"]
                )
                self.log(error_msg, "ERROR")
                self.result["msg"] = error_msg
                # Attempt to unmark the device
                self.log("Attempting to unmark the device after failure", "INFO")
                unmark_result = self.unmark_device_for_replacement()
                # Combine both error messages
                self.msg = "{0} | Unmarking result: {1}".format(
                    error_msg, unmark_result.msg
                )
                self.log(self.msg, "ERROR")
                self.result["msg"] = self.msg
                return self

            # If task is initiated successfully, monitor the replacement status
            self.task_id = task_id
            replacement_result = self.monitor_replacement_status()
            self.status = replacement_result["status"]
            self.msg = replacement_result["msg"]
            if self.status != "success":
                self.status = "failed"
                self.result["msg"] = self.msg
                # Attempt to unmark the device
                self.log("Attempting to unmark the device after failure", "INFO")
                unmark_result = self.unmark_device_for_replacement()
                self.msg = "{0} | Unmarking result: {1}".format(
                    self.msg, unmark_result.msg
                )
                self.log(self.msg, "ERROR")
                self.result["msg"] = self.msg
                return self

            self.faulty_device.append(self.have.get("faulty_device_name"))
            self.replacement_device.append(self.have.get("replacement_device_name"))
            self.result["changed"] = True
            self.result["msg"] = self.msg

        except Exception as e:
            self.status = "failed"
            error_msg = "Exception occurred during device replacement "
            self.log(error_msg, "ERROR")
            # Attempt to unmark the device
            self.log("Attempting to unmark the device after exception", "INFO")
            unmark_result = self.unmark_device_for_replacement()
            # Combine both error messages
            self.msg = "{0} | Unmarking result: {1}".format(
                error_msg, unmark_result.msg
            )
            self.log(self.msg, "ERROR")
            self.result["msg"] = self.msg
            self.result["response"] = []

        return self

    def get_diff_deleted(self, config):
        """
        Unmark the faulty device in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks if a device is marked for replacement and unmarks it if necessary:
            - Verifies the device's replacement readiness.
            - If ready, initiates the unmarking process via API and validates the task status.
            - Logs success or error messages based on the operation's outcome.
            - If already unmarked, logs a debug message.
        """
        is_marked_for_replacement = self.device_ready_for_replacement_check()
        faulty_device_name = self.have.get("faulty_device_name")

        if is_marked_for_replacement:
            self.log("Unmarking the faulty device '{0}'...".format(faulty_device_name))
            device_id = self.have.get("device_replacement_id")

            import_params = dict(
                payload=[{"id": device_id, "replacementStatus": "NON-FAULTY"}],
            )

            try:
                response = self.dnac._exec(
                    family="device_replacement",
                    function="unmark_device_for_replacement",
                    op_modifies=True,
                    params=import_params,
                )
                self.log(
                    "Received API response for faulty device '{0}' from 'unmark_device_for_replacement': {1}".format(
                        faulty_device_name, self.pprint(response)
                    ),
                    "DEBUG",
                )
                task_id = response.get("response", {}).get("taskId")
                task_result = self.check_rma_task_status(
                    task_id,
                    "Device unmarked for replacement successfully",
                    "Error while unmarking device for replacement",
                )
                self.faulty_device.append(faulty_device_name)
                self.msg = task_result["msg"]
                self.status = task_result["status"]
                self.log(self.msg, "INFO")
                return self

            except Exception:
                self.status = "failed"
                self.msg = "RMA failed to unmark the faulty device '{0}': No device found for unmarking replacement".format(
                    faulty_device_name
                )
                self.log(self.msg, "ERROR")
            return self

        self.log(
            "The device '{0}' is already in the unmarked state.".format(
                faulty_device_name
            ),
            "DEBUG",
        )
        return self

    def monitor_replacement_status(self):
        """
        Monitor the status of the device replacement task in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            - dict: A dictionary containing the status and message of the replacement task.
        Description:
            This method monitors the status of a device replacement task in Cisco Catalyst Center. It performs the following steps:
            - Initializes retry count and interval for checking task status.
            - Enters a loop to periodically check the task status:
                - Retrieves task details using the get_task_details method.
                - Checks if the task has completed successfully:
                    - If successful, updates result attributes and returns success status.
                - Checks if the task has encountered an error:
                    - If error occurred, updates result attributes and returns failed status.
                - If task is still in progress:
                    - Logs the progress and waits for the retry interval before checking again.
            - If the maximum number of retries is reached without a definitive result:
                - Sets the status to failed and logs a timeout message.
            - Handles various scenarios of task completion, failure, or timeout.
            - Returns a dictionary with the final status and message of the replacement task.
        """

        resync_retry_count = self.params.get("resync_retry_count")
        resync_retry_interval = self.params.get("resync_retry_interval")
        while resync_retry_count:
            task_details = self.get_task_details(self.task_id)
            self.log("Task Details: {0}".format(self.pprint(task_details)), "DEBUG")

            if task_details.get("endTime") is not None:
                if task_details.get("isError") is False:
                    self.result["changed"] = True
                    self.msg = "Device replacement completed successfully: {0}".format(
                        task_details.get("progress")
                    )
                    self.log(self.msg, "INFO")
                    self.result["task_response"] = {
                        "replacement_task_response": task_details,
                        "replacement_status": self.msg,
                    }
                    return {"status": "success", "msg": self.msg}

                self.result["changed"] = False
                self.status = "failed"
                self.msg = "Error in device replacement: {0}".format(
                    task_details.get("progress")
                )
                self.log(self.msg, "ERROR")
                self.result["task_response"] = {
                    "replacement_task_response": task_details,
                    "replacement_status": self.msg,
                }
                return {"status": "failed", "msg": self.msg}

            self.log(
                "RMA workflow in progress: {0}".format(task_details.get("progress")),
                "INFO",
            )
            time.sleep(resync_retry_interval)
            resync_retry_count -= 1

        # If we've exhausted all retries without a definitive result
        self.status = "failed"
        self.msg = "Device replacement monitoring timed out after {0} attempts".format(
            self.params.get("dnac_api_task_timeout")
        )
        self.log(self.msg, "ERROR")
        return {"status": "failed", "msg": self.msg}

    def unmark_device_for_replacement(self):
        """
        Unmark the faulty device for replacement in Cisco Catalyst Center only when replacing of faulty device to replacement device fails.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method unmarks a faulty device for replacement in Cisco Catalyst Center. It performs the following steps:
            - Checks if the faulty device ID is available.
            - Prepares the payload for the API call.
            - Sends a request to Cisco Catalyst Center to unmark the device for replacement.
            - Processes the API response and extracts the task ID.
            - Uses the check_rma_task_status method to monitor the task status.
            - Updates the status, msg, and result attributes based on the task result.
            - Handles any exceptions that occur during the process.
        """
        self.log("Unmarking device for replacement...")
        device_id = self.get_ready_for_replacement_device_id()

        import_params = dict(
            payload=[{"id": device_id, "replacementStatus": "NON-FAULTY"}],
        )

        try:
            response = self.dnac._exec(
                family="device_replacement",
                function="unmark_device_for_replacement",
                op_modifies=True,
                params=import_params,
            )
            self.log(
                "Received API response from 'unmark_device_for_replacement': {0}".format(
                    self.pprint(response)
                ),
                "DEBUG",
            )
            task_id = response.get("response", {}).get("taskId")
            task_result = self.check_rma_task_status(
                task_id,
                "Device unmarked for replacement successfully",
                "Error while unmarking device for replacement",
            )
            self.status = task_result["status"]
            self.msg = "RMA failed to replace the device: {0}".format(
                task_result["msg"]
            )

        except Exception:
            self.status = "failed"
            self.msg = "RMA failed to replace the device: No device found for unmarking replacement"
            self.log(self.msg, "ERROR")
        return self

    def get_ready_for_replacement_device_id(self):
        """
        Retrieves the ID of the first device marked as "READY-FOR-REPLACEMENT" in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            - device_id (str or None): The ID of the first device ready for replacement, or None if no such device is found.
        Description:
            - This method fetches a list of devices with their replacement status from Cisco Catalyst Center.
            - It then checks for the first device with a "READY-FOR-REPLACEMENT" status and returns its ID.
            - The method exits early if such a device is found.
        """
        response = self.dnac._exec(
            family="device_replacement",
            function="return_replacement_devices_with_details",
        )
        devices = response.get("response", [])
        for device in devices:
            if device.get("replacementStatus") == "READY-FOR-REPLACEMENT":
                device_id = device.get("id")
                self.log(
                    "Found ready-for-replacement device with ID: {0}".format(device_id)
                )
                return device_id

        self.log("No devices found with status 'READY-FOR-REPLACEMENT'.")
        return None

    def check_rma_task_status(self, task_id, success_message, error_prefix):
        """
        Check the status of an RMA task in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            task_id (str): The ID of the task to monitor.
            success_message (str): The message to log on successful completion.
            error_prefix (str): The prefix for the error message if the task fails.
        Returns:
            dict: A dictionary containing the status and message of the task result.
        Description:
            This method checks the status of an RMA task in Cisco Catalyst Center. It performs the following steps:
            - Continuously polls the task status using the get_task_details method.
            - Checks if the task has completed successfully or encountered an error.
            - Logs appropriate messages based on the task outcome.
            - Returns a dictionary with the task status and message.
            - Implements a delay between status checks to avoid overwhelming the API.
        """

        ccc_poll_interval = self.params.get("ccc_poll_interval")
        timeout_interval = self.params.get("timeout_interval")
        while timeout_interval > 0:
            task_details = self.get_task_details(task_id)
            self.log(task_details)
            if task_details.get("isError"):
                error_message = task_details.get(
                    "failureReason", "{0}: Task failed.".format(error_prefix)
                )
                self.log(error_message, "ERROR")
                return {"status": "failed", "msg": error_message}

            if "progress" in task_details:
                progress = task_details["progress"].lower()

                if "successful" in progress:
                    self.log(success_message, "INFO")
                    return {"status": "success", "msg": progress}

            time.sleep(ccc_poll_interval)
            timeout_interval -= ccc_poll_interval

    def update_rma_profile_messages(self):
        """
        Updates and logs messages based on the status of RMA device replacements.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): The current instance of the class with updated `result` and `msg` attributes.
        Description:
            This method generates and updates status messages regarding the RMA (Return Material Authorization) device replacement process.
            It checks if there are any faulty and replacement devices specified for replacement. If both are present, it constructs a
            success message detailing the completion of the replacement process for the faulty device(s) with the corresponding replacement device(s).
            If no faulty or replacement devices are found, it sets a message indicating that no replacements were performed.
            The method then updates the `result` attribute with the status of the operation (`changed` set to True if replacements occurred)
            and logs the final message using the appropriate log level. The constructed message is also stored in `result["response"]`
            for further reference.
        """
        self.result["changed"] = False
        result_msg_list = []

        if self.payload.get("state") == "replaced":
            if self.faulty_device and self.replacement_device:
                device_replacement_msg = (
                    "Device replacement was successfully completed for the faulty device(s) '{0}',"
                    " with the replacement device(s) '{1}'.".format(
                        "', '".join(self.faulty_device),
                        "', '".join(self.replacement_device),
                    )
                )
                result_msg_list.append(device_replacement_msg)
        else:
            if self.faulty_device:
                device_replacement_msg = "Unmark successfully completed for the faulty device(s) '{0}'.".format(
                    "', '".join(self.faulty_device)
                )
                result_msg_list.append(device_replacement_msg)

        if result_msg_list:
            self.result["changed"] = True
            self.msg = " ".join(result_msg_list)
        else:
            self.msg = "No changes were made. No RMA device replacement or unmark were performed in Cisco Catalyst Center."

        self.log(self.msg, "INFO")
        self.result["response"] = self.msg

        return self

    def verify_diff_replaced(self, config):
        """
        Verify the device replacement status in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies the replacement status of a device in Cisco Catalyst Center. It performs the following steps:
            - Prepares the payload for the API call using the replacement device serial number.
            - Checks if the replacement device serial number is available.
            - Sends a request to Cisco Catalyst Center to get details of replacement devices.
            - Processes the API response to find the matching device.
            - Logs the replacement status of the matching device, if found.
            - Handles any exceptions that occur during the process.
            - Always returns self to maintain method chaining.
        """

        replacement_device_serial = self.have.get("replacement_device_serial_number")
        if not replacement_device_serial:
            self.log("Replacement device serial number is missing", "WARNING")
            return self

        import_params = {"replacementDeviceSerialNumber": replacement_device_serial}

        try:
            response = self.dnac._exec(
                family="device_replacement",
                function="return_replacement_devices_with_details",
                params=import_params,
            )
            devices = response.get("response", [])
            replacement_status = None
            for device in devices:
                if device.get("id") == self.have.get("device_replacement_id"):
                    replacement_status = device
            self.log(
                "Replacement status: {0}".format(self.pprint(replacement_status)),
                "INFO",
            )
        except Exception as e:
            self.log("Error getting replacement status: {0}".format(str(e)), "ERROR")

        return self

    def verify_diff_deleted(self, config):
        """
        Verify the faulty device unmark in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies whether the difference in the configuration indicates a deleted device. It performs the following steps:
            - Checks if the device is ready for replacement using the `device_ready_for_replacement_check` method.
            - If the device is ready for replacement, it sets the status to "failed," logs an error message, and triggers a return status check.
            - If the device is not ready for replacement, it confirms the faulty device is in an unmarked state, sets the status to "success," and
              logs an informational message.
            - Always returns self to maintain method chaining.
        """
        is_marked_for_replacement = self.device_ready_for_replacement_check()

        if is_marked_for_replacement:
            self.status = "failed"
            self.msg = "The faulty device '{0}' is not in unmarked state.".format(
                self.have.get("faulty_device_name")
            )
            self.log(self.msg, "ERROR")
            self.check_return_status()

        self.msg = "The faulty device '{0}' is in unmarked state.".format(
            self.have.get("faulty_device_name")
        )
        self.status = "success"
        self.log(self.msg, "INFO")
        return self


def main():
    """main entry point for module execution"""
    # Basic Ansible type check and assigning defaults.
    device_replacement_spec = {
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
        "config_verify": {"type": "bool", "default": False},
        "dnac_log_append": {"type": "bool", "default": True},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "resync_retry_count": {"type": "int", "default": 1000},
        "resync_retry_interval": {"type": "int", "default": 30},
        "ccc_poll_interval": {"type": "int", "default": 2},
        "timeout_interval": {"type": "int", "default": 100},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "validate_response_schema": {"type": "bool", "default": True},
        "state": {"default": "replaced", "choices": ["replaced", "deleted"]},
    }
    module = AnsibleModule(
        argument_spec=device_replacement_spec, supports_check_mode=True
    )

    ccc_device_replacement = DeviceReplacement(module)
    state = ccc_device_replacement.params.get("state")

    if (
        ccc_device_replacement.compare_dnac_versions(
            ccc_device_replacement.get_ccc_version(), "2.3.5.3"
        )
        < 0
    ):
        ccc_device_replacement.msg = """The specified version '{0}' does not support the 'rma_workflow_manager' feature.
        Supported versions start from '2.3.5.3' onwards. """.format(
            ccc_device_replacement.get_ccc_version()
        )
        ccc_device_replacement.status = "failed"
        ccc_device_replacement.check_return_status()

    ccc_device_replacement.validate_input().check_return_status()
    config_verify = ccc_device_replacement.params.get("config_verify")

    for config in ccc_device_replacement.validated_config:
        ccc_device_replacement.reset_values()
        ccc_device_replacement.get_want(config).check_return_status()
        ccc_device_replacement.get_have().check_return_status()
        if state == "replaced":
            ccc_device_replacement.rma_device_replacement_pre_check().check_return_status()
            ccc_device_replacement.mark_faulty_device_for_replacement().check_return_status()
            ccc_device_replacement.get_diff_state_apply[state](
                config
            ).check_return_status()
        else:
            ccc_device_replacement.get_diff_state_apply[state](
                config
            ).check_return_status()
        if config_verify:
            ccc_device_replacement.verify_diff_state_apply[state](
                config
            ).check_return_status()

    ccc_device_replacement.update_rma_profile_messages().check_return_status()

    module.exit_json(**ccc_device_replacement.result)


if __name__ == "__main__":
    main()
