#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Ansible module to perform operations on Assurance ICAP (Intelligent Capture) settings in Cisco Catalyst Center.

ICAP allows network administrators to collect and analyze packet captures from network devices to troubleshoot
connectivity and performance issues. This module enables automation of ICAP configurations, making it easier
to manage assurance settings programmatically.
"""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ["Megha Kandari, Madhan Sankaranarayanan"]

DOCUMENTATION = r"""
---
module: assurance_icap_settings_workflow_manager
short_description: Configure and manage ICAP (Intelligent
  Capture) settings in Cisco Catalyst Center for network
  assurance.
description:
  - Automates the configuration and management of Intelligent
    Capture (ICAP) settings in Cisco Catalyst Center.
  - ICAP enables real-time packet capture and analysis
    for troubleshooting client and network device connectivity
    issues.
  - Supports capturing traffic based on parameters such
    as capture type, client MAC, AP, WLC, slots, OTA
    band, and channel.
  - Facilitates automated deployment and validation
    of ICAP configurations.
  - Supports downloading PCAP files for further analysis
    of captured network traffic.
version_added: '6.31.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Megha Kandari (@kandarimegha)
  - Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: Set to 'true' to verify the ICAP configuration
      on Cisco Catalyst Center after deployment.
    type: bool
    default: true
  state:
    description:
      - The state of Cisco Catalyst Center after module
        completion.
    type: str
    choices: ["merged"]
    default: merged
  config:
    description:
      - List of parameters required to configure, create,
        and deploy ICAP settings in Cisco Catalyst Center.
    type: list
    elements: dict
    required: true
    suboptions:
      assurance_icap_settings:
        description:
          - Defines ICAP settings for capturing client
            and network device information.
          - Used for onboarding, monitoring, and troubleshooting
            network connectivity issues.
        type: list
        elements: dict
        suboptions:
          capture_type:
            description: The type of Intelligent Capture
              to be performed (e.g., onboarding).
            type: str
            choices:
              - FULL # Captures complete network traffic for deep analysis.
              - ONBOARDING # Captures packets related to client onboarding processes.
              - OTA # Captures over-the-air (OTA) wireless traffic.
              - RFSTATS # Captures RF statistics to analyze signal and interference levels.
              - ANOMALY # Captures specific anomalies detected in the network.
          duration_in_mins:
            description: The duration of the Intelligent
              Capture session in minutes.
            type: int
          preview_description:
            description: A short summary or metadata
              about the Intelligent Capture session,
              providing details such as purpose, expected
              outcomes, or session context.
            type: str
          client_mac:
            description: The MAC address of the client
              device for which the capture is being
              performed.
            type: str
          wlc_name:
            description: The name of the Wireless LAN
              Controller (WLC) involved in the Intelligent
              Capture.
            type: str
          ap_name:
            description: The name of the Access Point
              (AP) for the capture.
            type: str
          slots:
            description: A list of radio slot numbers on the specified Access Point to include in the capture session. For example, C([0, 1])).
            type: list
            elements: int
          ota_band:
            description:
              - Specifies the wireless frequency band
                for the ICAP capture.
              - Ensure the selected band is valid for
                the region and device capabilities.
            type: str
            choices:
              - 2.4GHz # Supports legacy devices, may have interference.
              - 5GHz # Faster speeds, DFS (Dynamic Frequency Selection) may apply for some channels.
              - 6GHz # Wi-Fi 6E and Wi-Fi 7 only, check regional availability.
          ota_channel:
            description:
              - Wireless channel used for the ICAP capture
                (For example, 36, 40).
              - Available channels depend on the selected
                `ota_band` and regulatory restrictions.
            type: int
          ota_channel_width:
            description:
              - Specifies the channel width in MHz for
                the ICAP capture (For example, 20, 40).
              - Ensure compatibility with the selected
                `ota_band` and regulatory requirements.
            type: int
      assurance_icap_download:
        description:
          - Defines settings for downloading Intelligent
            Capture (ICAP) data.
          - Used to configure the parameters for capturing
            client data during a specific timeframe.
        type: dict
        suboptions:
          capture_type:
            description: The type of ICAP session to
              be executed.
            type: str
            choices:
              - FULL # Captures complete network traffic for deep analysis.
              - ONBOARDING # Captures packets related to client onboarding processes.
              - OTA # Captures over-the-air (OTA) wireless traffic.
              - RFSTATS # Captures RF statistics to analyze signal and interference levels.
              - ANOMALY # Captures specific anomalies detected in the network.
          client_mac:
            description: The MAC address of the client
              device for which the capture is being
              performed.
            type: str
            required: true
          ap_mac:
            description: The Ap mac address of the AP
              for which the capture will be performed
              through.
            type: str
            required: true
          start_time:
            description: The start date and time of the ICAP session in the format 'YYYY-MM-DD HH:MM:SS'.
              (24-hour format, for example, '2025-07-21 17:42:58' for 5:42:58 PM).
            type: str
            required: false
          end_time:
            description: The end date and time of the ICAP session in the format 'YYYY-MM-DD HH:MM:SS'.
              (24-hour format, for example, '2025-07-21 18:07:49' for 6:07:49 PM).
            type: str
            required: false
          file_path:
            description: The file system path where
              the captured data will be saved.
            type: str
            required: true
requirements:
  - dnacentersdk >=  2.8.6
  - python >= 3.9
notes:
  - SDK Method used are
    sensors.AssuranceSettings.get_device_deployment_status,
    sensors.AssuranceSettings.creates_an_icap_configuration_intent_for_preview_approve,
    sensors.AssuranceSettings.discards_the_icap_configuration_intent_by_activity_id
    sensors.AssuranceSettings.deploys_the_i_cap_configuration_intent_by_activity_id
    sensors.AssuranceSettings.lists_i_cap_packet_capture_files_matching_specified_criteria
    sensors.AssuranceSettings.downloads_a_specific_i_cap_packet_capture_file
  - Paths used are
    GET /dna/intent/api/v1/icapSettings/deviceDeployments
    POST /dna/intent/api/icapSettings/configurationModels
    DELETE /dna/intent/api/v1/icapSettings/configurationModels/{previewActivityId}
    POST /dna/intent/api/v1/icapSettings/configurationModels/{previewActivityId}/deploy
    GET /dna/data/api/v1/icap/captureFiles GET /dna/data/api/v1/icap/captureFiles/${id}/download
"""

EXAMPLES = r"""
---
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Configure ICAP on Cisco Catalyst Center
      cisco.dnac.assurance_icap_settings_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: debug
        dnac_log_append: true
        state: merged
        config_verify: true
        config:
          - assurance_icap_settings:
              # Example 1: Standard ONBOARDING capture for a client on a specific WLC
              - capture_type: ONBOARDING
                preview_description: "ICAP onboarding
                  capture"
                duration_in_mins: 30
                client_mac: 50:91:E3:47:AC:9E  # required field
                wlc_name: NY-IAC-EWLC.cisco.local  # required field
              # Example 2: Full packet capture for troubleshooting
              - capture_type: FULL
                preview_description: "Full ICAP capture
                  for troubleshooting"
                duration_in_mins: 30
                client_mac: 50:91:E3:47:AC:9E  # required field
                wlc_name: NY-IAC-EWLC.cisco.local  # required field
              # Example 3: Over-the-Air (OTA) capture for a specific AP radio slot
              - capture_type: OTA
                preview_description: "OTA ICAP capture
                  for troubleshooting"
                duration_in_mins: 30
                client_mac: 04:42:1A:4C:97:F6   # required field
                ap_name: AP1416.9D2A.1D0C  # required field
                wlc_name: SJ-EWLC-1.cisco.local  # required field
                slots: [0]
                ota_band: 5
                ota_channel: 36
                ota_channel_width: 40
              # Example 4: RF statistics capture for a specific AP & WLC
              - capture_type: RFSTATS
                preview_description: "RF statistics capture for troubleshooting"
                client_mac: 04:42:1A:4C:97:F6  # required field
                ap_name: AP1416.9D2A.1D0C  # required field
                wlc_name: SJ-EWLC-1.cisco.local  # required field
                slots: [0]
              # Example 5: Anomaly capture for a specific client
              - capture_type: ANOMALY
                preview_description: "Anomaly capture for troubleshooting"
                client_mac: 04:42:1A:4C:97:F6  # required field
                ap_name: AP1416.9D2A.1D0C  # required field
                wlc_name: SJ-EWLC-1.cisco.local  # required field
                slots: [0]

- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Download ICAP on Cisco Catalyst Center
      cisco.dnac.assurance_icap_settings_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: debug
        dnac_log_append: true
        state: merged
        config_verify: true
        config:
          - assurance_icap_download:
              - capture_type: FULL
                client_mac: 50:91:E3:47:AC:9E
                start_time: "2025-03-05 11:56:00"
                end_time: "2025-03-05 12:01:00"
                file_path: /Users/senorpink/Documents
"""


RETURN = r"""
# Case 1: Successful creation of ICAP settings, deployment of ICAP configuration, and discarding failed tasks.
response_1:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
          "taskId": "string",
           "url": "string"
    },
    "version": "string"
    }
"""


try:
    import pathlib

    HAS_PATHLIB = True
except ImportError:
    HAS_PATHLIB = False
    pathlib = None
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)
from datetime import datetime
import time
import os


class Icap(DnacBase):
    """Class containing member attributes for ICAP setting workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged"]
        self.result["response"] = [
            {
                "assurance_icap_settings": {"response": {}, "msg": {}},
                "assurance_icap_download": {
                    "response": {"msg": {}},
                },
            }
        ]

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.

        Args:
            self: The instance of the class containing the 'config' attribute to be validated.

        Returns:
            The method updates these attributes of the instance:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation ('success' or 'failed').
                - self.validated_config: If successful, a validated version of the 'config' parameter.
        """
        temp_spec = {
            "assurance_icap_settings": {
                "type": "list",
                "elements": "dict",
                "capture_type": {
                    "type": "str",
                    "required": True,
                    "choices": ["FULL", "ONBOARDING", "OTA", "RFSTATS", "ANOMALY"],
                },
                "duration_in_mins": {"type": int, "required": True},
                "client_mac": {"type": "str", "required": True},
                "wlc_name": {"type": "str", "required": False},
                "ap_name": {"type": "str", "required": False},
                "slots": {"type": list, "required": False},
                "ota_band": {
                    "type": "str",
                    "required": False,
                    "choices": ["2.4GHz", "5GHz", "6GHz"],
                },
                "ota_channel": {"type": int, "required": False},
                "ota_channel_width": {"type": int, "required": False},
            },
            "assurance_icap_download": {
                "type": "list",
                "elements": "dict",
                "capture_type": {"type": "str", "required": True},
                "client_mac": {"type": "str", "required": True},
                "ap_mac": {"type": "str", "required": False},
                "start_datetime": {"type": "str", "required": False},
                "end_datetime": {"type": "str", "required": False},
                "file_path": {"type": "str", "required": True},
            },
        }

        if not self.config:
            self.msg = "Validation failed: The 'config' parameter is missing or empty."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            self.msg = "The playbook contains invalid parameters: {0}".format(
                invalid_params
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validate_input': {0}".format(
            str(valid_temp)
        )
        self.log(self.msg, "INFO")

        return self

    def get_want(self, config):
        """
        Retrieve and store Assurance ICAP details from playbook configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing image import and other details.
        Returns:
            self: The current instance of the class with updated 'want' attributes.

        """
        self.log("Starting to retrieve the desired state from the playbook configuration", "DEBUG")
        want = {}
        want["assurance_icap_settings"] = config.get("assurance_icap_settings")
        self.log(f"Extracted assurance_icap_settings: {want['assurance_icap_settings']}", "DEBUG")
        want["assurance_icap_download"] = config.get("assurance_icap_download")
        self.log(f"Extracted assurance_icap_download: {want['assurance_icap_download']}", "DEBUG")
        if not want["assurance_icap_settings"] and not want["assurance_icap_download"]:
            self.msg = "No data provided for ICAP configuration creation."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        valid_capture_types = ["FULL", "ONBOARDING", "OTA", "RFSTATS", "ANOMALY"]

        if want["assurance_icap_settings"]:
            self.log("Processing assurance_icap_settings batches", "DEBUG")
            # Loop through each ICAP settings batch
            for batch in want.get("assurance_icap_settings", []):
                icap_settings_type = str(batch.get("capture_type", "")).upper()
                batch["capture_type"] = icap_settings_type  # Update to uppercase
                self.log(f"Normalized capture_type in assurance_icap_settings batch: {icap_settings_type}", "DEBUG")
                self.log(
                    "Validating capture type '{0}' for ICAP settings batch".format(icap_settings_type),
                    "DEBUG"
                )

                if icap_settings_type not in valid_capture_types:
                    self.msg = (
                        f"Invalid capture type provided in assurance_icap_settings: {icap_settings_type}. "
                        f"Valid options are: {', '.join(valid_capture_types)}."
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

            # Update ota_band value
            for setting in want.get("assurance_icap_settings", []):
                if "ota_band" in setting and isinstance(setting["ota_band"], str):
                    # Remove 'GHz', strip spaces, and convert to float or int
                    band_str = setting["ota_band"].replace("GHz", "").strip()
                    self.log(f"Original ota_band string: '{setting['ota_band']}', cleaned: '{band_str}'", "DEBUG")
                    band_value = float(band_str)
                    # Convert to int if it's a whole number (like 5.0)
                    setting["ota_band"] = int(band_value) if band_value.is_integer() else band_value
                    self.log(f"Converted ota_band value: {setting['ota_band']}", "DEBUG")

        if want["assurance_icap_download"]:
            self.log(
                "Processing {0} ICAP download configurations".format(
                    len(want["assurance_icap_download"])
                ),
                "DEBUG"
            )
            # Normalize and validate assurance_icap_download capture type
            for batch in want.get("assurance_icap_download", []):
                icap_download_type = str(batch.get("capture_type", "")).upper()
                batch["capture_type"] = icap_download_type
                self.log(f"Normalized capture_type in assurance_icap_download batch: {icap_download_type}", "DEBUG")
                self.log(
                    "Validating capture type '{0}' for ICAP download batch".format(icap_download_type),
                    "DEBUG"
                )

                if icap_download_type not in valid_capture_types:
                    self.msg = (
                        f"Invalid capture type provided in assurance_icap_download: {icap_download_type}. "
                        f"Valid options are: {', '.join(valid_capture_types)}."
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

        self.want = want
        self.log("Desired State (want): {0}".format((self.pprint(want))), "INFO")
        self.log(
            "Successfully extracted and validated desired ICAP configuration state",
            "INFO"
        )

        return self

    def get_have(self, config):
        """
        Get the current ICAP-associated information from the Cisco Catalyst Center
        based on the provided playbook details.

        This function processes the playbook configuration to retrieve device IDs for
        Wireless LAN Controllers (WLC) and Access Points (AP) based on their names.
        It logs the progress and any failures encountered while fetching the device IDs.

        Args:
            config (dict): Playbook details containing a list of assurance Intelligent Capture Settings.
                        Each setting includes WLC and AP names that will be used to
                        retrieve the corresponding device IDs.

        Returns:
            self: The current object with updated assurance Intelligent Capture Settings, including
                the retrieved WLC and AP IDs.
        """
        assurance_icap_settings_list = config.get("assurance_icap_settings", [])
        self.log(
            "Assurance Intelligent Capture Settings: {0}".format(
                assurance_icap_settings_list
            ),
            "INFO",
        )

        if not assurance_icap_settings_list:
            self.msg = "No data need to be retrieved for icap config creation "
            return self

        have, errors = [], []

        for assurance_icap_settings in assurance_icap_settings_list:
            # Process WLC Name
            wlc_name = assurance_icap_settings.get("wlc_name")
            if wlc_name:
                self.log("Fetching device ID for WLC: {0}".format(wlc_name), "INFO")
                wlc_id = self.get_device_id(wlc_name)
                if wlc_id:
                    self.log(
                        "Retrieved WLC ID: {0} for WLC Name: {1}".format(
                            wlc_id, wlc_name
                        ),
                        "INFO",
                    )
                    assurance_icap_settings["wlc_id"] = wlc_id
                else:
                    error_msg = "WLC device {0} is not found in catalyst Center or id could not be retrieved.".format(
                        wlc_name
                    )
                    self.log(error_msg, "ERROR")
                    errors.append(error_msg)

            # Process AP Name
            ap_name = assurance_icap_settings.get("ap_name")
            if ap_name:
                self.log("Fetching device ID for AP: {0}".format(ap_name), "INFO")
                ap_id = self.get_device_id(ap_name)
                if ap_id:
                    self.log(
                        "Retrieved AP ID: {0} for AP Name: {1}".format(ap_id, ap_name),
                        "INFO",
                    )
                    assurance_icap_settings["ap_id"] = ap_id
                else:
                    error_msg = "AP ID retrieval failed for '{0}'".format(ap_name)
                    self.log(error_msg, "ERROR")
                    errors.append(error_msg)

            have.append(assurance_icap_settings)

        self.have = have
        self.log("Final have state: {0}".format(self.have), "INFO")

        if errors:
            self.set_operation_result("failed", False, "\n".join(errors), "ERROR")

        return self

    def get_device_id(self, hostname):
        """
        Retrieve the device ID by querying the 'get_device_list' API using the hostname.

        Args:
        self (object): The instance interacting with Cisco Catalyst Center.
        hostname (str): The hostname of the device to retrieve the ID.

        Returns:
        str: The device ID if found, else None.
        """
        self.log("Retrieving device ID for hostname: {0}".format(hostname), "DEBUG")
        try:
            response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                params={"hostname": hostname},  # Using hostname in the API call
            )
            self.log("Received API response for Device List: {0}".format(response), "DEBUG")

            devices = response.get("response", [])
            if not devices:
                self.msg = "No devices found for the hostname '{0}'.".format(hostname)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return None

            # Assuming the device list response contains a list of devices
            device_id = devices[0].get("id")
            if not device_id:
                msg = "Device ID not found for hostname '{0}'.".format(hostname)
                self.log(msg, "ERROR")
                self.set_operation_result("failed", False, msg, "ERROR")
                return None

            self.log(
                "Retrieved device ID '{0}' for hostname '{1}'.".format(
                    device_id, hostname
                ),
                "INFO",
            )
            return device_id

        except Exception as e:
            self.msg = (
                "An error occurred while retrieving device ID for '{0}': {1}".format(
                    hostname, str(e)
                )
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return None

    def get_pcap_ids(self, assurance_icap_download):
        """
        Retrieves a list of ICAP responses matching the specified criteria for each settings dictionary.

        Args:
            assurance_icap_download (dict): Dictionary containing filter parameters.
                - capture_type(str): Capture type (Required).
                - ap_mac (str): AP MAC address (Optional).
                - client_mac (str): Client MAC address (Required).
                - start_time (int): Start time in UNIX epoch (Optional).
                - end_time (int): End time in UNIX epoch (Optional).

        Returns:
            str or None: The first file ID found in the ICAP response if available,
                            or None if no matching file is found or an error occurs

        """
        self.log("Starting to retrieve the data for download", "DEBUG")

        try:
            # Extract parameters
            capture_type = assurance_icap_download.get("capture_type")
            if not capture_type:
                msg = (
                    "'capture_type' is a required parameter because it is essential for retrieving the correct pcap file "
                    "associated with a specific capture type (e.g., ONBOARDING, FULL, OTA, RFSTATS, ANOMALY). "
                    "Please provide one of the valid options."
                )
                self.log(msg, "ERROR")
                self.set_operation_result("failed", False, msg, "ERROR")
                return None

            # Check ap_mac requirement for certain capture types
            ap_mac = assurance_icap_download.get("ap_mac")
            if capture_type in ["OTA", "ANOMALY"] and ap_mac is None:
                msg = "'ap_mac' is required for capture types 'OTA' and 'ANOMALY'."
                self.log(msg, "ERROR")
                self.set_operation_result("failed", False, msg, "ERROR")
                return None

            # Build request params
            param = {"type": capture_type}

            client_mac = assurance_icap_download.get("client_mac")
            if client_mac:
                param["clientMac"] = client_mac

            if ap_mac:
                param["apMac"] = ap_mac

            # Handle time filtering if both are provided
            start_time = assurance_icap_download.get("start_time")
            end_time = assurance_icap_download.get("end_time")
            if start_time is not None or end_time is not None:
                errormsg = []
                validated_start, validated_end = self.validate_start_end_datetime(
                    start_time, end_time, errormsg
                )
                self.log("Start Time (Epoch): {0}".format(validated_start), "DEBUG")
                self.log("End Time (Epoch): {0}".format(validated_end), "DEBUG")
                if validated_start:
                    param["startTime"] = validated_start
                if validated_end:
                    param["endTime"] = validated_end

                if errormsg:
                    self.msg = errormsg
                    self.log(self.msg, "ERROR")
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return None

            # Log the parameters used for retrieving the PCAP file ID
            self.log(
                "Parameters for retrieving PCAP file ID: {0}".format(param), "DEBUG"
            )

            # Execute API call
            response = self.dnac._exec(
                family="sensors",
                function="lists_i_cap_packet_capture_files_matching_specified_criteria",
                params=param,
            )
            self.log("Received API response for ICAP Packet Capture: {0}".format(response), "DEBUG")

            # Check if response is an empty list
            if isinstance(response, list) and not response:
                failure_reason = "Empty response received for ICAP parameters: {0}".format(param)
                self.msg = "ICAP capture download failed: {0}".format(failure_reason)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                self.log(self.msg, "ERROR")
                return None

            # Extract response dictionary
            response_data = response.get("response", [])
            if not response_data:
                failure_reason = "No ICAP packet capture files found for parameters: {0}".format(param)
                self.msg = "ICAP capture download failed: {0}".format(failure_reason)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                self.log(self.msg, "ERROR")
                return None

            # Extract the first file ID
            file_id = response_data[0].get("id")
            if not file_id:
                failure_reason = "ICAP packet capture file ID missing in response."
                self.msg = "ICAP capture download failed: {0}".format(failure_reason)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                self.log(self.msg, "ERROR")
                return None

            self.log("Extracted ICAP file ID: {0}".format(file_id), "INFO")
            return file_id

        except Exception as e:
            failure_reason = "An error occurred while retrieving ICAP packet capture files: {0}".format(str(e))
            self.msg = "ICAP capture download failed: {0}".format(failure_reason)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            self.log(self.msg, "ERROR")
            return None

    def validate_start_end_datetime(self, start_time=None, end_time=None, errormsg=None):
        """
        Validate and convert input datetimes into Unix epoch milliseconds.

        Args:
            start_time (str): The start datetime string in "%Y-%m-%d %H:%M:%S" format.
            end_time (str): The end datetime string in "%Y-%m-%d %H:%M:%S" format.
            errormsg (list): A list to store error messages if validation fails.

        Returns:
            tuple: (start_epoch_ms, end_epoch_ms) if valid, otherwise (None, None).
        """
        self.log(
            "Validating start and end datetime: start='{0}', end='{1}'".format(
                start_time, end_time
            ),
            "DEBUG",
        )
        date_format = "%Y-%m-%d %H:%M:%S"

        try:
            start_datetime, end_datetime = None, None
            if start_time:
                start_datetime = datetime.strptime(start_time, date_format)
            if end_time:
                end_datetime = datetime.strptime(end_time, date_format)
            self.log("Parsed start datetime: {0}, end datetime: {1}".format(start_datetime, end_datetime), "DEBUG")

            if start_datetime and end_datetime and start_datetime > end_datetime:
                msg = "Start datetime '{0}' must be before end datetime '{1}'.".format(start_time, end_time)
                errormsg.append(msg)
                self.log(msg, "ERROR")
                return None, None

            start_epoch_ms, end_epoch_ms = None, None
            # Convert to epoch milliseconds
            if start_datetime:
                start_epoch_ms = int(start_datetime.timestamp() * 1000)
            if end_datetime:
                end_epoch_ms = int(end_datetime.timestamp() * 1000)

            self.log("Datetime validation successful. Start: {0}, End: {1}".format(start_epoch_ms, end_epoch_ms), "INFO")
            return start_epoch_ms, end_epoch_ms

        except ValueError as e:
            msg = "Invalid datetime format. Expected '{0}'. Error: {1}".format(
                date_format, e
            )
            errormsg.append(msg)
            self.log(msg, "ERROR")
            return None, None

        except Exception as e:
            msg = "Unexpected error during datetime validation: {0}".format(e)
            errormsg.append(msg)
            self.log(msg, "ERROR")
            return None, None

    def get_diff_merged(self, config):
        """
        Create Assurance Intelligent Capture Configurations in Cisco Catalyst Center based on the playbook details

        Args:
        config (dict): Dictionary containing playbook keys:
            - assurance_icap_settings (list of dict): ICAP configuration details.
            - assurance_icap_download (dict): ICAP download filter parameters.

        Returns:
            self: The current object with updated ICAP configuration or download state.
        """
        self.log("Processing Assurance ICAP configurations", "DEBUG")

        assurance_icap_settings = config.get("assurance_icap_settings")
        if assurance_icap_settings is not None:
            self.log(
                "Creating ICAP configurations: {0}".format(assurance_icap_settings),
                "INFO",
            )
            self.create_icap(assurance_icap_settings)
        else:
            self.log("No ICAP settings provided in the playbook", "DEBUG")

        assurance_icap_download = config.get("assurance_icap_download")
        if assurance_icap_download:
            if assurance_icap_settings:
                # Extract max duration across all capture jobs
                sleep_duration = max(
                    [
                        item.get("duration_in_mins", 0)
                        for item in assurance_icap_settings
                    ]
                )
                self.log(
                    "Waiting for ICAP capture to complete before downloading... Duration: {0} minutes".format(
                        sleep_duration
                    ),
                    "INFO",
                )
                time.sleep(sleep_duration * 60)  # Convert to seconds
            self.log(
                "Downloading ICAP configurations: {0}".format(assurance_icap_download),
                "INFO",
            )
            self.download_icap_packet_traces(assurance_icap_download)
        else:
            self.log("No ICAP download details provided in the playbook", "DEBUG")

        return self

    def download_icap_packet_traces(self, assurance_icap_download):
        """
        Downloads ICAP packet capture files using the provided list of elements.

        Args:
            assurance_icap_download (list): List of elements used to fetch ICAP packet capture file IDs.

        Returns:
            list: List of responses containing downloaded file details or error messages.
        """
        responses = []
        self.log("Starting the ICAP packet capture download process.", "DEBUG")

        try:
            for icap_element in assurance_icap_download:
                self.log("Processing element: {0}".format(icap_element), "DEBUG")
                download_id = self.get_pcap_ids(icap_element)

                if not download_id:
                    self.log(
                        "No ICAP ID found for element: {0}".format(icap_element),
                        "WARNING",
                    )
                    responses.append(
                        {
                            "element": icap_element,
                            "status": "failed",
                            "error": "ICAP ID not found",
                        }
                    )
                    continue

                self.log("Fetching ICAP packet capture for ID: {0}".format(download_id))
                response = self.dnac._exec(
                    family="sensors",
                    function="downloads_a_specific_i_cap_packet_capture_file",
                    op_modifies=True,
                    params={"id": download_id},
                )
                response = response.data
                self.log(
                    "Received API response for ICAP ID {0}: {1}".format(download_id, response)
                )

                # If response contains binary data, save it as a .pcap file
                if response and isinstance(response, bytes):
                    file_path = icap_element.get("file_path")
                    if file_path:
                        full_path = os.path.join(file_path, download_id)
                        self.save_pcap_file(full_path, response)
                        responses.append(
                            {
                                "icap_id": download_id,
                                "status": "success",
                                "file_path": full_path,
                            }
                        )
                    else:
                        self.log(
                            "No valid file path provided for ICAP ID: {0}".format(
                                download_id
                            ),
                            "ERROR",
                        )
                        msg = "No valid file path provided for ICAP ID: {0}".format(
                            download_id
                        )
                        self.msg = msg
                        self.set_operation_result("failed", False, msg, "ERROR")
                        responses.append(
                            {
                                "icap_id": download_id,
                                "status": "failed",
                                "error": "No valid file path",
                            }
                        )
                else:
                    self.log(
                        "Invalid or empty response for ICAP ID: {0}".format(download_id),
                        "ERROR",
                    )
                    responses.append(
                        {
                            "icap_id": download_id,
                            "status": "failed",
                            "error": "Empty or invalid response",
                        }
                    )

        except Exception as e:
            error_msg = "Failed to download ICAP packet traces: {0}".format(str(e))
            self.log({"error": error_msg}, "ERROR")
            self.msg = error_msg
            self.set_operation_result("failed", False, self.msg, "ERROR")
            responses.append({"status": "failed", "error": str(e)})

        return responses

    def save_pcap_file(self, file_path, data):
        """
        Saves the binary data as a .pcap file.

        Args:
            file_path (str): The file path where the .pcap file should be saved.
            data (bytes): The binary packet capture data.

        Returns:
            None
        """
        try:
            # Ensure the target directory exists
            directory = os.path.dirname(file_path)
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                self.log("Directory created: {0}".format(directory), "DEBUG")

            # Write the binary data to the .pcap file
            with open(file_path, "wb") as pcap_file:
                pcap_file.write(data)

            self.msg = "Successfully saved ICAP packet capture file at: {0}".format(
                file_path
            )
            self.log(self.msg, "INFO")
            self.status = "success"
            self.result["changed"] = True
            self.result["response"][0]["assurance_icap_download"]["response"][
                "msg"
            ] = self.msg

        except OSError as e:
            error_msg = "Failed to create directory for ICAP file at {0}: {1}".format(
                directory, str(e)
            )
            self.log(error_msg, "ERROR")
            self.status = "failed"
            self.result["changed"] = False
            self.result["response"][0]["assurance_icap_download"]["response"][
                "msg"
            ] = error_msg

        except Exception as e:
            error_msg = "Failed to save ICAP file at {0}: {1}".format(file_path, str(e))
            self.log(error_msg, "ERROR")
            self.status = "failed"
            self.result["changed"] = False
            self.result["response"][0]["assurance_icap_download"]["response"][
                "msg"
            ] = error_msg

    def deploy_icap_config(self, preview_activity_id, preview_description):
        """
        Deploy an Intelligent Capture Configuration intent in Cisco Catalyst Center.

        This method deploys the specified Intelligent Capture Configuration based on the provided details and
        preview activity ID. It handles task creation, monitors task status, and logs success or failure.

        Args:
            preview_activity_id (str): Preview activity ID.
            preview_description (str): Description of the ICAP deployment.

        Returns:
            self: The current object with operation result and status message.
        """
        self.log(
            "Starting deployment of ICAP configuration: {0}".format(
                preview_activity_id
            ),
            "INFO",
        )
        try:
            self.log(
                "Requested payload for deploying {0}".format(preview_activity_id),
                "DEBUG",
            )
            task_name = "deploys_the_i_cap_configuration_intent_by_activity_id"
            response = self.dnac._exec(
                family="sensors",
                function="deploys_the_i_cap_configuration_intent_by_activity_id",
                op_modifies=True,
                params={"preview_activity_id": preview_activity_id, "object": {}},
            )
            response = response.get("response")
            task_id = response.get("taskId")
            self.log(
                "Received API response for deploy icap config as: {0}".format(response),
                "INFO",
            )
            if not task_id:
                self.msg = "Failed to retrieve task ID for ICAP deployment."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            task_details = self.get_task_details(task_id)
            preview_activity_id = task_id
            if task_details.get("isError"):
                failure_reason = task_details.get("failureReason", "Unknown error")
                self.msg = "ICAP configuration deployment failed: {0}".format(
                    failure_reason
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                self.log(self.msg, "ERROR")
                return self

            self.log(
                "Successfully deployed ICAP configuration: {0}".format(
                    preview_description
                ),
                "INFO",
            )
            self.want["want_deployment_task_id"] = task_id  # Store task ID
            return self

        except Exception as e:
            self.msg = "An exception occurred while deploying ICAP config '{0}' in Cisco Catalyst Center: {1}".format(
                preview_description, str(e)
            )
            self.log(
                "Attempting to delete ICAP config due to deployment failure.", "WARNING"
            )
            try:
                self.delete_icap_config(
                    preview_activity_id, preview_description
                ).check_return_status()
            except Exception as e:
                self.log("exception for deployment {0}".format(str(e)), "DEBUG")
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def update_keys(self, data, mapping):
        """
        Update dictionary keys in a list of dictionaries based on a given mapping.

        This function iterates over a list of dictionaries and replaces keys according
        to the provided mapping dictionary. If a key exists in the mapping, it is
        replaced with the corresponding value; otherwise, it remains unchanged.

        Args:
        data (list of dict): A list of dictionaries whose keys need to be updated.
        mapping (dict): A dictionary defining key replacements, where each key
                        represents the original key and the value is the new key.

        Returns:
        list of dict: A list of dictionaries with updated keys.
        """
        if not data:
            self.log("No data provided for key update.", "DEBUG")
            return []

        self.log("Updating dictionary keys based on mapping.", "DEBUG")
        return [{mapping.get(k, k): v for k, v in item.items()} for item in data]

    def get_icap_configuration_status_per_network_device(self, preview_activity_id, preview_description):
        """
        Retrieves the status of an Intelligent Capture (ICAP) configuration per network device.

        Args:
            preview_activity_id (str): The unique identifier for the preview activity.
            preview_description (str): A description of the ICAP configuration being previewed.

        Returns:
            network_device_id (str): The network device ID associated with the ICAP configuration.
        """
        self.log(
            "Polling ICAP configuration status for activity '{0}' with description '{1}' until network device ID is available".format(
                preview_activity_id, preview_description
            ),
            "DEBUG"
        )

        start_time = time.time()
        retry_interval = int(self.payload.get("dnac_task_poll_interval", 5))
        resync_retry_count = int(self.payload.get("dnac_api_task_timeout", 100))
        retry_count = 0

        while True:
            retry_count += 1
            self.log(
                "Attempt {0} to get ICAP configuration status and network device ID for preview activity ID: {1}".format(
                    retry_count, preview_activity_id
                ),
                "DEBUG"
            )
            try:
                icap_configuration_status_per_network_device = self.dnac._exec(
                    family="sensors",
                    function="get_i_cap_configuration_status_per_network_device",
                    params={"preview_activity_id": preview_activity_id}
                )

                self.log("Received API response for ICAP configuration status: {0}".format(icap_configuration_status_per_network_device), "DEBUG")

                # Validate response
                if not icap_configuration_status_per_network_device or not isinstance(icap_configuration_status_per_network_device, dict):
                    self.msg = "Invalid response received for preview activity ID: {0}".format(preview_activity_id)
                    self.delete_icap_config(preview_activity_id, preview_description)
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    return None

                response = icap_configuration_status_per_network_device.get("response", [])
                response = response[0] if response else {}
                self.log("Parsed ICAP configuration status response: {0}".format(response), "DEBUG")

                network_device_id = response.get("networkDeviceId")
                status = response.get("status")

                if network_device_id and status == "Not Started":
                    self.log(
                        "ICAP configuration status is 'Not Started' - returning network device ID: {0}".format(network_device_id),
                        "INFO"
                    )
                    return network_device_id
                elif network_device_id:
                    self.log(
                        "Network device ID found but status is '{0}' - continuing to poll".format(status),
                        "DEBUG"
                    )
                else:
                    self.log(
                        "No network device ID found in response - continuing to poll",
                        "DEBUG"
                    )

                self.msg = "No network device ID found for preview activity ID: {0}".format(preview_activity_id)
                self.delete_icap_config(preview_activity_id, preview_description)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            except Exception as e:
                self.msg = "Error retrieving ICAP configuration status: {0}".format(str(e))
                self.log(self.msg, "ERROR")

            # Check if timeout has been reached
            elapsed_time = time.time() - start_time
            if elapsed_time >= resync_retry_count:
                self.msg = f"Max retries reached ({resync_retry_count} seconds) while retrieving ICAP configuration\
                            status for activity ID: {preview_activity_id}"
                self.log(self.msg, "ERROR")
                self.delete_icap_config(preview_activity_id, preview_description)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            # Log before sleeping and retry
            self.log("Waiting for {0} seconds before retrying ICAP configuration status for activity ID: {1}"
                     .format(retry_interval, preview_activity_id), "DEBUG")
            time.sleep(retry_interval)

    def generate_device_cli_of_icap_config(self, preview_activity_id, network_device_id, preview_description):
        """
        Generates CLI commands for the Intelligent Capture Configuration based on the preview activity ID and network device ID.

        Args:
            preview_activity_id (str): The unique identifier for the preview activity.
            network_device_id (str): The unique identifier for the network device.
            preview_description (str): A description of the ICAP configuration being previewed.

        Returns:
            self: The current object with operation result and status message.
        """
        self.log(
            "Generating CLI commands for ICAP configuration with preview activity ID: {0}, network device ID: {1}, and description: {2}".format(
                preview_activity_id, network_device_id, preview_description
            ),
            "INFO"
        )

        retry_interval = int(self.payload.get("dnac_task_poll_interval", 5))
        timeout = int(self.payload.get("dnac_api_task_timeout", 100))
        start_time = time.time()
        retry_count = 0

        devices_clis_of_the_icap_configuration = {}

        # Polling loop until we get a valid response or timeout
        while True:
            retry_count += 1
            self.log(
                "Attempt {0} to generate CLI commands for preview activity ID: {1}".format(
                    retry_count, preview_activity_id
                ),
                "DEBUG"
            )
            try:
                devices_clis_of_the_icap_configuration = self.dnac._exec(
                    family="sensors",
                    function="generates_the_devices_clis_of_the_i_cap_configuration_intent",
                    params={
                        "preview_activity_id": preview_activity_id,
                        "network_device_id": network_device_id
                    }
                )

                self.log(
                    "Received API Response from CLI generation: {0}".format(devices_clis_of_the_icap_configuration),
                    "DEBUG"
                )

                # Check if valid response is received
                if devices_clis_of_the_icap_configuration and isinstance(devices_clis_of_the_icap_configuration, dict):
                    if isinstance(devices_clis_of_the_icap_configuration, dict):
                        response = devices_clis_of_the_icap_configuration.get("response", {})
                        if response:
                            self.log(
                                f"Successfully received a non-empty 'response' object from CLI generation API. Response: {response}",
                                "INFO"
                            )
                            break  # Exit polling loop if a valid response is found
                        else:
                            self.log(
                                "API response received but 'response' key is empty or missing. Retrying...",
                                "DEBUG"
                            )
                    else:
                        self.log(
                            f"API response is not a dictionary. Received: {type(devices_clis_of_the_icap_configuration)}. Retrying...",
                            "DEBUG"
                        )

            except Exception as e:
                self.msg = "Error while calling API to generate CLI commands: {0}".format(str(e))
                self.log(self.msg, "ERROR")

            # Check if timeout has been reached
            if time.time() - start_time >= timeout:
                self.msg = "Max retries reached while generating CLI commands for preview activity ID: {0}".format(
                    preview_activity_id
                )
                self.log(self.msg, "ERROR")
                self.delete_icap_config(preview_activity_id, preview_description)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                return self

            # Wait before retry
            self.log("No valid response yet, retrying in {0} seconds...".format(retry_interval), "DEBUG")
            time.sleep(retry_interval)

        self.log(
            "Processing CLI generation response to extract task ID",
            "DEBUG"
        )

        # After loop, process the final response
        response = devices_clis_of_the_icap_configuration.get("response", {})
        task_id = response.get("taskId")

        if not task_id:
            self.msg = "Failed to retrieve task ID for ICAP deployment."
            self.log(
                "Initiating cleanup due to task failure - deleting ICAP configuration",
                "WARNING"
            )
            self.delete_icap_config(preview_activity_id, preview_description)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            self.log(self.msg, "ERROR")
            return self

        self.log(
            "Retrieved task ID '{0}' for CLI generation - validating task details".format(task_id),
            "INFO"
        )

        # Validate task details
        task_details = self.get_task_details(task_id)
        if task_details.get("isError"):
            failure_reason = task_details.get("failureReason", "Unknown error")
            self.msg = "ICAP configuration deployment failed: {0}".format(failure_reason)
            self.log(
                "Initiating cleanup due to task failure - deleting ICAP configuration",
                "WARNING"
            )
            self.delete_icap_config(preview_activity_id, preview_description)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            self.log(self.msg, "ERROR")
            return self

        self.log(
            "CLI command generation completed successfully for preview activity ID '{0}' and network device ID '{1}'".format(
                preview_activity_id, network_device_id
            ),
            "INFO"
        )
        return self

    def retrieves_the_devices_clis_of_the_icap(self, preview_activity_id, network_device_id, preview_description):
        """
        Retrieves the CLI commands that will be applied to the device for the specified ICAP configuration.

        Args:
            preview_activity_id (str): The unique identifier for the preview activity.
            network_device_id (str): The unique identifier for the network device.
            preview_description (str): A description of the ICAP configuration being previewed.

        Returns:
            device_clis_of_icap (dict): A dictionary containing the CLI commands for the specified ICAP configuration.

        Raises:
            Calls self.set_operation_result() and exits on API errors or invalid responses.

        Description:
            Calls the 'retrieves_the_devices_clis_of_the_i_capintent' API to fetch CLI commands
            for a specific ICAP configuration. Validates the response format and handles errors
            by calling cleanup methods and setting appropriate operation results.
        """
        # Implementation to retrieve CLI commands
        try:
            self.log("Retrieving CLI commands for preview activity ID: {0} and network device ID: {1}".format(preview_activity_id, network_device_id), "DEBUG")
            response = self.dnac._exec(
                family="sensors",
                function="retrieves_the_devices_clis_of_the_i_capintent",
                params={
                    "preview_activity_id": preview_activity_id,
                    "network_device_id": network_device_id
                }
            )
            self.log("Received API response for CLI retrieval: {0}".format(response), "DEBUG")
            if response is None or not isinstance(response, dict):
                self.msg = "Invalid or unexpected API response received for CLI retrieval for preview activity ID: {0}".format(preview_activity_id)
                self.log("calling delete_icap_config due to invalid response in retrieves_the_devices_clis_of_the_i_capintent ", "DEBUG")
                self.delete_icap_config(preview_activity_id, preview_description)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            device_clis_of_icap = response.get("response")
            if device_clis_of_icap is None:
                self.msg = (
                    f"No 'response' key found or its value is None in the API response for CLI retrieval for preview activity ID: "
                    f"{preview_activity_id}. This might indicate no CLIs were generated or an API issue."
                )
                self.log(
                    f"Calling delete_icap_config due to missing 'response' data in 'retrieves_the_devices_clis_of_the_i_capintent_v1'"
                    f" for preview activity ID: {preview_activity_id}.",
                    "ERROR"
                )
                self.delete_icap_config(preview_activity_id, preview_description)
                self.set_operation_result("failed", False, self.msg, "WARNING").check_return_status()

            self.log("Retrieved device CLI's: {0}".format(device_clis_of_icap), "DEBUG")
        except Exception as e:
            self.msg = "An error occurred while retrieving device CLI's: {0}".format(str(e))
            self.log("calling delete_icap_config due to exception in retrieves_the_devices_clis_of_the_i_capintent ", "DEBUG")
            self.delete_icap_config(preview_activity_id, preview_description)
            self.log(self.msg, "ERROR")
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        return device_clis_of_icap

    def existing_icap_configuration(self, icap):
        """
        Checks if an ICAP configuration with the same parameters is already in progress.

        Args:
            icap (dict): A dictionary containing the ICAP configuration details.

        Returns:
            None: If no existing configuration is found, otherwise raises an error.
        """
        try:
            capture_type = icap.get("capture_type")
            client_mac = icap.get("client_mac")
            ap_id = icap.get("ap_id", None)
            ap_name = icap.get("ap_name", None)
            wlc_id = icap.get("wlc_id")
            param = {
                'capture_status': "INPROGRESS",
                'captureType': capture_type,
                'clientMac': client_mac,
                'wlcId': wlc_id
            }
            if capture_type == "OTA":
                is_site_assigned_to_ap = self.is_ap_assigned_to_site(ap_id, ap_name)
                if ap_id and is_site_assigned_to_ap:
                    param['apId'] = ap_id
                    param['apName'] = ap_name
                else:
                    self.msg = "Provided AP '{0}' is not assigned to a site".format(ap_name)
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            self.log(
                "Checking for existing ICAP configurations with parameters: capture_type='{0}', client_mac='{1}', wlc_id='{2}', ap_id='{3}'".format(
                    capture_type,
                    client_mac,
                    wlc_id,
                    ap_id
                ),
                "DEBUG"
            )
            if ap_id:
                param['apId'] = ap_id
                self.log(
                    "Including AP ID '{0}' in the search parameters".format(ap_id),
                    "DEBUG"
                )

            # Check if an ICAP configuration with the same parameters is already in progress
            existing_config = self.dnac._exec(
                family="sensors",
                function="retrieves_deployed_i_cap_configurations_while_supporting_basic_filtering",
                params=param
            )
            self.log("Received API response for Existing ICAP configurations: {0}".format(existing_config), "DEBUG")
            if existing_config and existing_config.get("response"):
                self.msg = "An ICAP configuration {0} with capture type '{1}' is already in progress.".format(icap, capture_type)
                self.log(self.msg, "ERROR")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            else:
                self.log(
                    "No existing ICAP configuration found with the same parameters - validation passed",
                    "INFO"
                )
        except Exception as e:
            self.msg = "An error occurred while checking existing ICAP configurations: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
        return None

    def valid_client_mac(self, client_mac, wlc_name):
        """
        Validates whether a given client MAC address is present on a specified
        Wireless LAN Controller (WLC) in Cisco Catalyst Center.

        This method queries the clients API to confirm if the specified MAC address
        is currently connected to or registered on the target WLC.

        Args:
            client_mac (str): The MAC address of the wireless client to validate.
            wlc_name (str): The name of the Wireless LAN Controller (WLC) to check.

        Returns:
            bool: True if the client MAC is found on the specified WLC,
                False otherwise.
        """

        try:
            self.log("Validating existence of client MAC '{0}' on WLC '{1}'".format(client_mac, wlc_name), "DEBUG")

            params = {
                "macAddress": client_mac
            }

            response = self.dnac._exec(
                family="clients",
                function="retrieves_the_list_of_clients_while_also_offering_basic_filtering_and_sorting_capabilities",
                params=params
            )
            self.log("Received API response for client MAC validation: {0}".format(response), "DEBUG")

            if response and isinstance(response, dict):
                clients = response.get("response", [])
                if clients:
                    self.log("Client MAC '{0}' found".format(client_mac), "DEBUG")
                    return True

            self.log("Client MAC '{0}' not found".format(client_mac), "WARNING")
            return False

        except Exception as e:
            self.log("Exception while checking client MAC '{0}': {1}".format(client_mac, str(e)), "ERROR")
            return False

    def is_ap_assigned_to_site(self, ap_id, ap_name):
        """
        Checks whether a given Access Point (AP) is assigned to a site using
        the 'Get site assigned network device' API in Cisco Catalyst Center.

        Args:
            ap_id (str): Device ID of the Access Point.
            ap_name (str): Hostname of the Access Point.

        Returns:
            bool:
                - (True, site_info) if the AP is assigned to a site.
                - (False, message) if the AP is not assigned to any site or an error occurs.
        """

        try:
            self.log("Verifying site assignment for AP '{0}' (ID: {1}).".format(ap_name, ap_id), "DEBUG")

            response = self.dnac._exec(
                family="site_design",
                function="get_site_assigned_network_device",
                params={"id": ap_id}
            )
            self.log("Received API response for site assignment: {0}".format(response), "DEBUG")

            if not response or not response.get("response"):
                msg = "AP '{0}' is not assigned to any site".format(ap_name)
                self.log(msg, "WARNING")
                return False

            site_info = response["response"]

            if not site_info.get("siteId"):
                msg = "AP '{0}' is not assigned to any site".format(ap_name)
                self.log(msg, "WARNING")
                return False

            self.log(
                "AP '{0}' is assigned to site '{1}' (Site ID: {2})".format(
                    ap_name,
                    site_info.get("siteNameHierarchy"),
                    site_info["siteId"]
                ),
                "DEBUG"
            )
            return True

        except Exception as e:
            msg = "Exception while checking site assignment for AP '{0}': {1}".format(ap_name, str(e))
            self.log(msg, "ERROR")
            return False, msg

    def create_icap(self, assurance_icap_details):
        """
        Creates Intelligent Capture Configuration in the Cisco Catalyst Center, monitors its task status, and takes appropriate actions
        based on the result of the task. If the task fails, a cleanup function is called to delete the configuration.
        If the task succeeds, the next step in the workflow is executed.

        Args:
            assurance_icap_details (list): A list of dictionaries containing the details for Intelligent Capture Configuration.

        Returns:
            self: Returns the instance of the class with updated `status` and `msg` attributes.
        """

        self.log(
            "Starting ICAP configuration creation with details: {0}".format(
                assurance_icap_details
            ),
            "INFO",
        )
        result_icap_settings = self.result.get("response")[0].get(
            "assurance_icap_settings"
        )

        for icap in assurance_icap_details:
            capture_type = icap.get("capture_type")
            if capture_type is None:
                self.msg = "Missing required parameter 'capture_type' in assurance_icap_settings"
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            client_mac = icap.get("client_mac")
            wlc_name = icap.get("wlc_name")

            if not self.valid_client_mac(client_mac, wlc_name):
                self.msg = "Wireless Client MAC address '{0}' not found.".format(client_mac)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            # check if the icap with same config is already is in progress
            self.existing_icap_configuration(icap)

        preview_description = assurance_icap_details[0].get("preview_description")
        key_mapping = {
            "capture_type": "captureType",
            "preview_description": "previewDescription",
            "duration_in_mins": "durationInMins",
            "client_mac": "clientMac",
            "wlc_id": "wlcId",
            "ap_id": "apId",
            "ota_channel": "otaChannel",
            "ota_band": "otaBand",
            "ota_channel_width": "otaChannelWidth",
        }

        # Update keys in assurance_icap_details
        updated_assurance_icap_details = self.update_keys(
            assurance_icap_details, key_mapping
        )
        keys_to_delete = ["previewDescription", "wlc_name", "ap_name"]

        # Iterate through each dictionary in the list and pop the specified keys
        for item in updated_assurance_icap_details:
            for key in keys_to_delete:
                item.pop(key, None)

        preview_description = assurance_icap_details[0].get("preview_description")
        preview_activity_id = None

        try:
            task_name = "creates_an_i_cap_configuration_intent_for_preview_approve"
            param = {"previewDescription": preview_description, "payload": updated_assurance_icap_details}
            self.log("Creating Intelligent Capture Configuration with the following parameters: {0}.".format(self.pprint(param)))

            response = self.dnac._exec(
                family="sensors",
                function="creates_an_i_cap_configuration_intent_for_preview_approve",
                op_modifies=True,
                params=param,
            )
            self.log(
                "Received API response for create icap config as: {0}".format(response),
                "INFO",
            )
            response = response.get("response")
            task_id = response.get("taskId")
            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")

            task_details = self.get_task_details(task_id)
            preview_activity_id = task_id
            if task_details.get("isError") is True:
                failure_reason = task_details.get("failureReason")
                self.msg = "ICAP configuration creation failed: {0}".format(
                    failure_reason
                )
                self.set_operation_result("failed", False, failure_reason, "ERROR")
                return self

            self.log(f"Attempting to retrieve network device ID for preview activity ID: {preview_activity_id}.", "INFO")
            network_device_id = self.get_icap_configuration_status_per_network_device(preview_activity_id, preview_description)
            if not network_device_id:
                self.msg = "Failed to retrieve network device ID for ICAP configuration."
                self.log(self.msg, "ERROR")
                self.delete_icap_config(preview_activity_id, preview_description)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            self.log(f"Successfully retrieved Network Device ID for ICAP configuration: {network_device_id}.", "INFO")

            # Generate the CLI commands that will be applied to device.
            self.log("Generating CLI commands for ICAP configuration.", "DEBUG")
            self.generate_device_cli_of_icap_config(
                preview_activity_id=preview_activity_id,
                network_device_id=network_device_id,
                preview_description=preview_description
            )
            self.log("Retrieving the generated CLI commands for review.", "INFO")

            # to view the CLIs that will be applied to the device
            to_be_applied_clis = self.retrieves_the_devices_clis_of_the_icap(
                preview_activity_id=preview_activity_id,
                network_device_id=network_device_id,
                preview_description=preview_description
            )
            self.log("Retrieved device CLI's to be applied: {0}".format(to_be_applied_clis), "DEBUG")
            result_icap_settings.setdefault("device_cli", {}).update(
                {"The device's CLIs of the ICAP intent": to_be_applied_clis}
            )

            # Proceed with deployment if successful
            self.log(
                "ICAP configuration created successfully. Proceeding with deployment.",
                "INFO",
            )
            self.msg = "ICAP Configuration '{0}' created successfully.".format(
                preview_description
            )

            self.deploy_icap_config(preview_activity_id, preview_description)

            if isinstance(result_icap_settings, dict):
                result_icap_settings.setdefault("response", {}).update(
                    {"Deployed ICAP configuration": updated_assurance_icap_details}
                )
                result_icap_settings.setdefault("msg", {}).update(
                    {preview_description: "ICAP configuration deployed successfully"}
                )
            self.set_operation_result(
                "success", True, self.msg, "INFO", self.result["response"]
            )
            return self

        except Exception as e:
            self.msg = "An exception occurred while creating ICAP config in Cisco Catalyst Center: {0}".format(
                str(e)
            )
            self.log(self.msg, "ERROR")
            if preview_activity_id:
                self.delete_icap_config(preview_activity_id, preview_description)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def delete_icap_config(self, preview_activity_id, preview_description):
        """
        Discards an Intelligent Capture Configuration intent in Cisco Catalyst Center using the task ID.

        Args:
            task_id (str): The unique identifier of the task associated with the Intelligent Capture Configuration intent.
            preview_description (str):  Represents the ICAP intent's preview-deploy description string.

        Returns:
            self (object): Returns the current instance of the class with updated status and message attributes.

        Description:
            This method retrieves the `previewActivityId` using the provided task ID, then initiates the discard operation
            for the Intelligent Capture Configuration intent in Cisco Catalyst Center. It monitors the task's status and updates the
            instance attributes with the operation's result.

        """
        self.log(
            "Starting deleting {0} the failed Intelligent Capture Configuration".format(
                preview_description
            ),
            "INFO",
        )

        try:
            response = self.dnac._exec(
                family="sensors",
                function="discards_the_i_cap_configuration_intent_by_activity_id",
                op_modifies=True,
                params={"preview_activity_id": preview_activity_id},
            )
            self.log(
                "Received API response for discard icap config as: {0}".format(
                    response.get("response")
                ),
                "INFO",
            )
            return self

        except Exception as e:
            self.msg = "An exception occurred while discarding ICAP config in Cisco Catalyst Center: {0}".format(
                str(e)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")
            self.log(self.msg, "ERROR")
            return self

    def get_device_deployment_status(self, deployment_task_id):
        """
        Get the deployment status of a device from Cisco Catalyst Center.

        Args:
            deployment_task_id (str): The task ID for the deployment.

        Returns:
            list: The response containing deployment status details.
        """
        self.log(
            "Fetching deployment status for task ID: {0}".format(deployment_task_id),
            "INFO",
        )

        start_time = time.time()
        retry_interval = int(self.payload.get("dnac_task_poll_interval", 5))
        resync_retry_count = int(self.payload.get("dnac_api_task_timeout", 100))

        while True:
            try:
                response = self.dnac._exec(
                    family="sensors",
                    function="get_device_deployment_status",
                    params={"deploy_activity_id": deployment_task_id},
                )
                self.log(
                    "Received API response for deployment status: {0}".format(response), "INFO"
                )

                # Check if response is valid
                if response.get("response"):
                    deployment_status = response["response"][0].get("status")

                    if deployment_status == "Success":
                        self.log(
                            "Deployment succeeded for task ID: {0}".format(
                                deployment_task_id
                            ),
                            "INFO",
                        )
                        return response["response"]

            except Exception as e:
                self.log("Error fetching deployment status: {0}".format(str(e)), "ERROR")

            # Check if timeout has been reached
            if time.time() - start_time >= resync_retry_count:
                self.log(
                    "Max retries reached, returning empty result for task ID: {0}".format(
                        deployment_task_id
                    ),
                    "ERROR",
                )
                return []

            # Log before sleeping
            self.log(
                "Waiting for {0} seconds before retrying deployment status for task ID: {1}".format(
                    retry_interval, deployment_task_id
                ),
                "DEBUG",
            )
            time.sleep(retry_interval)  # Wait before retrying

    def verify_diff_merged(self, config):
        """
        Validates the Cisco Catalyst Center Intelligent Capture Configuration with playbook details when state is merged (Create/Download).

        Args:
            config (dict): Playbook details containing Intelligent Capture Configuration.

        Returns:
            self: The current object with Intelligent Capture Configuration validation result.
        """
        self.log("Requested State (want): {0}".format(self.want), "INFO")

        assurance_icap_settings_list = config.get("assurance_icap_settings", [])
        self.log(
            "Assurance ICAP Settings: {0}".format(assurance_icap_settings_list), "INFO"
        )

        assurance_icap_download = config.get("assurance_icap_download", [])
        self.log(
            "Assurance ICAP download details: {0}".format(assurance_icap_download),
            "INFO",
        )

        if not assurance_icap_settings_list and not assurance_icap_download:
            self.msg = "No data needs to be retrieved for ICAP config creation."
            self.log(self.msg, "INFO")
            return self

        # Validate assurance_icap_settings if provided
        if assurance_icap_settings_list:
            deployment_task_id = self.want.get("want_deployment_task_id")

            if deployment_task_id:
                deployment_response = self.get_device_deployment_status(
                    deployment_task_id
                )
                self.log(
                    "Received deployment status for the current deployment id {0} as {1}".format(
                        deployment_task_id, deployment_response
                    ),
                    "INFO",
                )
                deployment_success = False
                for deployment in deployment_response:
                    if deployment.get("status") == "Success":
                        deployment_success = True
                if deployment_success:
                    self.log("Successfully validated ICAP configuration(s).", "INFO")
                    self.result.get("response")[0].get(
                        "assurance_icap_settings"
                    ).update({"Validation": "Success"})
                else:
                    # If none of the deployments were successful
                    self.set_operation_result(
                        "failed",
                        False,
                        "ICAP deployment Verification is unsuccessful",
                        "ERROR",
                    )

        # Validate assurance_icap_download if provided
        if assurance_icap_download:
            for download_entry in assurance_icap_download:
                file_path = download_entry.get("file_path")
                self.log("Verifying ICAP download file path: {0}".format(file_path))
                if file_path:
                    abs_file_path = pathlib.Path(file_path).resolve()
                    if not abs_file_path.is_dir():
                        self.msg = "Provided file path is not a directory: {0}".format(
                            abs_file_path
                        )
                        self.log(self.msg, "ERROR")
                        self.set_operation_result("failed", False, self.msg, "ERROR")
                        return self

                    # Check files modified within the last 10 seconds
                    window_seconds = 10
                    current_time = time.time()
                    window_start_time = current_time - window_seconds

                    files_found = []
                    try:
                        for f in abs_file_path.iterdir():
                            if f.stat().st_mtime > window_start_time:
                                files_found.append(f.name)
                    except Exception as e:
                        self.msg = "Failed to verify ICAP download output. Error checking file path: {0}".format(
                            str(e)
                        )
                        self.set_operation_result("failed", False, self.msg, "ERROR")
                        return self

                    if files_found:
                        self.msg = "ICAP download files verified successfully. Files: {0}".format(
                            files_found
                        )
                        self.log(self.msg, "INFO")
                        self.result.get("response")[0].get(
                            "assurance_icap_download"
                        ).update({"Validation": "Success"})
                    else:
                        self.msg = "No ICAP download files found at path: {0}".format(
                            abs_file_path
                        )
                        self.log(self.msg, "WARNING")
                        self.set_operation_result("Failed", False, self.msg, "INFO")

        return self


def main():
    """Main entry point for module execution"""

    # Define the specification for module arguments
    element_spec = {
        "dnac_host": {"type": "str", "required": True},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": True},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": True},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"type": "list", "required": True, "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged"]},
        "validate_response_schema": {"type": "bool", "default": True},
    }

    # Create an AnsibleModule object with argument specifications
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    ccc_assurance = Icap(module)
    state = ccc_assurance.params.get("state")
    ccc_version = ccc_assurance.get_ccc_version()

    if ccc_assurance.compare_dnac_versions(ccc_version, "2.3.7.9") < 0:
        ccc_assurance.msg = """The specified version '{0}' does not support the Assurance Intelligent Capture
        Settings feature. Supported versions start from '2.3.7.9' onwards.""".format(
            ccc_assurance.get_ccc_version()
        )
        ccc_assurance.status = "failed"
        ccc_assurance.check_return_status()

    if state not in ccc_assurance.supported_states:
        ccc_assurance.status = "invalid"
        ccc_assurance.msg = "State {0} is invalid".format(state)
        ccc_assurance.check_return_status()

    ccc_assurance.validate_input().check_return_status()
    config_verify = ccc_assurance.params.get("config_verify")

    for config in ccc_assurance.validated_config:
        ccc_assurance.reset_values()
        ccc_assurance.get_want(config).check_return_status()
        ccc_assurance.get_have(config).check_return_status()
        ccc_assurance.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_assurance.verify_diff_state_apply[state](config).check_return_status()

        module.exit_json(**ccc_assurance.result)


if __name__ == "__main__":
    main()
