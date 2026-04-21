#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to perform update Health score KPI's in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ["Megha Kandari, Madhan Sankaranarayanan"]

DOCUMENTATION = r"""
---
module: assurance_device_health_score_settings_workflow_manager
short_description: Resource module for managing assurance
  Health score settings in Cisco Catalyst Center.
description:
  - Manages assurance Health score settings in Cisco
    Catalyst Center.
  - It supports updating configurations for Health score
    settings functionalities.
  - This module interacts with Cisco Catalyst Center's
    Assurance settings to configure thresholds, rules,
    KPIs, and more for health score monitoring.
  - The health score can be customized based on device
    type.
  - The network device's health score is determined
    by the lowest score among all included KPIs.
  - To disable a KPI from impacting the overall device
    health, you can exclude it from the health score
    calculation.
  - Health score setting is not applicable for Third
    Party Devices.
version_added: '6.31.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Megha Kandari (@kandarimegha) Madhan Sankaranarayanan
  (@madhansansel)
options:
  config_verify:
    description: >
      Set to `True` to enable configuration verification
      on Cisco Catalyst Center after applying the playbook
      config. This will ensure that the system validates
      the configuration state after the change is applied.
    type: bool
    default: false
  state:
    description: >
      Specifies the desired state for the configuration.
      If `merged`, the module will update the configuration
      modifying existing ones.
    type: str
    choices: [merged]
    default: merged
  config:
    description: >
      A list of settings and parameters for managing
      network issues in Cisco Catalyst Center, including
      synchronization with health thresholds, priority,
      KPI enablement, and threshold values.
    type: list
    elements: dict
    required: true
    suboptions:
      device_health_score:
        description: >
          Configures the health score settings for network
          devices. Defines thresholds for KPIs like
          CPU UTILIZATION, MEMORY UTILIZATION, etc.
        type: dict
        required: true
        suboptions:
          device_family:
            description: >
              Specifies the device family to which the
              health score applies.
                required:
              true
                choices:
                  - ROUTER
                  - SWITCH_AND_HUB
                  - WIRELESS_CONTROLLER
                  - UNIFIED_AP
                  - WIRELESS_CLIENT
                  - WIRED_CLIENT
          kpi_name:
            description: >
              The name of the Key Performance Indicator
              (KPI) to be monitored (e.g., LINK ERROR).
              Must be one of the valid KPI names for
              the specified device family. choices:
                ROUTER:
                    -
              BGP Session from Border to Control Plane
              (BGP)
                    -
              BGP Session from Border to Control Plane
              (PubSub)
                    -
              BGP Session from Border to Peer Node for
              INFRA VN
                    -
              BGP Session from Border to Peer Node
                    -
              BGP Session from Border to Transit Control
              Plane
                    -
              BGP Session to Spine
                    -
              Cisco TrustSec environment data download
              status
                    -
              CPU Utilization
                    -
              Extended Node Connectivity
                    -
              Fabric Control Plane Reachability
                    -
              Fabric Multicast RP Reachability
                    -
              Inter-device Link Availability
                    -
              Internet Availability
                    -
              Link Discard
                    -
              Link Error
                    -
              Link Utilization
                    -
              LISP Session from Border to Transit Site
              Control Plane
                    -
              LISP Session Status
                    -
              Memory Utilization
                    -
              Peer Status
                    -
              Pub-Sub Session from Border to Transit
              Site Control Plane
                    -
              Pub-Sub Session Status for INFRA VN
                    -
              Pub-Sub Session Status
                    -
              Remote Internet Availability
                    -
              VNI Status
                SWITCH_AND_HUB:
                    -
              AAA server reachability
                    -
              BGP Session from Border to Control Plane
              (BGP)
                    -
              BGP Session from Border to Control Plane
              (PubSub)
                    -
              BGP Session from Border to Peer Node for
              INFRA VN
                    -
              BGP Session from Border to Peer Node
                    -
              BGP Session from Border to Transit Control
              Plane
                    -
              BGP Session to Spine
                    -
              Cisco TrustSec environment data download
              status
                    -
              CPU Utilization
                    -
              Extended Node Connectivity
                    -
              Fabric Control Plane Reachability
                    -
              Fabric Multicast RP Reachability
                    -
              Inter-device Link Availability
                    -
              Internet Availability
                    -
              Link Discard
                    -
              Link Error
                    -
              LISP Session from Border to Transit Site
              Control Plane
                    -
              LISP Session Status
                    -
              Memory Utilization
                    -
              Peer Status
                    -
              Pub-Sub Session from Border to Transit
              Site Control Plane
                    -
              Pub-Sub Session Status for INFRA VN
                    -
              Pub-Sub Session Status
                    -
              Remote Internet Availability
                    -
              VNI Status
                WIRELESS_CONTROLLER:
                    -
              Fabric Control Plane Reachability
                    -
              Free Mbuf
                    -
              Free Timer
                    -
              Link Error
                    -
              LISP Session Status
                    -
              Memory Utilization
                    -
              Packet Pool
                    -
              WQE Pool
                UNIFIED_AP:
                    -
              Air Quality 2.4 GHz
                    -
              Air Quality 5 GHz
                    -
              Air Quality 6 GHz
                    -
              CPU Utilization
                    -
              Interference 2.4 GHz
                    -
              Interference 5 GHz
                    -
              Interference 6 GHz
                    -
              Link Error
                    -
              Memory Utilization
                    -
              Noise 2.4 GHz
                    -
              Noise 5 GHz
                    -
              Noise 6 GHz
                    -
              RF Utilization 2.4 GHz
                    -
              RF Utilization 5 GHz
                    -
              RF Utilization 6 GHz
                WIRELESS_CLIENT:
                    -
              Connectivity RSSI
                    -
              Connectivity SNR
                WIRED_CLIENT:
                    -
              Link Error
            type: str
            required: true
          include_for_overall_health:
            description: >
              Boolean value indicating whether this
              KPI should be included in the overall
              health score calculation.
            type: bool
            required: true
          threshold_value:
            description: >
              The threshold value that, when exceeded,
              will affect the health score.
            type: int
          synchronize_to_issue_threshold:
            description: >
              Boolean value indicating whether the threshold
              should synchronize with issue resolution
              thresholds.
            type: bool
requirements:
  - dnacentersdk >= 2.8.6
  - python >= 3.9
notes:
  - SDK Method used are
    devices.AssuranceSettings.get_all_health_score_definitions_for_given_filters,
    devices.AssuranceSettings.update_health_score_definitions
  - Paths used are
    post /dna/intent/api/v1/health_scoreDefinitions/${id},
    post /dna/intent/api/v1/health_scoreDefinitions/bulkUpdate
"""

EXAMPLES = r"""
---
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Update Health score and threshold settings
      cisco.dnac. assurance_device_health_score_settings_workflow_manager:
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
          - device_health_score:
              - device_family: SWITCH_AND_HUB  # required field
                kpi_name: CPU Utilization  # required field
                include_for_overall_health: true  # required field
                threshold_value: 90
                synchronize_to_issue_threshold: false
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Update Health score and threshold settings
      cisco.dnac. assurance_device_health_score_settings_workflow_manager:
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
          - device_health_score:
              - device_family: ROUTER  # required field
                kpi_name: Link Error  # required field
                include_for_overall_health: true  # required field
                threshold_value: 60
                synchronize_to_issue_threshold: false
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Update Health score and threshold settings
      cisco.dnac. assurance_device_health_score_settings_workflow_manager:
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
          - device_health_score:
              - device_family: UNIFIED_AP  # required field
                kpi_name: Interference 6 GHz  # required field
                include_for_overall_health: true  # required field
                threshold_value: 80
                synchronize_to_issue_threshold: false
"""


RETURN = r"""
#Case 1: Successful updation of health_score
response_1:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
          "id": "string",
          "name": "string",
          "displayName": "string",
          "deviceFamily": "string",
          "description": "string",
          "includeForOverallHealth": "boolean",
          "definitionStatus": "string",
          "thresholdValue": "number",
          "synchronizeToIssueThreshold": "boolean",
          "lastModified": "string"
      },
      "version": "string"
    }
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)


class Healthscore(DnacBase):
    """Class containing member attributes for Assurance health score setting workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged"]
        self.result["response"] = [
            {"device_health_score_settings": {"response": {}, "msg": {}}},
        ]
        self.create_issue, self.update_issue, self.no_update_issue = [], [], []

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.

        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.
            self.config (dict): A dictionary representing the playbook configuration that needs validation.
            The 'config' should be structured according to a specification, with keys such as 'device_health_score'.
            Each key in the configuration should match the predefined data types and structure defined in `temp_spec`.


        Returns:
            The method updates these attributes of the instance:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation ('success' or 'failed').
                - self.validated_config (dict): The validated configuration, if successful, otherwise the method returns early with failure.
        """

        temp_spec = {
            "device_health_score": {
                "type": "list",
                "elements": "dict",
                "name": {"type": "str", "required": True},
                "device_family": {"type": "str", "required": True},
                "include_for_overall_health": {"type": "bool", "required": True},
                "threshold_value": {"type": "int", "required": False},
                "synchronize_to_issue_threshold": {"type": "bool", "required": False},
            }
        }

        if not self.config:
            self.msg = "The playbook configuration is empty or missing."
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

    def input_data_validation(self, config):
        """
        Additional validation to check if the provided input assurance data is correct
        and as per the UI Cisco Catalyst Center.
        This function checks that the provided KPIs (Key Performance Indicators) and parameters are valid
        for the specified device families.

        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            config (list or dict): Input data containing assurance details.

        Returns:
            object: Returns the current instance with validation results.
            self.msg(str): A message indicating the validation result, either an error or success.
            self.status(str): The validation status, which will be 'failed' in case of invalid data and 'success' if the validation is successful.

        Description:
            Validates the given assurance data by iterating through the nested structure
            and ensuring the KPIs and parameters comply with defined rules.
        """
        errormsg = []
        device_family_to_kpi = {
            "ROUTER": {
                "include_for_overall_health": [
                    "Fabric Multicast RP Reachability",
                    "Inter-device Link Availability",
                    "Internet Availability",
                    "LISP Session from Border to Transit Site Control Plane",
                    "LISP Session Status",
                    "Peer Status",
                    "BGP Session from Border to Control Plane (BGP)",
                    "BGP Session from Border to Control Plane (PubSub)",
                    "BGP Session from Border to Peer Node for INFRA VN",
                    "BGP Session from Border to Peer Node",
                    "BGP Session from Border to Transit Control Plane",
                    "BGP Session to Spine",
                    "Cisco TrustSec environment data download status",
                    "Extended Node Connectivity",
                    "Fabric Control Plane Reachability",
                    "Pub-Sub Session from Border to Transit Site Control Plane",
                    "Pub-Sub Session Status for INFRA VN",
                    "Pub-Sub Session Status",
                    "Remote Internet Availability",
                    "VNI Status",
                ],
                "include_Threshold_and_sync": [
                    "Link Discard",
                    "Link Error",
                    "Link Utilization",
                    "Memory Utilization",
                    "CPU Utilization",
                ],
                "include_Threshold": [],
            },
            "SWITCH_AND_HUB": {
                "include_for_overall_health": [
                    "AAA server reachability",
                    "BGP Session from Border to Control Plane (BGP)",
                    "BGP Session from Border to Control Plane (PubSub)",
                    "BGP Session from Border to Peer Node for INFRA VN",
                    "BGP Session from Border to Peer Node",
                    "BGP Session from Border to Transit Control Plane",
                    "BGP Session to Spine",
                    "Cisco TrustSec environment data download status",
                    "Extended Node Connectivity",
                    "Fabric Control Plane Reachability",
                    "Fabric Multicast RP Reachability",
                    "Inter-device Link Availability",
                    "Internet Availability",
                    "LISP Session from Border to Transit Site Control Plane",
                    "LISP Session Status",
                    "Peer Status",
                    "Pub-Sub Session from Border to Transit Site Control Plane",
                    "Pub-Sub Session Status for INFRA VN",
                    "Pub-Sub Session Status",
                    "Remote Internet Availability",
                    "VNI Status",
                ],
                "include_Threshold_and_sync": [
                    "CPU Utilization",
                    "Link Discard",
                    "Link Error",
                    "Memory Utilization",
                ],
                "include_Threshold": [],
            },
            "WIRELESS_CONTROLLER": {
                "include_for_overall_health": [
                    "Fabric Control Plane Reachability",
                    "LISP Session Status",
                    "Packet Pool",
                    "WQE Pool",
                ],
                "include_Threshold_and_sync": [
                    "Memory Utilization",
                ],
                "include_Threshold": [
                    "Free Mbuf",
                    "Free Timer",
                    "Link Error",
                ],
            },
            "UNIFIED_AP": {
                "include_for_overall_health": [],
                "include_Threshold_and_sync": [
                    "CPU Utilization",
                    "Interference 2.4 GHz",
                    "Interference 5 GHz",
                    "Interference 6 GHz",
                    "Memory Utilization",
                    "Noise 2.4 GHz",
                    "Noise 5 GHz",
                    "Noise 6 GHz",
                    "RF Utilization 2.4 GHz",
                    "RF Utilization 5 GHz",
                    "RF Utilization 6 GHz",
                ],
                "include_Threshold": [
                    "Air Quality 2.4 GHz",
                    "Air Quality 5 GHz",
                    "Air Quality 6 GHz",
                    "Link Error",
                ],
            },
            "WIRELESS_CLIENT": {
                "include_for_overall_health": [],
                "include_Threshold_and_sync": [
                    "Connectivity RSSI",
                ],
                "include_Threshold": [
                    "Connectivity SNR",
                ],
            },
            "WIRED_CLIENT": {
                "include_for_overall_health": [],
                "include_Threshold_and_sync": [],
                "include_Threshold": [
                    "Link Error",
                ],
            },
        }

        normalized_health_scores = []
        if isinstance(config, dict) and "device_health_score" in config:
            self.log(
                "Condition met: config is a dict and contains 'device_health_score'",
                "INFO",
            )
            normalized_health_scores.extend(config["device_health_score"])
        elif isinstance(config, list):
            self.log("Condition met: config is a list", "INFO")
            for item in config:
                if "device_health_score" in item:
                    self.log(
                        "Sub-condition met: item in list contains 'device_health_score'. Value: {}".format(
                            item["device_health_score"]
                        ),
                        "INFO",
                    )
                    normalized_health_scores.extend(item["device_health_score"])
        else:
            self.msg = "Invalid configuration format provided. Ensure 'device_health_score' is present."
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        for entry in normalized_health_scores:
            device_family = entry.get("device_family")
            kpi_name = entry.get("kpi_name")
            include_for_overall_health = entry.get("include_for_overall_health", False)
            threshold_value = entry.get("threshold_value")
            synchronize_to_issue_threshold = entry.get(
                "synchronize_to_issue_threshold", False
            )
            self.log(
                "Extracted Values - device_family: {}, kpi_name: {}, include_for_overall_health: {}, "
                "threshold_value: {}, synchronize_to_issue_threshold: {}".format(
                    device_family,
                    kpi_name,
                    include_for_overall_health,
                    threshold_value,
                    synchronize_to_issue_threshold,
                ),
                "INFO",
            )

            if not device_family or device_family not in device_family_to_kpi:
                errormsg.append(
                    "Device_Family: Invalid or missing Device Family '{}'.".format(
                        device_family
                    )
                )
                continue

            valid_kpis = device_family_to_kpi[device_family]
            if not kpi_name:
                errormsg.append("kpi_name: KPI Name is missing.")
            else:
                if (
                    kpi_name not in valid_kpis["include_for_overall_health"]
                    and kpi_name not in valid_kpis["include_Threshold_and_sync"]
                    and kpi_name not in valid_kpis["include_Threshold"]
                ):
                    errormsg.append(
                        "kpi_name: Invalid KPI '{}' for Device Family '{}'.".format(
                            kpi_name, device_family
                        )
                    )
                else:
                    category = (
                        "include_for_overall_health"
                        if kpi_name in valid_kpis["include_for_overall_health"]
                        else "include_Threshold_and_sync"
                    )

                    if category == "include_for_overall_health" and (
                        threshold_value or synchronize_to_issue_threshold
                    ):
                        errormsg.append(
                            "'threshold_value' or 'synchronize_to_issue_threshold not applicable for KPI '{}''.".format(
                                kpi_name
                            )
                        )
                    if (
                        category == "include_Threshold"
                        and synchronize_to_issue_threshold
                    ):
                        errormsg.append(
                            "'synchronize_to_issue_threshold' is not applicable for KPI '{}' under 'include_Threshold_and_sync'.".format(
                                kpi_name
                            )
                        )
                    self.log(
                        "KPI '{}' belongs to category '{}' for Device Family '{}'".format(
                            kpi_name, category, device_family
                        ),
                        "INFO",
                    )

        if len(errormsg) > 0:
            self.msg = "Invalid parameters in playbook config: {}".format(errormsg)
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        self.msg = "Successfully validated config params: {}".format(config)
        self.log(self.msg, "INFO")
        return self

    def health_score_obj_params(self, get_object):
        """
        Get the required comparison obj_params value

        Parameters:
            get_object (str) - identifier for the required obj_params
            self (object): The instance of the class that calls this method.

        Returns:
            list - A list of value for comparison.
            None - If an invalid `get_object` is provided, logs an error and returns None.
        """

        try:
            if get_object == "device_health_score_settings":
                return [
                    ("name", "name"),
                    ("device_family", "device_family"),
                    ("include_for_overall_health", "include_for_overall_health"),
                    ("threshold_value", "threshold_value"),
                    (
                        "synchronize_to_issue_threshold",
                        "synchronize_to_issue_threshold",
                    ),
                ]

            error_message = "Received an unexpected value for 'get_object': {0}".format(
                get_object
            )
            self.log(error_message, "ERROR")
            self.set_operation_result("failed", False, error_message, "ERROR")
        except Exception as e:
            self.log("Received exception: {}".format(e), "CRITICAL")

        return None

    def get_want(self, config):
        """
        Retrieve and store assurance Health score details from playbook configuration.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing image import and other details.

        Returns:
            self: The current instance of the class with updated 'want' attributes.
        """

        want = {"device_health_score": config.get("device_health_score", [])}

        kpi_name = {
            "Link Error": "linkErrorThreshold",  # WIRED_CLIENT and # UNIFIED_AP and # WIRELESS_CLIENT # ROUTER
            "Connectivity RSSI": "rssiThreshold",  # WIRELESS_CLIENT
            "Connectivity SNR": "snrThreshold",  # WIRELESS_CLIENT
            "Air Quality 2.4 GHz": "rf_airQuality_2_4GThreshold",  # UNIFIED_AP
            "Air Quality 5 GHz": "rf_airQuality_5GThreshold",  # UNIFIED_AP
            "Air Quality 6 GHz": "rf_airQuality_6GThreshold",  # UNIFIED_AP
            "CPU Utilization": "cpuUtilizationThreshold",  # SWITCH_AND_HUB and # ROUTER and # UNIFIED_AP and # WIRELESS_CONTROLLER
            "Interference 2.4 GHz": "rf_interference_2_4GThreshold",  # UNIFIED_AP
            "Interference 5 GHz": "rf_interference_5GThreshold",  # UNIFIED_AP
            "Interference 6 GHz": "rf_interference_6GThreshold",  # UNIFIED_AP
            "Noise 2.4 GHz": "rf_noise_2_4GThreshold",  # UNIFIED_AP
            "Noise 5 GHz": "rf_noise_5GThreshold",  # UNIFIED_AP
            "Noise 6 GHz": "rf_noise_6GThreshold",  # UNIFIED_AP
            "RF Utilization 2.4 GHz": "rf_utilization_2_4GThreshold",  # UNIFIED_AP
            "RF Utilization 5 GHz": "rf_utilization_5GThreshold",  # UNIFIED_AP
            "RF Utilization 6 GHz": "rf_utilization_6GThreshold",  # UNIFIED_AP
            "Free Mbuf": "freeMbufThreshold",  # WIRELESS_CONTROLLER
            "Free Timer": "freeTimerThreshold",  # WIRELESS_CONTROLLER
            "Packet Pool": "packetPool",  # WIRELESS_CONTROLLER
            "WQE Pool": "WQEPool",  # WIRELESS_CONTROLLER
            "AAA server reachability": "aaaServerReachability",  # SWITCH_AND_HUB
            "BGP Session from Border to Control Plane (BGP)": "bgpBgpSiteThreshold",  # SWITCH_AND_HUB and # ROUTER
            "BGP Session from Border to Control Plane (PubSub)": "bgpPubsubSiteThreshold",  # SWITCH_AND_HUB and # ROUTER
            "BGP Session from Border to Peer Node for INFRA VN": "bgpPeerInfraVnThreshold",  # SWITCH_AND_HUB and # ROUTER
            "BGP Session from Border to Peer Node": "bgpPeerThreshold",  # SWITCH_AND_HUB and # ROUTER
            "BGP Session from Border to Transit Control Plane": "bgpTcpThreshold",  # SWITCH_AND_HUB and # ROUTER
            "BGP Session to Spine": "bgpEvpnThreshold",  # SWITCH_AND_HUB and # ROUTER
            "Cisco TrustSec environment data download status": "ctsEnvDataThreshold",  # SWITCH_AND_HUB and # ROUTER
            "Fabric Control Plane Reachability": "fabricReachability",  # SWITCH_AND_HUB and # ROUTER and # WIRELESS_CONTROLLER
            "Fabric Multicast RP Reachability": "multicastRPReachability",  # SWITCH_AND_HUB and # ROUTER
            "Extended Node Connectivity": "fpcLinkScoreThreshold",  # ROUTER and # WIRELESS_CONTROLLER
            "Inter-device Link Availability": "infraLinkAvailabilityThreshold",  # SWITCH_AND_HUB
            "Internet Availability": "defaultRouteThreshold",  # SWITCH_AND_HUB and # ROUTER
            "Link Discard": "linkDiscardThreshold",  # SWITCH_AND_HUB and # ROUTER
            "Link Utilization": "linkUtilizationThreshold",  # SWITCH_AND_HUB and # ROUTER
            "LISP Session from Border to Transit Site Control Plane": "lispTransitConnScoreThreshold",  # SWITCH_AND_HUB and # ROUTER
            "LISP Session Status": "lispCpConnScoreThreshold",  # SWITCH_AND_HUB and # ROUTER and # WIRELESS_CONTROLLER
            "Memory Utilization": "memoryUtilizationThreshold",  # SWITCH_AND_HUB and # ROUTER and # WIRELESS_CONTROLLER and # UNIFIED_AP
            "Peer Status": "peerThreshold",  # SWITCH_AND_HUB and # ROUTER
            "Pub-Sub Session from Border to Transit Site Control Plane": "pubsubTransitSessionScoreThreshold",  # SWITCH_AND_HUB and # ROUTER
            "Pub-Sub Session Status for INFRA VN": "pubsubInfraVNSessionScoreThreshold",  # SWITCH_AND_HUB and # ROUTER
            "Pub-Sub Session Status": "pubsubSessionThreshold",  # SWITCH_AND_HUB and # ROUTER
            "Remote Internet Availability": "remoteRouteThreshold",  # SWITCH_AND_HUB and # ROUTER
            "VNI Status": "vniStatusThreshold",  # SWITCH_AND_HUB and # ROUTER
        }

        # Define validation rules for KPI names and device families
        validation_rules = {
            "Connectivity RSSI": {
                "device_family": "WIRELESS_CLIENT",
                "range": (-128, 0),
            },
            "Connectivity SNR": {"device_family": "WIRELESS_CLIENT", "range": (1, 40)},
        }
        self.log(want["device_health_score"])
        for health_score in want["device_health_score"]:
            name = health_score["kpi_name"]

            if name not in kpi_name:
                self.log("Unknown KPI name: {}".format(name), "ERROR")
                continue  # Skip unknown KPI names

            health_score["kpi_name"] = kpi_name[name]

            # Validate threshold values based on KPI name and device family
            rule = validation_rules.get(name)
            if rule and health_score.get("device_family") == rule["device_family"]:
                threshold_value = health_score.get("threshold_value")
                min_val, max_val = rule["range"]
                if threshold_value is None or not (
                    min_val <= threshold_value <= max_val
                ):
                    self.msg = "Threshold value for {} should be between {} and {} dBm.".format(
                        name, min_val, max_val
                    )
                    self.log("Validation failed: {}".format(self.msg), "CRITICAL")
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self  # Exit early on failure

        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")
        return self

    def get_have(self, config):
        """
        Get the current assurance Health score and associated information from the Cisco Catalyst Center
        based on the provided playbook details.

        Parameters:
        self (object): The instance interacting with Cisco Catalyst Center.
        config (dict): The configuration dictionary containing health score details.

        Returns:
        self: The current instance with updated 'have' attributes.
        """
        self.log("Starting to retrieve assurance health score details...", "INFO")
        device_health_score_details = config.get("device_health_score", [])

        if not device_health_score_details:
            self.msg = "No device_health_score details provided in the configuration."
            self.set_operation_result("failed", False, self.msg, "ERROR")

        have = []

        for index, health_score_details in enumerate(
            device_health_score_details, start=1
        ):
            self.log(
                "Processing entry {0}: {1}".format(index, health_score_details), "DEBUG"
            )
            if "kpi_name" in health_score_details:
                health_score_details["name"] = health_score_details.pop("kpi_name")
                self.log(
                    "Renamed 'kpi_name' to 'name' in entry {0}".format(index), "DEBUG"
                )

            device_family = health_score_details.get("device_family")
            if not device_family:
                self.log("{0}: Missing 'device_family' field.".format(index), "WARNING")
                self.msg = "Missing 'device_family' field."
                self.set_operation_result("failed", False, self.msg, "ERROR")

            self.log(
                "Fetching KPI details for device family '{0}' in entry {1}".format(
                    device_family, index
                ),
                "INFO",
            )

            kpi_details = self.get_kpi_details(device_family, health_score_details)

            if not kpi_details:
                self.msg = (
                    "No matching KPI details found for device family '{0}'".format(
                        device_family
                    )
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            have.append(kpi_details)

        key_replacements = {
            "deviceFamily": "device_family",
            "includeForOverallHealth": "include_for_overall_health",
            "thresholdValue": "threshold_value",
            "synchronizeToIssueThreshold": "synchronize_to_issue_threshold",
        }

        for index, item in enumerate(have, start=1):
            for old_key, new_key in key_replacements.items():
                if old_key in item:
                    item[new_key] = item.pop(old_key)
                    self.log(
                        "Renamed '{0}' to '{1}' in entry {2}".format(
                            old_key, new_key, index
                        ),
                        "DEBUG",
                    )

        self.have = have

        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.msg = "Successfully retrieved the details from the system."
        self.log(self.msg)
        return self

    def get_kpi_details(self, device_family, health_score_details):
        """
        Retrieve the KPI name based on the device family by calling the 'Get all health score definitions for given filters' API.

        Parameters:
        device_family (str): The device family for which KPI details are to be fetched.
        health_score_details (dict): The details of the health score for which KPI information is needed.

        Returns:
        kpi: The KPI details for the given device family and health score name if found.
        None: If no matching KPI details are found or if there is an exception during the API call.

        """
        self.log("Retrieving KPI for device family '{0}'".format(device_family))

        total_response = []
        try:
            for include_for_overall_health in [True, False]:
                response = self.dnac._exec(
                    family="devices",
                    function="get_all_health_score_definitions_for_given_filters",
                    params={
                        "deviceType": device_family,
                        "includeForOverallHealth": include_for_overall_health,
                    },
                )
                if isinstance(response.get("response"), list):
                    total_response.extend(response.get("response"))
            self.log(
                "Retrieved {0} KPI records for device family '{1}'".format(
                    len(total_response), device_family
                ),
                "DEBUG",
            )
        except Exception as msg:
            self.msg = "Exception occurred while getting KPI details: {0}".format(msg)
            self.log(self.msg, "ERROR")
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return None

        if not isinstance(response, dict):
            self.msg = "Failed to retrieve KPI details - Response is not a dictionary"
            self.log(self.msg, "CRITICAL")
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return None

        kpi_details = total_response

        if not kpi_details:
            self.msg = "No KPI details found for device family '{0}'".format(
                device_family
            )
            self.log(self.msg, "ERROR")
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return None

        for kpi in kpi_details:
            if kpi.get("deviceFamily") == device_family and kpi.get(
                "name"
            ) == health_score_details.get("name"):
                self.log(
                    "KPI details for device family '{0}' and KPI '{1}': {2}".format(
                        device_family, health_score_details.get("name"), kpi
                    ),
                    "INFO",
                )
                return kpi

        self.msg = "No KPI found for device family '{0}' and KPI name '{1}'".format(
            device_family, kpi_details
        )
        self.log(self.msg, "ERROR")
        self.set_operation_result("failed", False, self.msg, "ERROR")
        return None

    def get_diff_merged(self, config):
        """
        Update Assurance Health score configurations in Cisco Catalyst Center based on the playbook details

        Parameters:
            config (list of dict) - Playbook details containing Assurance Health score information.

        Returns:
            self - The current object with Assurance health score information.
        """
        self.log("Starting get_diff_merged with provided config", "INFO")
        device_health_score_details = config.get("device_health_score")
        if not device_health_score_details:
            self.log(
                "No device_health_score details found in config. Skipping update.",
                "WARNING",
            )
            return self

        self.log("Updating health score settings with provided details", "INFO")
        self.update_health_score_settings(
            device_health_score_details
        ).check_return_status()

        self.log("Successfully completed get_diff_merged", "INFO")
        return self

    def update_health_score_settings(self, device_health_score_details):
        """
        Update the device Health score settings in Cisco Catalyst Center.

        This method compares the current Health score settings (`self.have`) with the desired Health score settings (`device_health_score_details`)
        from the playbook configuration. If there are any differences, it updates the Health score settings in Cisco Catalyst Center. It also checks if
        an update is needed for each setting, and if not, it logs that no update is required for that specific Health score setting.

        Parameters:
            device_health_score_details (list of dict): List of dictionaries containing the Health score settings that need to be updated.
                Each dictionary must include the following keys:
                - "name" (str): The name of the Health score setting.
                - "include_for_overall_health" (bool): Indicates if the Health score is included for overall health.
                - "threshold_value" (int): The threshold value for the Health score.
                - "synchronize_to_issue_threshold" (bool): Indicates if the Health score should be synchronized to issue threshold.

        Returns:
            self: The current instance of the class with updated Health score settings. If any setting fails to update, the operation will
                be marked as "failed", and the method will return early.
        """
        self.log("Starting update_health_score_settings with provided details", "INFO")
        updated_health_score_settings = []
        result_health_score_settings = self.result.get("response")[0].get(
            "device_health_score_settings"
        )

        if result_health_score_settings is None:
            self.log(
                "Failed to retrieve existing health score settings. Aborting update.",
                "ERROR",
            )
            self.set_operation_result(
                "failed", False, "Missing existing health score settings", "ERROR"
            )
            return self

        for health_score_setting in device_health_score_details:
            name = health_score_setting.get("name")
            if name is None:
                self.msg = (
                    "Missing required parameter 'name' in device_health_score_details"
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log("Processing health score setting: {0}".format(name), "DEBUG")
            health_score_obj_params = self.health_score_obj_params(
                "device_health_score_settings"
            )

            for item in self.have:
                if health_score_setting.get("name") == item.get(
                    "name"
                ) and health_score_setting.get("device_family") == item.get(
                    "device_family"
                ):
                    health_score_params = {}
                    if not self.requires_update(
                        item, health_score_setting, health_score_obj_params
                    ):
                        self.log(
                            "Health score setting '{0}' does not require an update".format(
                                name
                            ),
                            "INFO",
                        )

                        if result_health_score_settings.get("msg") is not None:
                            result_health_score_settings["msg"].update(
                                {name: "Health score settings do not require an update"}
                            )
                        continue

                    health_score_params = {
                        "id": item.get("id"),
                        "payload": {
                            "includeForOverallHealth": health_score_setting.get(
                                "include_for_overall_health"
                            ),
                            "thresholdValue": health_score_setting.get(
                                "threshold_value"
                            ),
                            "synchronizeToIssueThreshold": health_score_setting.get(
                                "synchronize_to_issue_threshold"
                            ),
                        },
                    }

                    self.log(
                        "Preparing update for Health score settings '{0}' with params: {1}".format(
                            name, health_score_params
                        ),
                        "DEBUG",
                    )

                    try:
                        response = self.dnac._exec(
                            family="devices",
                            function="update_health_score_definition_for_the_given_id",
                            op_modifies=True,
                            params=health_score_params,
                        )

                        if not response:
                            error_message = "Failed to update health score definition: No response received from DNAC."
                            self.log(error_message, "ERROR")
                            self.set_operation_result("failed", False, error_message, "ERROR").check_return_status()

                        response_data = response.get("response")
                        if response_data:
                            self.log(
                                "Successfully updated Health score settings '{0}' with details: {1}".format(
                                    name, response_data
                                ),
                                "INFO",
                            )
                            updated_health_score_settings.append(response_data)

                        result_health_score_settings.get("response").update(
                            {"Health score details": updated_health_score_settings}
                        )
                        result_health_score_settings.get("msg").update(
                            {
                                response_data.get(
                                    "name"
                                ): "Health score settings updated Successfully"
                            }
                        )
                        self.msg = "Successfully updated Health score settings."
                        self.set_operation_result(
                            "success", True, self.msg, "INFO", self.result["response"]
                        )
                    except Exception as e:
                        e = str(e).split('"')[9]
                        self.msg = "Exception occurred while updating the Health score settings '{0}':'{1}'".format(
                            str(name), str(e)
                        )
                        self.log(self.msg, "ERROR")
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        return self

    def verify_diff_merged(self, config):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is merged (Update).

        Parameters:
            config (dict) - Playbook details containing Assurance Health score setting.
              - "device_health_score" (list of dict): The list of Health score settings that need to be validated.

        Returns:
            self - The current object with Assurance Health score information.
            If validation fails the operation is marked as failed and the method returns early with an error message.
        """

        self.all_device_health_score_details = {}
        self.get_have(config)
        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.log(
            "Requested State (want): {0}".format(self.want.get("device_health_score")),
            "INFO",
        )
        device_health_score_list = self.want.get("device_health_score")
        if not device_health_score_list:
            self.log("No device health score settings to validate.", "INFO")
            self.msg = "No Assurance Health score settings provided for validation."
            return self

        self.log(
            "Desired State of assurance Health score issue settings (want): {0}".format(
                device_health_score_list
            ),
            "DEBUG",
        )
        self.log(
            "Current State of assurance Health score issue settings (have): {0}".format(
                self.have
            ),
            "DEBUG",
        )

        for index, item in enumerate(device_health_score_list):
            if index >= len(self.have):
                self.msg = "Mismatch: More device health score settings in 'want' than in 'have'."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            device_health_score_details = self.have[index]
            health_score_obj_params = self.health_score_obj_params(
                "device_health_score_settings"
            )

            if self.requires_update(
                device_health_score_details, item, health_score_obj_params
            ):
                self.msg = "Assurance Health score Config is not applied to the Cisco Catalyst Center"
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

        self.log("Successfully validated Assurance Health score setting(s).", "INFO")
        if isinstance(self.result.get("response"), list) and self.result["response"]:
            self.result["response"][0].setdefault(
                "device_health_score_settings", {}
            ).update({"Validation": "Success"})

        self.msg = "Successfully validated the Assurance user defined issue."
        return self


def main():
    """main entry point for module execution"""
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
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"type": "list", "required": True, "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged"]},
        "validate_response_schema": {"type": "bool", "default": True},
    }

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    ccc_assurance = Healthscore(module)
    state = ccc_assurance.params.get("state")

    if state not in ccc_assurance.supported_states:
        ccc_assurance.status = "invalid"
        ccc_assurance.msg = "State '{0}' is invalid. Supported states: {1}".format
        (state, ", ".join(ccc_assurance.supported_states))
        ccc_assurance.check_return_status()

    ccc_version = ccc_assurance.get_ccc_version()
    if ccc_assurance.compare_dnac_versions(ccc_version, "2.3.7.9") < 0:
        ccc_assurance.msg = (
            "The specified version '{0}' does not support the Assurance Health Score features. "
            "Supported versions start from '2.3.7.9' onwards.".format(ccc_version)
        )
        ccc_assurance.status = "failed"
        ccc_assurance.check_return_status()
    ccc_assurance.validate_input().check_return_status()
    config_verify = ccc_assurance.params.get("config_verify")

    for config in ccc_assurance.validated_config:
        ccc_assurance.input_data_validation(config).check_return_status()
        ccc_assurance.get_want(config).check_return_status()
        ccc_assurance.get_have(config).check_return_status()
        ccc_assurance.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_assurance.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_assurance.result)


if __name__ == "__main__":
    main()
