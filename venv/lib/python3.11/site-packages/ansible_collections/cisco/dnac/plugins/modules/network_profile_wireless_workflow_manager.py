#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to perform operations on create and delete wireless network profile details
in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ["A Mohamed Rafeek, Madhan Sankaranarayanan"]

DOCUMENTATION = r"""
---
module: network_profile_wireless_workflow_manager
short_description: Resource module for managing network
  wireless profile in Cisco Catalyst Center
description:
  - This module allows the creation and deletion of
    wireless profiles in Cisco Catalyst Center.
  - It enables configuring SSID details, assigning profile
    names, and managing additional interface settings,
    destination ports, and protocols.
  - This module interacts with Cisco Catalyst Center's
    to create profile name, SSID details, additional
    interface details destination port and protocol.
version_added: "6.37.0"
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - A Mohamed Rafeek (@mabdulk2)
  - Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: |
      Set to `True` to enable configuration verification on Cisco Catalyst Center
      after applying the playbook config. This will ensure that the system validates
      the configuration state after the change is applied.
    type: bool
    default: false
  state:
    description: |
      Specifies the desired state for the configuration. If "merged", the module
      will create or update the configuration, adding new settings or modifying existing
      ones. If "deleted", it will remove the specified settings.
    type: str
    choices: ["merged", "deleted"]
    default: merged
  config:
    description: A list containing the details for network
      wireless profile creation.
    type: list
    elements: dict
    required: true
    suboptions:
      profile_name:
        description: Specify the name of the wireless
          profile that needs to be created.
        type: str
        required: true
      site_names:
        description: |
          List of site names assigned to the profile. For example, ["Global/USA/New York/BLDNYC"].
        type: list
        elements: str
        required: false
      ssid_details:
        description: |
          Contains the SSID details required to update or configure the wireless network profile.
        type: list
        elements: dict
        required: false
        suboptions:
          ssid_name:
            description: The name of the SSID (Service
              Set Identifier) to be configured.
            type: str
            required: true
          dot11be_profile_name:
            description: |
              The 802.11be profile name to be assigned to this SSID.
              This profile defines advanced Wi-Fi 7 (802.11be) parameters to optimize
              network performance and efficiency.
            type: str
            required: false
          enable_fabric:
            description: |
              Set to `True` to enable fabric mode for this SSID.
              When enabled, the SSID operates within a Cisco SD-Access fabric network,
              leveraging policy-based segmentation and automation.
            type: bool
            required: false
          vlan_group_name:
            description: |
              The VLAN group name to which this SSID belongs, if applicable.
              VLAN groups allow multiple VLANs to be logically grouped for efficient
              traffic segmentation and policy enforcement.
            type: str
            required: false
          interface_name:
            description: |
              The name of the network interface where this SSID is configured.
              If specified, the SSID will be mapped to this interface instead of
              being part of a VLAN group.
            type: str
            required: false
          anchor_group_name:
            description: |
              The name of the anchor group if SSID anchoring is required.
              SSID anchoring is used in mobility architectures where traffic
              for a particular SSID is tunneled to a designated anchor controller.
            type: str
            required: false
          local_to_vlan:
            description: |
              The VLAN ID to which the SSID is mapped. This must be a numeric value
              between 1 and 4094, ensuring proper network segmentation.
            type: int
            required: false
      ap_zones:
        description: |
          Defines AP (Access Point) zones that need to be associated with
          the wireless network profile.
        type: list
        elements: dict
        required: false
        suboptions:
          ap_zone_name:
            description: Name of the AP zone to be created
              and associated with the wireless profile.
            type: str
            required: true
          ssids:
            description: |
              A list of SSIDs to be linked to this AP zone.
              For example, ["SSID1", "SSID2"].
            type: list
            elements: str
            required: true
          rf_profile_name:
            description: |
              Specifies the Radio Frequency (RF) profile to be assigned to the AP zone.
              This can be a predefined profile such as "HIGH", "LOW", "TYPICAL",
              or a custom RF profile created by the user.
              For example, "HIGH".
            type: str
            required: true
      day_n_templates:
        description: |
          List of Day-N template names assigned to the profile.
        type: list
        elements: str
        required: false
      feature_template_designs:
        description: |
          List of feature template designs to be assigned or removed to/from the wireless network profile.
          Feature templates provide advanced configuration capabilities for wireless infrastructure
          including AAA settings, SSID configurations, CleanAir parameters, and RRM settings.
          These templates enable standardized configuration deployment across wireless network profiles.
        type: list
        elements: dict
        required: false
        suboptions:
          design_type:
            description: |
                The category or name of the feature template to be applied.
                This defines the functional area of the configuration (For example, AAA, SSID, CleanAir).
                Only one feature template category can be specified per entry in this list.
                For support values:
                - AAA_RADIUS_ATTRIBUTES_CONFIGURATION
                - ADVANCED_SSID_CONFIGURATION
                - CLEANAIR_CONFIGURATION
                - DOT11AX_CONFIGURATION
                - DOT11BE_STATUS_CONFIGURATION
                - EVENT_DRIVEN_RRM_CONFIGURATION
                - FLEX_CONFIGURATION
                - MULTICAST_CONFIGURATION
                - RRM_FRA_CONFIGURATION
                - RRM_GENERAL_CONFIGURATION
            type: str
            required: false
          feature_templates:
            description: |
              A list of specific design names or IDs to apply within the chosen feature template category.
              These designs include various parameters and settings for wireless infrastructure configuration.
            type: list
            elements: str
            required: true
          applicability_ssids:
            description: |
              A list of SSIDs to which this feature template applies.
              If "Default Advanced SSID Design" is selected for the 'feature_templates', this feature template
              will automatically apply to all SSIDs, regardless of this list's content.
              For example, ["SSID1", "SSID2"].
            type: list
            elements: str
            required: false
            default: ["All"]
      additional_interfaces:
        description: |
          Specifies additional interfaces to be added to this wireless profile.
          If the specified interface name and VLAN ID do not exist, they will be created.
        type: list
        elements: dict
        required: false
        suboptions:
          interface_name:
            description: Name of the additional interface.
            type: str
            required: true
          vlan_id:
            description: |
              VLAN ID for the interface. It must be a numeric value between 1 and 4094.
              This field is required if the VLAN interface and ID do not already exist.
            type: int
            required: true
requirements:
  - dnacentersdk >= 2.8.6
  - python >= 3.9
notes:
  - SDK Method used are
    wireless.create_wireless_profile
    ,
    wireless.update_application_policy,
    wireless.get_wireless_profile,
    site_design.assign_sites,
    wireless.get_interfaces
    wireless.create_interface
  - Paths used are
    GET dna/intent/api/v1/wirelessProfiles
    POST dna/intent/api/v1/wirelessProfiles/{ GET /dna/intent/api/v1/app-policy-intent
    DELETE /dna/intent/api/v1/app-policy-intent GET
    /dna/intent/api/v1/wirelessSettings/interfaces POST
    /dna/intent/api/v1/wirelessSettings/interfaces
"""

EXAMPLES = r"""
---
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Create network wireless profile
      cisco.dnac.network_profile_wireless_workflow_manager:
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
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - profile_name: Corporate_Wireless_Profile
            site_names:
              - Global/Headquarters
              - Global/BranchOffice
            ssid_details:
              - ssid_name: Corporate_WiFi
                enable_fabric: false
                dot11be_profile_name: Corporate_VLAN
                vlan_group_name: Corporate_VLAN_Group
              - ssid_name: Guest_WiFi
                enable_fabric: false
                dot11be_profile_name: Corporate_VLAN
                interface_name: guest_network
                local_to_vlan: 3002
            ap_zones:
              - ap_zone_name: HQ_AP_Zone
                rf_profile_name: HIGH
                ssids:
                  - Corporate_WiFi
              - ap_zone_name: Branch_AP_Zone
                rf_profile_name: TYPICAL
                ssids:
                  - Guest_WiFi
            additional_interfaces:
              - interface_name: Corp_Interface_1
                vlan_id: 100
              - interface_name: Guest_Interface_1
                vlan_id: 3002
            day_n_templates:
              - Wireless_Controller_Config
            feature_template_designs:
              - design_type: Advanced SSID Configuration
                feature_templates:
                  - Default Advanced SSID Design
                applicability_ssids:
                  - HQ_WiFi
                  - Branch_Secure

    - name: Create network wireless profile name only
      cisco.dnac.network_profile_wireless_workflow_manager:
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
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - profile_name: Corporate_Wireless_Profile

    - name: Create network wireless profile assign to site
      cisco.dnac.network_profile_wireless_workflow_manager:
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
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - profile_name: Corporate_Wireless_Profile
            site_names:
              - Global/USA/SAN JOSE/SJ_BLD20

    - name: Create network wireless profile with feature template assign to site
      cisco.dnac.network_profile_wireless_workflow_manager:
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
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - profile_name: Corporate_Wireless_Profile
            site_names:
              - Global/USA/SAN JOSE/SJ_BLD20/FLOOR3
            feature_template_designs:
              - design_type: AAA_RADIUS_ATTRIBUTES_CONFIGURATION
                feature_templates:
                  - Default AAA_Radius_Attributes_Configuration

    - name: Update network wireless profile with feature template
      cisco.dnac.network_profile_wireless_workflow_manager:
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
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - profile_name: Corporate_Wireless_Profile
            site_names:
              - Global/USA/SAN JOSE/SJ_BLD20/FLOOR3
            feature_template_designs:
              - design_type: AAA_RADIUS_ATTRIBUTES_CONFIGURATION
                feature_templates:
                  - Default AAA_Radius_Attributes_Configuration
              - design_type: CLEANAIR_CONFIGURATION
                feature_templates:
                  - SAMPLE
                  - Default CleanAir 6GHz Design

    - name: Create network wireless profile with SSID details
      cisco.dnac.network_profile_wireless_workflow_manager:
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
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - profile_name: Corporate_Wireless_Profile
            ssid_details:
              - ssid_name: Guest_WiFi
                enable_fabric: false
                dot11be_profile_name: Corporate_VLAN
                interface_name: guest_network
                local_to_vlan: 3002
              - ssid_name: ODC_WiFi
                enable_fabric: false
                dot11be_profile_name: Corporate_VLAN
                interface_name: guest_network
                local_to_vlan: 3001

    - name: Update network wireless profile with additional SSID details
      cisco.dnac.network_profile_wireless_workflow_manager:
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
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - profile_name: Corporate_Wireless_Profile
            ssid_details:
              - ssid_name: Guest_WiFi
                enable_fabric: false
                dot11be_profile_name: Corporate_VLAN
                interface_name: guest_network
                local_to_vlan: 3002
              - ssid_name: ODC_WiFi
                enable_fabric: false
                dot11be_profile_name: Corporate_VLAN
                interface_name: guest_network
                local_to_vlan: 3001
              - ssid_name: Corporate_WiFi
                enable_fabric: false
                dot11be_profile_name: Corporate_VLAN
                interface_name: guest_network
                local_to_vlan: 3003

    - name: Update wireless network profile
      cisco.dnac.network_profile_wireless_workflow_manager:
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
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - profile_name: Corporate_Wireless_Profile
            site_names:
              - Global/FrontOffice
            ssid_details:
              - ssid_name: Guest_WiFi
                enable_fabric: false
                dot11be_profile_name: Corporate_VLAN
                interface_name: guest_network
                local_to_vlan: 3002
            ap_zones:
              - ap_zone_name: Branch_AP_Zone
                rf_profile_name: TYPICAL
                ssids:
                  - Guest_WiFi
            additional_interfaces:
              - interface_name: Guest_Interface_4
                vlan_id: 2002
            day_n_templates:
              - Wireless_Controller_Config

    - name: Delete wireless profile from Cisco Catalyst Center.
      cisco.dnac.network_profile_wireless_workflow_manager:
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
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: deleted
        config:
          - profile_name: Corporate_Wireless_Profile
"""

RETURN = r"""
# Case 1: Successful wireless profile operations (create/update)
response_merged:
  description: Response returned when wireless profile operations complete successfully.
    Contains details about profile creation, updates, site assignments, and template associations.
  returned: always when state=merged
  type: dict
  sample:
    # Basic profile creation
    profile_create_basic:
      msg: "Wireless profile(s) created/updated and verified successfully"
      response:
        - profile_name: "Corporate_Wireless_Profile"
          profile_status: "Network Profile [ff0003b4-adab-4de4-af0e-0cf07d6df07f] Successfully Created"
      status: "success"
      changed: true

    # Profile with site assignment
    profile_create_with_sites:
      msg: "Wireless profile(s) created/updated and verified successfully"
      response:
        - profile_name: "Corporate_Wireless_Profile"
          profile_status: "Network Profile [9a1c37bd-52a9-436c-af8c-35e64f788abd] Successfully Created"
          site_status: "Sites ['Global/USA/SAN JOSE/SJ_BLD20/FLOOR3',
                        'Global/USA/SAN JOSE/SJ_BLD20/FLOOR1'] successfully associated
                        to network profile: Corporate_Wireless_Profile"
      status: "success"
      changed: true

    # Profile update with template assignment
    profile_update_with_template_assignment:
      msg: "Wireless profile(s) created/updated and verified successfully"
      response:
        - profile_name: "Corporate_Wireless_Profile"
          profile_status: "Network Profile [bba6fd01-9d65-4bde-973a-a7ba6a9ad9b4] Successfully Updated"
          template_status: "Templates successfully attached to network profile"
      status: "success"
      changed: true

# Case 2: Successful wireless profile deletion
response_deleted:
  description: Response returned when wireless profile deletion completes successfully.
    Contains details about profile removal and site disassociation.
  returned: always when state=deleted
  type: dict
  sample:
    msg: "Wireless profile(s) deleted and verified successfully"
    response:
      - profile_name: "Corporate_Wireless_Profile"
        status: "Network Profile [ff0003b4-adab-4de4-af0e-0cf07d6df07f] Successfully Deleted"
        sites_unassigned: "Sites successfully disassociated before deletion"
    status: "success"
    changed: true

# Case 3: No changes required (idempotent)
response_no_changes:
  description: Response when no changes are required as the desired state already exists.
  returned: when configuration already matches desired state
  type: dict
  sample:
    msg: "No changes required, profile(s) already exist and match desired configuration"
    response: []
    status: "success"
    changed: false

# Case 4: Partial success with warnings
response_partial_success:
  description: Response when some operations succeed but others encounter issues.
    Contains details about successful operations and any warnings or failures.
  returned: when some operations succeed but others fail
  type: dict
  sample:
    msg: "Wireless profile(s) created/updated with warnings"
    response:
      - profile_name: "Corporate_Wireless_Profile"
        profile_status: "Network Profile [ff0003b4-adab-4de4-af0e-0cf07d6df07f] Successfully Created"
        warnings:
          - "Some templates could not be attached due to permission issues"
          - "Site assignment failed for 1 out of 3 sites"
    status: "success"
    changed: true
    warnings: 2

# Case 5: Operation failure
response_failed:
  description: Response when wireless profile operations fail.
    Contains error details and information about what failed.
  returned: when operations fail
  type: dict
  sample:
    msg: "Failed to create/update wireless profile: API validation error"
    response:
      - profile_name: "Corporate_Wireless_Profile"
        error: "Invalid SSID configuration: AP Zone SSID names does not exist."
        failed_operation: "profile_creation"
    status: "failed"
    changed: false

# Case 6: Verification failure
response_verification_failed:
  description: Response when profile operations complete but verification fails.
    Indicates the operation may have succeeded but the final state doesn't match expectations.
  returned: when config_verify=true and verification fails
  type: dict
  sample:
    msg: "Profile operation completed but verification failed"
    response:
      - profile_name: "Corporate_Wireless_Profile"
        operation_status: "Network Profile [ff0003b4-adab-4de4-af0e-0cf07d6df07f] Successfully Created"
        verification_error: "Unable to verify the profile doesn't match expected state"
    status: "failed"
    changed: true

"""

import re
import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    validate_list_of_dicts,
    validate_str,
)
from ansible_collections.cisco.dnac.plugins.module_utils.network_profiles import (
    NetworkProfileFunctions,
)


class NetworkWirelessProfile(NetworkProfileFunctions):
    """Class containing member attributes for network profile workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.created, self.deleted, self.not_processed = [], [], []
        self.remove_profile_data, self.already_removed = [], []

        self.keymap = dict(
            profile_name="wirelessProfileName",
            rf_profile_name="rfProfileName",
            sites="sites",
            ssid_name="ssidName",
            wlan_profile_name="wlanProfileName",
            dot11be_profile_name="dot11beProfileId",
            vlan_group_name="vlanGroupName",
            enable_fabric="enableFabric",
            interface_name="interfaceName",
            local_to_vlan="localToVlan",
            anchor_group_name="anchorGroupName",
            policy_profile_name="policyProfileName",
            ap_zone_name="apZoneName",
        )
        self.available_design_types = [
            "AAA_RADIUS_ATTRIBUTES_CONFIGURATION",
            "ADVANCED_SSID_CONFIGURATION",
            "CLEANAIR_CONFIGURATION",
            "DOT11AX_CONFIGURATION",
            "DOT11BE_STATUS_CONFIGURATION",
            "EVENT_DRIVEN_RRM_CONFIGURATION",
            "FLEX_CONFIGURATION",
            "MULTICAST_CONFIGURATION",
            "RRM_FRA_CONFIGURATION",
            "RRM_GENERAL_CONFIGURATION",
        ]

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.

        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.

        Returns:
            The method updates these attributes of the instance:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation ('success' or 'failed').
                - self.validated_config: If successful, validated version of 'config' parameter.
        """
        temp_spec = {
            "profile_name": {"type": "str", "required": True},
            "site_names": {"type": "list", "elements": "str", "required": False},
            "ssid_details": {
                "type": "list",
                "elements": "dict",
                "ssid_name": {"type": "str", "required": True},
                "dot11be_profile_name": {"type": "str", "required": False},
                "enable_fabric": {"type": "bool", "default": False},
                "vlan_group_name": {"type": "str", "required": False},
                "interface_name": {"type": "str", "required": False},
                "anchor_group_name": {"type": "str", "required": False},
                "local_to_vlan": {
                    "type": "int",
                    "range_min": 1,
                    "range_max": 4095,
                    "required": False,
                },
            },
            "ap_zones": {
                "type": "list",
                "elements": "dict",
                "ap_zone_name": {"type": "str", "required": True},
                "rf_profile_name": {"type": "str", "required": True},
                "ssids": {"type": "list", "elements": "str", "required": True},
            },
            "onboarding_templates": {
                "type": "list",
                "elements": "str",
                "required": False,
            },
            "day_n_templates": {"type": "list", "elements": "str", "required": False},
            "additional_interfaces": {
                "type": "list",
                "elements": "dict",
                "interface_name": {"type": "str", "required": True},
                "vlan_id": {
                    "type": "int",
                    "range_min": 1,
                    "range_max": 4095,
                    "required": True,
                },
            },
            "feature_template_designs": {
                "type": "list",
                "elements": "dict",
                "design_type": {"type": "str", "required": False},
                "feature_templates": {
                    "type": "list",
                    "elements": "str",
                    "required": False
                },
                "applicability_ssids": {
                    "type": "list",
                    "elements": "str",
                    "required": False
                },
            },
        }

        if not self.config:
            msg = "The playbook configuration is empty or missing."
            self.set_operation_result("failed", False, msg, "ERROR")
            return self

        # Validate configuration against the specification
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        duplicate_profile = self.find_duplicate_value(self.config, "profile_name")
        if duplicate_profile:
            msg = "profile_name: Duplicate Profile Name(s) '{0}' found in playbook.".format(
                duplicate_profile
            )
            self.result["response"] = msg
            self.set_operation_result(
                "failed", False, msg, "ERROR"
            ).check_return_status()

        if invalid_params:
            msg = "The playbook contains invalid parameters: {0}".format(invalid_params)
            self.result["response"] = msg
            self.set_operation_result(
                "failed", False, msg, "ERROR"
            ).check_return_status()

        self.validated_config = valid_temp
        msg = (
            "Successfully validated playbook configuration parameters using "
            + "'validate_input': {0}".format(str(valid_temp))
        )
        self.log(msg, "INFO")

        return self

    def input_data_validation(self, config):
        """
        Additional validation to check if the provided input wireless profile is correct
        and as per the UI Cisco Catalyst Center.

        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            config (dict): Dictionary containing the wireless profile details.

        Returns:
            self - The current object with input config details

        """
        errormsg = []
        param_spec_str = dict(type="str")

        profile_name = config.get("profile_name")
        if profile_name:
            validate_str(profile_name, param_spec_str, "profile_name", errormsg)
        else:
            errormsg.append("profile_name: Profile Name is missing in playbook.")

        if self.payload.get("state") == "deleted":
            return self

        site_names = config.get("site_names")
        if site_names:
            for sites in site_names:
                validate_str(sites, param_spec_str, "sites", errormsg)
                duplicate_sites = list(
                    set([site for site in site_names if site_names.count(site) > 1])
                )
                if duplicate_sites:
                    errormsg.append(
                        "Duplicate site(s) '{0}' found in site_names".format(
                            duplicate_sites
                        )
                    )
                    break

        ap_zones_list = config.get("ap_zones")
        ssid_list = config.get("ssid_details")
        if ap_zones_list and (not ssid_list or not isinstance(ssid_list, list)):
            errormsg.append(
                "ap_zones: ssid_details missing or invalid to update ap_zones: {0}".format(
                    ap_zones_list
                )
            )

        if ssid_list and isinstance(ssid_list, list):
            self.validate_ssid_info(ssid_list, config, errormsg)

        onboarding_templates = config.get("onboarding_templates")
        day_n_templates = config.get("day_n_templates")
        if onboarding_templates:
            errormsg.append(
                "onboarding_templates: Onboarding templates are currently unavailable due to SDK/API upgrade. "
                "This feature will be available in an upcoming release"
            )
            for template_name in onboarding_templates:
                validate_str(
                    template_name, param_spec_str, "onboarding_templates", errormsg
                )
                duplicate_template = list(
                    set(
                        [
                            template
                            for template in onboarding_templates
                            if onboarding_templates.count(template) > 1
                        ]
                    )
                )
                if duplicate_template:
                    errormsg.append(
                        "Duplicate template(s) '{0}' found in onboarding_templates".format(
                            duplicate_template
                        )
                    )
                    break

                if day_n_templates and template_name in day_n_templates:
                    errormsg.append(
                        "Onboarding_templates: Duplicate template "
                        + "'{0}' found in day_n_templates".format(template_name)
                    )
                    break

        if day_n_templates:
            for template_name in day_n_templates:
                validate_str(template_name, param_spec_str, "day_n_templates", errormsg)
                duplicate_template = list(
                    set(
                        [
                            template
                            for template in day_n_templates
                            if day_n_templates.count(template) > 1
                        ]
                    )
                )
                if duplicate_template:
                    errormsg.append(
                        "Duplicate template(s) '{0}' found in day_n_templates".format(
                            duplicate_template
                        )
                    )
                    break

        additional_interfaces = config.get("additional_interfaces")
        if additional_interfaces:
            duplicate_interfaces = self.find_duplicate_value(
                additional_interfaces, "interface_name"
            )
            if duplicate_interfaces:
                msg = "interface_name: Duplicate interface name(s) '{0}' found in playbook.".format(
                    duplicate_interfaces
                )
                errormsg.append(msg)

            for interface in additional_interfaces:
                interface_name = interface.get("interface_name")
                if interface_name:
                    validate_str(
                        interface_name,
                        dict(type="str", length_max=31),
                        "interface_name",
                        errormsg,
                    )
                else:
                    errormsg.append(
                        "interface_name: additional_interfaces of Interface Name is missing in playbook."
                    )

                vlan_id = interface.get("vlan_id")
                if vlan_id is not None:
                    try:
                        vlan_id = int(vlan_id)
                        if vlan_id not in range(1, 4095):
                            errormsg.append(
                                "vlan_id: Invalid Additional Interface VLAN ID '{0}' in playbook.".format(
                                    vlan_id
                                )
                            )
                    except ValueError:
                        errormsg.append(
                            "vlan_id: VLAN ID '{0}' must be an integer.".format(vlan_id)
                        )
                else:
                    errormsg.append(
                        "vlan_id: VLAN ID of Interface is missing in playbook."
                    )

        if errormsg:
            msg = "Invalid parameters in playbook config: '{0}' ".format(errormsg)
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

        msg = "Successfully validated config params: {0}".format(str(config))
        self.log(msg, "INFO")
        return self

    def validate_ssid_info(self, ssid_list, config, errormsg):
        """
        Extends validation for SSID Details.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            ssid_list (list): List of dictionaries containing SSID details.
            errormsg(list) - List contains error message any validation failure.

        """
        self.log("Starting SSID validation...", "DEBUG")
        for ssid_details in ssid_list:
            ssid_name = ssid_details.get("ssid_name")
            if not ssid_name:
                errormsg.append("ssid_name: ssid name is missing in playbook.")
            else:
                self.log("Validating ssid_name: {0}".format(ssid_name), "DEBUG")
                param_spec = dict(type="str", length_max=32)
                validate_str(ssid_name, param_spec, "ssid_name", errormsg)

            enable_fabric = ssid_details.get("enable_fabric")
            if enable_fabric and enable_fabric not in (True, False):
                errormsg.append(
                    "enable_fabric: Invalid enable fabric '{0}' in playbook. either true or false.".format(
                        enable_fabric
                    )
                )

            dot11be_profile_name = ssid_details.get("dot11be_profile_name")
            if dot11be_profile_name:
                param_spec = dict(type="str", length_max=32)
                validate_str(
                    dot11be_profile_name, param_spec, "dot11be_profile_name", errormsg
                )

            if not enable_fabric:
                vlan_group_name = ssid_details.get("vlan_group_name")
                if vlan_group_name:
                    param_spec = dict(type="str", length_max=32)
                    validate_str(
                        vlan_group_name, param_spec, "vlan_group_name", errormsg
                    )

                interface_name = ssid_details.get("interface_name")
                if interface_name:
                    param_spec = dict(type="str", length_max=31)
                    validate_str(interface_name, param_spec, "interface_name", errormsg)

                anchor_group_name = ssid_details.get("anchor_group_name")
                if anchor_group_name:
                    param_spec = dict(type="str", length_max=32)
                    validate_str(
                        anchor_group_name, param_spec, "anchor_group_name", errormsg
                    )

                local_to_vlan = ssid_details.get("local_to_vlan")
                if (
                    local_to_vlan
                    and local_to_vlan not in range(1, 4095)
                    and interface_name
                ):
                    errormsg.append(
                        "local_to_vlan: Invalid local vlan number '{0}' in playbook.".format(
                            local_to_vlan
                        )
                    )

                if not (vlan_group_name or interface_name):
                    errormsg.append(
                        "Either VLAN Group Name or Interface Name required in playbook."
                    )

                if anchor_group_name:
                    if vlan_group_name and interface_name:
                        errormsg.append(
                            "If the SSID includes an anchor group name, "
                            + "either vlan group name or interface name must "
                            + "be specified, but not necessarily both"
                        )

                if vlan_group_name and interface_name:
                    errormsg.append(
                        "Either vlan group name or interface name must "
                        + "be specified, but not necessarily both"
                    )

                if vlan_group_name and local_to_vlan:
                    errormsg.append(
                        "Either vlan group name or Local to vlan must "
                        + "be specified, but not necessarily both"
                    )

        ap_zone_list = config.get("ap_zones")
        if ap_zone_list and isinstance(ap_zone_list, list):
            duplicate_zone_name = self.find_duplicate_value(
                ap_zone_list, "ap_zone_name"
            )
            if duplicate_zone_name:
                msg = "ap_zone_name: Duplicate AP zone name(s) '{0}' found in playbook.".format(
                    duplicate_zone_name
                )
                errormsg.append(msg)

            if len(ap_zone_list) > 100:
                errormsg.append(
                    "ap_zones: AP zones list is more than 100 entries in playbook."
                )
            else:
                for ap_zones in ap_zone_list:
                    if ap_zones:
                        self.validate_ap_zone(ap_zones, ssid_list, errormsg)

        feature_template_designs = config.get("feature_template_designs")
        if feature_template_designs:
            self.validate_feature_templates(feature_template_designs, ssid_list, errormsg)

    def validate_ap_zone(self, ap_zones, ssid_list, errormsg):
        """
        Extends validation for AP zone values.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            ap_zones (dict) - Contains AP zone data given from playbook
            ssid_list (list) - Contains list of dict contains SSID details to validate AP
                               zone SSID

        Returns:
            No return, collect the error message in case of any validation failure.
        """
        self.log("Starting AP Zone validation...", "DEBUG")

        ap_zone_name = ap_zones.get("ap_zone_name")
        if ap_zone_name:
            param_spec = dict(type="str", length_max=32)
            validate_str(ap_zone_name, param_spec, "ap_zone_name", errormsg)
        else:
            errormsg.append("ap_zone_name: AP Zone Name is missing in playbook.")

        rf_profile_name = ap_zones.get("rf_profile_name")
        if rf_profile_name:
            param_spec = dict(type="str", length_max=30)
            validate_str(rf_profile_name, param_spec, "rf_profile_name", errormsg)
        else:
            errormsg.append("rf_profile_name: RF Profile name is missing in playbook.")

        device_tags = ap_zones.get("device_tags")
        if device_tags:
            for device_tag in device_tags:
                param_spec = dict(type="str", length_max=30)
                validate_str(device_tag, param_spec, "device_tag", errormsg)

        ssids = ap_zones.get("ssids")
        if not ssids:
            errormsg.append("ssids: ssids is missing on ap_zones in playbook.")
            return

        if not isinstance(ssids, list):
            errormsg.append("ssids: Expected a list, but got a non-list value.")
            return

        if len(ssids) > 16:
            errormsg.append(
                "ssids: List contains more than 16 entries, which exceeds the allowed limit."
            )
            return

        for ap_ssid in ssids:
            param_spec = dict(type="str", length_max=32)
            validate_str(ap_ssid, param_spec, "ap_ssid", errormsg)
            ssid_exists = any(ap_ssid in zone.values() for zone in ssid_list)
            if not ssid_exists:
                zone_msg = (
                    "ssids: AP Zone SSID: {0} : {1} not exist in ssid_details.".format(
                        ap_ssid, ssid_exists
                    )
                )
                errormsg.append(zone_msg)

    def validate_feature_templates(self, feature_template_designs, ssid_list, errormsg):
        """
        Validate feature templates provided in the playbook configuration.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            feature_template_designs (list): List of dictionaries containing feature template details.
            ssid_list (list): List of dictionaries containing SSID details.
            errormsg (list): List to collect error messages in case of validation failures.

        Returns:
            None: This function updates the errormsg list directly if any validation errors are found.
        """
        self.log("Validating feature template configurations for wireless network profile template assignment", "DEBUG")
        self.log("Processing {0} feature templates for validation against wireless profile requirements".format(
            len(feature_template_designs) if isinstance(feature_template_designs, list) else 0), "DEBUG")

        if not isinstance(feature_template_designs, list):
            errormsg.append("feature_template_designs: Expected a list, but got a non-list value.")
            return None

        if len(feature_template_designs) > 500:
            errormsg.append(
                "feature_template_designs: List contains more than 500 entries, which exceeds the allowed limit."
            )
            return None

        if feature_template_designs \
           and self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") < 0:
            errormsg.append(
                "The specified version '{0}' does not support for feature template."
                "Supported version(s) start from '3.1.3.0' onwards.".format(
                    self.get_ccc_version())
            )
            return None

        self.log("Feature template basic validation passed - proceeding with detailed template configuration validation", "DEBUG")

        # Track validation statistics for operational visibility
        templates_processed = 0
        templates_with_errors = 0
        advanced_ssid_templates_found = 0
        default_design_templates_found = 0
        for feature_template_design in feature_template_designs:
            templates_processed += 1
            template_has_errors = False

            self.log("Validating feature template design configuration {0}/{1}".format(
                templates_processed, len(feature_template_designs)), "DEBUG")

            # Validate design type configuration
            design_type = feature_template_design.get("design_type")
            if design_type:
                validate_str(
                    design_type,
                    dict(type="str"),
                    "design_type",
                    errormsg,
                )

                # Validate design type against supported categories
                if design_type not in self.available_design_types:
                    errormsg.append(
                        "design_type: Invalid design type '{0}' in playbook. "
                        "Available design types are: {1}".format(
                            design_type, self.available_design_types
                        )
                    )
                    template_has_errors = True
                    self.log("Design type validation failed for '{0}' - not in supported design types".format(design_type), "ERROR")
            else:
                errormsg.append("design_type: Design type is missing in feature template configuration.")
                template_has_errors = True

            feature_templates = feature_template_design.get("feature_templates", [])
            if not feature_templates:
                errormsg.append(
                    "feature_templates: 'feature_templates' is missing in feature_template_design."
                )
                template_has_errors = True
            elif not isinstance(feature_templates, list):
                errormsg.append(
                    "feature_templates: Expected a list for 'feature_templates', but got a non-list value."
                )
                template_has_errors = True
            else:
                # Validate each template design entry
                for design in feature_templates:
                    if not isinstance(design, str):
                        errormsg.append(
                            "feature_templates: Expected a string for each item in 'feature_templates', but got a non-string value."
                        )
                        template_has_errors = True
                    elif "Default Advanced SSID Design" in feature_templates and len(feature_templates) > 1:
                        default_design_templates_found += 1
                        if len(feature_templates) > 1:
                            errormsg.append(
                                "feature_templates: 'Default Advanced SSID Design' is a special case and should be the only " +
                                "template design in feature_template_designs. " +
                                "Please remove other template designs if 'Default Advanced SSID Design' is used."
                            )
                            template_has_errors = True
                            self.log("Default Advanced SSID Design validation failed - cannot be combined with other designs", "ERROR")

            applicability_ssids = feature_template_design.get("applicability_ssids", [])
            if applicability_ssids:
                self.log("Validating SSID applicability for {0} SSIDs".format(
                    len(applicability_ssids)), "DEBUG")
                if "Default Advanced SSID Design" not in feature_templates:
                    errormsg.append(
                        "applicability_ssids: 'applicability_ssids' should only be used with 'Default Advanced SSID Design' template design."
                    )
                    template_has_errors = True

                if len(applicability_ssids) > 16:
                    errormsg.append(
                        "applicability_ssids: List contains more than 16 entries, which exceeds the allowed limit."
                    )
                    template_has_errors = True

                for feature_ssid in applicability_ssids:
                    if not isinstance(feature_ssid, str):
                        errormsg.append(
                            "applicability_ssids: Expected a string for each item in 'applicability_ssids', but got a non-string value."
                        )
                        template_has_errors = True
                    else:
                        validate_str(feature_ssid,
                                     dict(type="str", length_max=32),
                                     "applicability_ssids", errormsg)

                        # Cross-reference SSID with ssid_details
                        if not self.value_exists(ssid_list, "ssid_name", feature_ssid):
                            errormsg.append(
                                "applicability_ssids: SSID '{0}' does not exist in ssid_details.".format(
                                    feature_ssid
                                )
                            )
                            template_has_errors = True
                            self.log("SSID applicability validation failed - SSID '{0}' not found in ssid_details".format(
                                feature_ssid), "ERROR")

            if template_has_errors:
                templates_with_errors += 1

            self.log("Checking for duplicate template designs across feature template configurations", "DEBUG")

            duplicates, matches = self.find_duplicates_in_feature_templates(feature_template_designs)
            if duplicates or matches:
                errormsg.append(
                    "feature_templates: Duplicate feature_template '{0} {1}' found in playbook.".format(
                        str(duplicates), str(matches)
                    )
                )
                self.log("Duplicate feature_template validation failed - found duplicates: {0} {1}".format(
                    str(duplicates), str(matches)), "ERROR")

        if templates_with_errors > 0:
            self.log("Feature template validation completed with errors - {0}/{1} templates failed validation".format(
                templates_with_errors, templates_processed), "WARNING")
        else:
            self.log("Feature template validation completed successfully - all {0} templates passed validation".format(
                templates_processed), "INFO")

        if advanced_ssid_templates_found > 0:
            self.log("Advanced SSID Configuration templates found: {0}".format(
                advanced_ssid_templates_found), "INFO")

        if default_design_templates_found > 0:
            self.log("Default Advanced SSID Design templates found: {0}".format(
                default_design_templates_found), "INFO")

    def find_duplicates_in_feature_templates(self, feature_template_designs):
        """
        Checks for duplicate entries within each 'feature_templates' list in the provided feature templates,
        and identifies dictionaries with identical 'feature_templates' lists.

        Args:
            feature_template_designs (list of dict): A list where each dictionary contains at least the key
                'feature_templates', which is expected to be a list of template identifiers.

        Returns:
            tuple:
                - List[dict]: Dictionaries from feature_template_designs that contain duplicate entries within
                              their 'feature_templates' list.
                - List[Tuple[int, int]]: Pairs of indices from feature_template_designs where
                                         the 'feature_templates' lists are identical.

        Notes:
            - A 'duplicate' within a 'feature_templates' means the same template identifier
              appears more than once in the list.
            - 'Matching' means two different dictionaries have exactly the same
              'feature_templates' list (order matters).
        """
        self.log("Analyzing feature template configurations for duplicate feature_templates and identical feature_templates lists", "DEBUG")
        self.log("Processing {0} feature templates for duplicate detection analysis".format(
            len(feature_template_designs)), "DEBUG")

        duplicates_found = []
        matching_indices = []
        combine_designs = []

        templates_processed = 0
        intra_template_duplicates = 0
        inter_template_duplicates = 0
        identical_lists_found = 0

        # Track seen template design lists for identical list detection
        seen_template_designs = {}
        global_template_designs = []

        # Process each feature template for duplicate detection
        for template_index, feature_template_design in enumerate(feature_template_designs):
            templates_processed += 1
            template_design_list = feature_template_design.get('feature_templates', [])

            self.log("Analyzing feature template {0}/{1} with {2} feature templates".format(
                template_index + 1, len(feature_template_designs), len(template_design_list)), "DEBUG")

            # Check for intra-template duplicates (within same feature_templates list)
            if len(template_design_list) != len(set(template_design_list)):
                intra_template_duplicates += 1
                duplicates_found.append(feature_template_design)
                self.log("Intra-template duplicate detected in feature_templates at index {0}: {1}".format(
                    template_index, template_design_list), "DEBUG")

            # Check for identical feature_templates lists across feature templates
            template_design_tuple = tuple(template_design_list)
            if template_design_tuple in seen_template_designs:
                identical_lists_found += 1
                matching_indices.append((seen_template_designs[template_design_tuple], template_index))
                self.log("Identical feature_templates lists found between indices {0} and {1}: {2}".format(
                    seen_template_designs[template_design_tuple], template_index, template_design_list), "DEBUG")
            else:
                seen_template_designs[template_design_tuple] = template_index

            # Check for inter-template duplicates (same design across different templates)
            for feature_template in template_design_list:
                if feature_template in global_template_designs:
                    inter_template_duplicates += 1
                    if feature_template_design not in duplicates_found:
                        duplicates_found.append(feature_template_design)
                    self.log("Inter-template duplicate design '{0}' found in feature template at index {1}".format(
                        feature_template, template_index), "DEBUG")
                else:
                    global_template_designs.append(feature_template)

        total_duplicates = len(duplicates_found)
        total_matches = len(matching_indices)

        if total_duplicates > 0 or total_matches > 0:
            self.log("Duplicate detection completed - found {0} templates with duplicates and {1} identical template lists".format(
                total_duplicates, total_matches), "WARNING")

            if intra_template_duplicates > 0:
                self.log("Intra-template duplicates found in {0} feature templates".format(
                    intra_template_duplicates), "WARNING")

            if inter_template_duplicates > 0:
                self.log("Inter-template duplicate designs detected: {0} occurrences".format(
                    inter_template_duplicates), "WARNING")

            if identical_lists_found > 0:
                self.log("Identical template design lists found: {0} matches".format(
                    identical_lists_found), "WARNING")

            return duplicates_found, matching_indices

        self.log("Duplicate detection completed successfully - no duplicates or identical lists found in {0} feature templates".format(
            templates_processed), "INFO")

        return None, None

    def get_want(self, config):
        """
        Retrieve wireless network profile or delete profile from playbook configuration.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing network profile details.

        Returns:
            self: The current instance of the class with updated 'want' attributes.

        Description:
            This function parses the playbook configuration to extract information
            related to network profile. It stores these details in the 'want' dictionary
            for later use in the Ansible module.
        """
        want = {}

        self.log("Validating input data before proceeding...", "DEBUG")
        self.input_data_validation(config).check_return_status()
        self.log(
            "Input data validation successful. Extracting wireless profile details.",
            "DEBUG",
        )

        want["wireless_profile"] = config
        self.want = want
        self.log("Desired State (want): {0}".format(self.pprint(self.want)), "INFO")

        return self

    def get_have(self, config):
        """
        Get required details for the given profile config from Cisco Catalyst Center

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict) - Playbook details containing network profile

        Returns:
            self - The current object with ssid info, template validate site id
            information collection for profile update.
        """

        self.have["wireless_profile"], self.have["wireless_profile_list"] = {}, []
        offset = 1
        limit = int(self.payload.get("offset_limit", 500))

        while True:
            profiles = self.get_network_profile("Wireless", offset, limit)
            if not profiles:
                self.log(
                    "No data received from API (Offset={0}). Exiting pagination.".format(
                        offset
                    ),
                    "DEBUG",
                )
                break

            self.log(
                "Received {0} profile(s) from API (Offset={1}).".format(
                    len(profiles), offset
                ),
                "DEBUG",
            )
            self.have["wireless_profile_list"].extend(profiles)

            if len(profiles) < limit:
                self.log(
                    "Received less than limit ({0}) results, assuming last page. Exiting pagination.".format(
                        limit
                    ),
                    "DEBUG",
                )
                break

            offset += limit  # Increment offset for pagination
            self.log(
                "Incrementing offset to {0} for next API request.".format(offset),
                "DEBUG",
            )

        if self.have["wireless_profile_list"]:
            self.log(
                "Total {0} profile(s) retrieved for 'Wireless': {1}.".format(
                    len(self.have["wireless_profile_list"]),
                    self.pprint(self.have["wireless_profile_list"]),
                ),
                "DEBUG",
            )
        else:
            self.log("No existing wireless profile(s) found.", "WARNING")

        profile_info = {}
        profile_name = config.get("profile_name")
        if profile_name:
            self.log(
                "Checking if profile '{0}' exists in retrieved profiles.".format(
                    profile_name
                ),
                "DEBUG",
            )

            if self.value_exists(
                self.have["wireless_profile_list"], "name", profile_name
            ):
                profile_info["profile_info"] = self.get_wireless_profile(profile_name)
                self.log(
                    "Fetched wireless profile details for '{0}': {1}".format(
                        profile_name, profile_info["profile_info"]
                    ),
                    "DEBUG",
                )

        if self.payload.get("state") == "deleted":
            if not self.value_exists(
                self.have["wireless_profile_list"], "name", profile_name
            ):
                self.msg = "Profile: {0} already deleted or does not exist.".format(
                    profile_name
                )
                self.log(self.msg, "INFO")
                self.set_operation_result(
                    "success", False, self.msg, "INFO"
                ).check_return_status()
                return self

            self.have["wireless_profile"] = profile_info

        self.log(
            "Validating site template existence for config: {0}".format(config), "DEBUG"
        )
        self.check_site_template(config, profile_info)

        ssid_details = config.get("ssid_details")
        ssid_for_apzone = []
        if ssid_details:
            ssid_response = []

            for each_ssid in ssid_details:
                if each_ssid:
                    each_ssid_response = {}
                    self.log("Check Site ID exist in for global for SSID", "INFO")
                    site_exist, site_id = self.get_site_id("global")

                    if site_exist:
                        self.log(
                            "Collect SSID details for global: {0}".format(site_id),
                            "INFO",
                        )
                        global_ssid_list = self.get_ssid_details(site_id, "global")

                        self.log(
                            "Check given ssid exist for: {0}".format(
                                each_ssid.get("ssid_name")
                            ),
                            "INFO",
                        )
                        ssid_exist, ssid_info = self.check_ssid_details(
                            each_ssid.get("ssid_name"), global_ssid_list
                        )

                        each_ssid_response["ssid_exist"] = ssid_exist
                        each_ssid_response["ssid_response"] = ssid_info
                        each_ssid["wlan_profile_name"] = ssid_info["wlan_profile_name"]
                        each_ssid["policy_profile_name"] = ssid_info[
                            "policy_profile_name"
                        ]

                    ssid_response.append(each_ssid_response)
                    ssid_for_apzone.append(each_ssid["ssid_name"])

            if ssid_response:
                profile_info["ssid_response"] = ssid_response

        ap_zones = config.get("ap_zones")
        if ap_zones:
            self.log("Fetching AP zone information.", "DEBUG")
            self.get_ap_zone_info(ap_zones, ssid_for_apzone, profile_info)

        additional_interfaces = config.get("additional_interfaces")
        if additional_interfaces:
            self.log("Fetching additional interface information.", "DEBUG")
            self.get_additional_interface_info(additional_interfaces, profile_info)

        feature_template_designs = config.get("feature_template_designs")
        if feature_template_designs \
           and self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") >= 0:
            self.log("Fetching feature template information.", "DEBUG")
            self.get_feature_template_info(feature_template_designs, profile_info)

        onboarding_templates = config.get("onboarding_templates")
        day_n_templates = config.get("day_n_templates")
        profile_id = profile_info.get("profile_info", {}).get("id")
        template_detail = []
        if (onboarding_templates or day_n_templates) and profile_id:
            self.log(
                "Getting templates for the profile: {0}: {1}".format(
                    profile_name, self.pprint(profile_info.get("profile_info"))
                ),
                "INFO",
            )
            profile_info["profile_id"] = profile_id
            template_detail = self.get_templates_for_profile(profile_id)
            if template_detail:
                profile_info["previous_templates"] = template_detail

        temp_status, unmatch = self.compare_config_with_sites_templates(
            config, template_detail, "template"
        )
        profile_info["template_compare_stat"] = True
        profile_info["template_compare_unmatched"] = None
        if not temp_status:
            self.log(
                "Template comparison failed for profile: {0}. Unmatched items: {1}".format(
                    profile_name, unmatch
                ),
                "WARNING",
            )
            profile_info["template_compare_stat"] = False
            profile_info["template_compare_unmatched"] = unmatch
        else:
            self.log(
                "Template comparison successful for profile: {0}".format(profile_name),
                "INFO",
            )

        self.log("Getting site list for the profile: {0}".format(profile_name), "INFO")
        site_status = None
        site_list = []
        if profile_id:
            site_list = self.get_site_lists_for_profile(profile_name, profile_id)
            self.log(
                "Site list fetched for profile_id {0}: {1}".format(
                    profile_id, site_list
                ),
                "DEBUG",
            )
        else:
            self.log(
                "Profile ID not available. Skipping site list fetch for profile: {0}".format(
                    profile_name
                ),
                "DEBUG",
            )

        if site_list:
            self.log(
                "Received Site List: {0} for config: {1}.".format(site_list, config),
                "INFO",
            )
            profile_info["previous_sites"] = site_list
        else:
            self.log(
                "No site list associated with profile: {0}".format(profile_name),
                "DEBUG",
            )

        if site_list and not profile_info.get("site_response"):
            self.log(
                "No site response found for profile: {0}. Assuming site comparison passed.".format(
                    profile_name
                ),
                "INFO",
            )
            profile_info["site_compare_stat"] = True
            profile_info["site_compare_unmatched"] = None

        if site_list and profile_info.get("site_response"):
            site_status, unmatch = self.compare_config_with_sites_templates(
                profile_info["site_response"], site_list, "sites"
            )
            profile_info["site_compare_stat"] = True
            profile_info["site_compare_unmatched"] = None
            if not site_status:
                profile_info["site_compare_stat"] = False
                profile_info["site_compare_unmatched"] = unmatch
                self.log(
                    "Site comparison failed for profile: {0}. Unmatched sites: {1}".format(
                        profile_name, unmatch
                    ),
                    "WARNING",
                )
            else:
                self.log(
                    "Site comparison successful for profile: {0}".format(profile_name),
                    "INFO",
                )

        if not site_list and not profile_info.get("site_response"):
            profile_info["site_compare_stat"] = True
            profile_info["site_compare_unmatched"] = None
            self.log(
                "No site list or site response found. Assuming site comparison passed for profile: {0}".format(
                    profile_name
                ),
                "INFO",
            )

        self.log("Collected Required data, now compare Configuration Data", "INFO")
        if profile_info.get("profile_info"):
            profile_stat, unmatched = self.compare_config_data(config, profile_info)
            profile_info["profile_compare_stat"] = False
            if profile_stat:
                profile_info["profile_compare_stat"] = True
            profile_info["profile_compare_unmatched"] = unmatched

        have_profile_name = profile_info.get("profile_info", {}).get(
            "wirelessProfileName"
        )
        # Check if there are no additional configurations and profile names match
        if have_profile_name == profile_name and not any(
            config.get(key)
            for key in [
                "ssid_details",
                "ap_zones",
                "site_names",
                "additional_interfaces",
                "onboarding_templates",
                "day_n_templates",
                "feature_template_designs",
            ]
        ):
            self.log(
                "No additional configurations found. Profile names match.", "DEBUG"
            )
            profile_info["profile_compare_stat"] = True
            profile_info["profile_compare_unmatched"] = None

        self.have["wireless_profile"] = profile_info

        if not self.have["wireless_profile"]:
            self.msg = (
                "No wireless profile data found for given configuration: {0}".format(
                    config
                )
            )
            self.log(self.msg, "DEBUG")

        self.log("Current State (have): {0}".format(self.pprint(self.have)), "INFO")
        self.msg = "Successfully retrieved the details from the system"
        self.status = "success"
        return self

    def get_ap_zone_info(self, ap_zones, ssid_for_apzone, profile_info):
        """
        This function extending the get have function to get details for AP Zone details

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            ap_zones (list): A List of dict containing AP Zone name, rf profile and SSIDs.
            ssid_for_apzone (list): A List contains SSID list given on SSID section in playbook
            profile_info (dict): A dict contain AP zone informations

        Returns:
            No return, Contains the information of AP zone and to parse ot the profile_info
        """
        try:
            if not ap_zones:
                self.log("No AP Zones provided in the configuration.", "DEBUG")
                return

            self.log("Starting AP Zone comparison.", "INFO")
            apzone_response = []
            for each_ap_zone in ap_zones:
                if each_ap_zone.get("ssids"):
                    each_apzone_response = []
                    for sub_ap_zone in each_ap_zone.get("ssids"):
                        if sub_ap_zone in ssid_for_apzone:
                            each_apzone_response.append(sub_ap_zone)
                    if len(each_apzone_response) == len(each_ap_zone.get("ssids")):
                        apzone_response.append(each_ap_zone.get("ssids"))
            if len(apzone_response) == len(ap_zones):
                profile_info["apzone_change_required"] = False
            else:
                profile_info["apzone_change_required"] = True
        except Exception as e:
            msg = "An error occurred during compare AP Zone: {0}".format(str(e))
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

    def get_additional_interface_info(self, additional_interfaces, profile_info):
        """
        This function extending the get have function to get details for
        additional interface information

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            additional_interfaces (list): A List of dict containing interface names and Vlan ids.
            profile_info (dict): A dict contain additional interface information with status

        Returns:
            No return, Contains the information about the Additional interface details to add to
            profile_info
        """
        self.log(
            "Get the Additional interface details for: {0}".format(
                additional_interfaces
            ),
            "DEBUG",
        )
        try:
            if not additional_interfaces:
                self.log(
                    "No additional interfaces provided in the configuration.", "DEBUG"
                )
                return

            self.log(
                "Fetching additional interface details: {0}".format(
                    additional_interfaces
                ),
                "INFO",
            )
            all_interfaces = []

            for each_interface in additional_interfaces:
                interface = each_interface.get("interface_name")
                vlan_id = each_interface.get("vlan_id")

                if not interface or not vlan_id:
                    self.log(
                        "Skipping invalid interface entry: {0}".format(each_interface),
                        "WARNING",
                    )
                    continue

                self.log(
                    "Checking additional interface: {0} (VLAN {1})".format(
                        interface, vlan_id
                    ),
                    "DEBUG",
                )
                check_response = self.additional_interface_check_or_create(
                    interface, vlan_id
                )
                all_interfaces.append(
                    {
                        "interface_name": interface,
                        "vlan_id": vlan_id,
                        "exist": bool(check_response),
                    }
                )

            profile_info["additional_interfaces"] = all_interfaces
            self.log(
                "Collected additional interface details: {0}".format(all_interfaces),
                "INFO",
            )

        except Exception as e:
            msg = "An error occurred during get Additional interface: {0}".format(
                str(e)
            )
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

    def additional_interface_check_or_create(self, interface, vlan_id):
        """
        This function used to check the interface and vlan exist if not exist
        then need to be created.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            interface (str): A string containing interface name.
            vlan_id (int): A integer contains Vlan ID from 1 to 4094

        Returns:
            matched (bool): Update True or False if additional interface match with input.
        """
        self.log(
            "Check the interface name: {0} vlan: {1}".format(interface, vlan_id), "INFO"
        )
        payload = {
            "limit": 500,
            "offset": 1,
            "interface_name": interface,
            "vlan_id": vlan_id,
        }
        try:
            interfaces = self.execute_get_request(
                "wireless", "get_interfaces", payload
            )
            if interfaces and isinstance(interfaces.get("response"), list):
                self.log(
                    "Interface {0} with VLAN {1} already exists.".format(
                        interface, vlan_id
                    ),
                    "DEBUG",
                )
                return True

            self.log(
                "Interface {0} with VLAN {1} not found. Creating...".format(
                    interface, vlan_id
                ),
                "INFO",
            )

            self.log(
                "Creating new Interface and Vlan : {0} Vlan: {1}".format(
                    interface, vlan_id
                ),
                "INFO",
            )
            payload = {"interfaceName": interface, "vlanId": vlan_id}
            task_details = self.execute_process_task_data(
                "wireless", "create_interface", payload
            )
            if task_details:
                self.log(
                    "Successfully created interface {0} with VLAN {1}.".format(
                        interface, vlan_id
                    ),
                    "INFO",
                )
                return True

            self.log(
                "Failed to create interface {0} with VLAN {1}.".format(
                    interface, vlan_id
                ),
                "ERROR",
            )
            self.fail_and_exit("Unable to create interface: {0}".format(payload))

        except Exception as e:
            msg = "An error occurred during Additional interface Check: {0}".format(
                str(e)
            )
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

    def get_feature_template_info(self, feature_template_designs, profile_info):
        """
        Retrieve feature template configuration details for wireless network profile management.

        This method queries the Catalyst Center wireless API to collect comprehensive feature
        template information including template designs, device types, and SSID applicability
        for specified feature template configurations. It processes template mappings to retrieve
        design identifiers and SSID associations essential for wireless network profile
        feature template assignment and configuration management.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            feature_template_designs (list): List of dictionaries containing feature template configurations.
                                    Format: [{"design_type": "AAA_RADIUS_ATTRIBUTES_CONFIGURATION",
                                            "feature_templates": ["design1", "design2"],
                                            "applicability_ssids": ["SSID1", "SSID2"]}]
                                    Each dictionary contains design type, template designs,
                                    and optional SSID applicability.
            profile_info (dict): Dictionary to store collected feature template information.
                                Updated with "feature_template_designs" key containing template details
                                for wireless profile configuration processing.

        Returns:
            None: This method updates the profile_info dictionary directly with feature template
            details. Returns None if no templates found or if errors occur during processing.

            Note:
                Feature template information is essential for wireless profile configuration
                and defines how specific wireless features are applied to network profiles
                and associated SSIDs within the Catalyst Center wireless infrastructure.
        """
        self.log("Retrieving feature template configuration details for wireless network profile management", "DEBUG")
        self.log("Processing {0} feature template configurations for template design collection".format(
            len(feature_template_designs)), "DEBUG")

        if not feature_template_designs:
            self.log("No feature template designs provided for template information retrieval - returning without processing", "DEBUG")
            return None

        all_template_details = []
        templates_processed = 0
        designs_collected = 0
        templates_with_errors = 0

        try:
            for feature_template_design in feature_template_designs:
                templates_processed += 1

                design_type = feature_template_design.get("design_type")
                feature_templates = feature_template_design.get("feature_templates", [])

                self.log("Processing feature template {0}/{1} with design type '{2}' and {3} feature templates".format(
                    templates_processed, len(feature_template_designs), design_type, len(feature_templates)), "DEBUG")

                if not design_type:
                    self.log("Design type missing in feature template configuration - skipping template", "WARNING")
                    continue

                if not feature_templates or not isinstance(feature_templates, list):
                    self.log("Feature templates missing or invalid in feature template configuration - skipping template", "WARNING")
                    continue

                payload_template = {"type": design_type}

                # Process each template design within the feature template
                for feature_template in feature_templates:
                    payload_template["design_name"] = feature_template

                    self.log("Querying feature template design '{0}' for design type '{1}'".format(
                        feature_template, design_type), "DEBUG")

                    try:
                        design_response = self.execute_get_request(
                            "wireless", "get_feature_template_summary", payload_template
                        )

                        self.log("Feature template design query completed for '{0}'".format(
                            feature_template), "DEBUG")

                        # Validate and process template design response
                        if design_response and isinstance(design_response.get("response"), list):
                            response_data = design_response.get("response", [])

                            if response_data and len(response_data) > 0:
                                instances = response_data[0].get("instances", [])

                                if instances and len(instances) > 0:
                                    design_id = instances[0].get("id")

                                    if design_id:
                                        designs_collected += 1
                                        template_detail = {
                                            "design_id": design_id,
                                            "design_name": feature_template,
                                            "design_type": design_type
                                        }

                                        # Add SSID applicability if specified
                                        applicability_ssids = feature_template_design.get("applicability_ssids")
                                        if applicability_ssids:
                                            template_detail["ssids"] = applicability_ssids
                                            self.log("Added SSID applicability for feature templates '{0}': {1}".format(
                                                feature_template, applicability_ssids), "DEBUG")

                                        all_template_details.append(template_detail)
                                        self.log("Feature template design '{0}' collected successfully with ID '{1}'".format(
                                            feature_template, design_id), "DEBUG")
                                    else:
                                        self.log("No design ID found in template response for '{0}'".format(
                                            feature_template), "WARNING")
                                else:
                                    self.log("No instances found in template response for '{0}'".format(
                                        feature_template), "WARNING")
                            else:
                                self.log("Empty response data received for feature template '{0}'".format(
                                    feature_template), "WARNING")
                        else:
                            self.log("Invalid or empty response received for feature template '{0}'".format(
                                feature_template), "WARNING")

                    except Exception as design_exception:
                        templates_with_errors += 1
                        self.log("Failed to retrieve feature template design '{0}': {1}".format(
                            feature_template, str(design_exception)), "ERROR")

            # Update profile_info with collected template details
            if all_template_details:
                profile_info["feature_template_designs"] = all_template_details
                self.log("Feature template information collection completed - collected {0} template designs from {1} feature templates".format(
                    designs_collected, templates_processed), "INFO")

                if templates_with_errors > 0:
                    self.log("Warning: {0} template designs encountered errors during collection".format(
                        templates_with_errors), "WARNING")

                return self

            self.log("No feature template designs found for the provided feature template configurations", "DEBUG")
            return None

        except Exception as api_exception:
            error_message = "Failed to retrieve feature template information: {0}".format(str(api_exception))
            self.log(error_message, "ERROR")
            return None

    def compare_config_data(self, input_config, have_info):
        """
        This function used to compare the playbook input with the have data and
        return the status and unmatch value

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            input_config (dict): A dict containing playbook config of wireless profile.
            have_prof_info (dict): A string contain the profile response from have function

        Returns:
            matched (bool): Update True or False if input match with the have data
            dict or None: A dict contain unmatched kay value pair
        """
        self.log(
            "Compare the input config: {0} with have: {1}".format(
                self.pprint(input_config), self.pprint(have_info)
            ),
            "INFO",
        )
        unmatched_keys = []
        have_prof_info = have_info.get("profile_info")
        ssid_list = input_config.get("ssid_details", [])
        have_ssid_details = have_prof_info.get("ssidDetails", [])
        ap_zones_list = input_config.get("ap_zones", [])
        feature_template_designs = have_info.get("feature_template_designs", [])

        have_ap_zones = have_prof_info.get("apZones", [])
        additional_interfaces = input_config.get("additional_interfaces", [])
        have_additional_interfaces = have_prof_info.get("additionalInterfaces", [])
        have_feature_templates = have_prof_info.get("featureTemplates", [])

        if ssid_list:
            if not have_ssid_details:
                self.log("No SSID details found in the existing profile.", "DEBUG")
                unmatched_keys.append(ssid_list)
            else:
                if ssid_list:
                    for each_ssid in ssid_list:
                        self.log("Comparing Input SSID configurations for {0}".format(
                            each_ssid.get("ssid_name")), "INFO")
                        input_ssid_exist_state = False
                        for have_ssid in have_ssid_details:
                            if each_ssid.get("ssid_name") == have_ssid.get("ssidName"):
                                input_ssid_exist_state = True
                                self.log("Matching SSID found: {0}. Comparing configurations...".format(
                                    each_ssid.get("ssid_name")), "INFO")
                                ssid_match, unmatched_values = (
                                    self.compare_each_config_with_have(
                                        each_ssid, have_ssid, "ssid_details"
                                    )
                                )
                                if not ssid_match:
                                    unmatched_keys.append(unmatched_values)
                                    self.log(
                                        "SSID mismatch found: {0}".format(
                                            unmatched_values
                                        ),
                                        "WARNING",
                                    )

                        if not input_ssid_exist_state:
                            unmatched_keys.append(each_ssid)
                            self.log(
                                "SSID '{0}' not found in existing profile.".format(
                                    each_ssid.get("ssid_name")
                                ),
                                "WARNING",
                            )

        if ap_zones_list:
            if not have_ap_zones:
                self.log("No AP Zone details found in the existing profile.", "DEBUG")
                unmatched_keys.append(ap_zones_list)
            else:
                self.log("Comparing AP Zone configurations with existing profile AP Zones", "INFO")
                for ap_zone in ap_zones_list:
                    self.log("Comparing Input AP Zone configuration for {0}".format(
                        ap_zone.get("ap_zone_name")), "INFO")
                    input_ap_zone_exist_state = False
                    for have_zone in have_ap_zones:
                        if ap_zone.get("ap_zone_name") == have_zone.get(
                            "apZoneName"
                        ):
                            input_ap_zone_exist_state = True
                            self.log("Matching AP Zone found: {0}. Comparing configurations...".format(
                                ap_zone.get("ap_zone_name")), "INFO")
                            zone_match, unmatched_values = (
                                self.compare_each_config_with_have(
                                    ap_zone, have_zone, "ap_zones"
                                )
                            )
                            if not zone_match:
                                self.log(
                                    "AP Zone mismatch found: {0}".format(
                                        unmatched_values
                                    ),
                                    "WARNING",
                                )
                                unmatched_keys.append(unmatched_values)

                    if not input_ap_zone_exist_state:
                        ap_zone_name = ap_zone.get("ap_zone_name", "Unknown") if ap_zone else "Unknown"
                        unmatched_keys.append(ap_zone)
                        self.log(
                            "AP Zone '{0}' not found in existing profile configuration.".format(
                                ap_zone_name
                            ),
                            "WARNING",
                        )

        if additional_interfaces:
            if not have_additional_interfaces:
                self.log("No Additional interface details found in the existing profile.", "DEBUG")
                unmatched_keys.append(additional_interfaces)
            else:
                self.log("Validating additional interface configurations against existing profile interfaces", "INFO")
                for each_interface in additional_interfaces:
                    interface_name = each_interface.get("interface_name")
                    if interface_name not in have_additional_interfaces:
                        unmatched_keys.append(interface_name)
                        self.log(
                            "Additional interface '{0}' not found in existing config.".format(
                                interface_name
                            ),
                            "WARNING",
                        )

        if feature_template_designs \
           and self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") >= 0:
            if not have_feature_templates:
                self.log("No Feature template details found in the existing profile.", "DEBUG")
                unmatched_keys.append(feature_template_designs)
            else:
                self.log("Validating feature template configurations against existing profile template assignments", "DEBUG")
                self.log("Processing {0} feature template designs for configuration comparison with existing assignments".format(
                    len(feature_template_designs)), "DEBUG")

                feature_templates_processed = 0
                feature_templates_with_mismatches = 0
                for feature_template_design in feature_template_designs:
                    feature_templates_processed += 1
                    template_design_name = feature_template_design.get("design_name")
                    template_design_id = feature_template_design.get("design_id")
                    template_ssids = feature_template_design.get("ssids")

                    self.log("Validating feature template {0}/{1} with design '{2}'".format(
                        feature_templates_processed, len(feature_template_designs), template_design_name), "DEBUG")

                    # Validate template design ID exists in current profile assignments
                    if template_design_id and not self.value_exists(have_feature_templates, "id", template_design_id):
                        feature_templates_with_mismatches += 1
                        unmatched_keys.append(
                            "Feature template designs with feature template '{0}' not found.".format(template_design_name)
                        )
                        self.log(
                            "Feature template design mismatch detected - feature template "
                            "'{0}' (ID: {1}) not found in existing profile assignments".format(
                                template_design_name, template_design_id), "WARNING")

                    # Validate SSID applicability exists in current profile assignments
                    if template_ssids and not self.value_exists(have_feature_templates, "ssids", template_ssids):
                        feature_templates_with_mismatches += 1
                        unmatched_keys.append(
                            "Feature template with applicability_ssids '{0}' not found.".format(template_ssids)
                        )
                        self.log(
                            "Feature template SSID applicability number of mismatch "
                            "detected '{0}'- SSIDs '{1}' not found in existing profile template assignments".format(
                                len(unmatched_keys), template_ssids), "WARNING")

                # Log comprehensive feature template validation summary
                if feature_templates_with_mismatches > 0:
                    self.log("Feature template validation completed with mismatches"
                             " - {0}/{1} templates have configuration differences".format(
                                 feature_templates_with_mismatches, feature_templates_processed), "WARNING")
                else:
                    self.log("Feature template validation completed successfully - all {0} templates match existing profile assignments".format(
                        feature_templates_processed), "DEBUG")

        if unmatched_keys:
            self.log(
                "Unmatched SSID Details: {0}".format(str(unmatched_keys)), "WARNING"
            )
            return False, unmatched_keys

        return True, None

    def get_wireless_profile(self, profile_name):
        """
        Get wireless profile from the given playbook data and response with
        wireless profile information with ssid details.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            profile_name (str): A string containing input data to get wireless profile
                                for given profile name.

        Returns:
            dict or None: Dict contains wireless profile information, otherwise None.

        Description:
            This function used to get the wireless profile from the input config.
        """

        self.log("Get wireless profile for : {0}".format(profile_name), "INFO")
        try:
            response = self.dnac._exec(
                family="wireless",
                function="get_wireless_profiles",
                params={"wireless_profile_name": profile_name},
            )
            self.log(
                "Response from 'get_wireless_profiles_v1' API: {0}".format(
                    self.pprint(response)
                ),
                "DEBUG",
            )
            if not response:
                self.log(
                    "No wireless profile found for: {0}".format(profile_name), "INFO"
                )
                return None
            self.log(
                "Received the wireless profile response: {0}".format(
                    self.pprint(response)
                ),
                "INFO",
            )
            return response.get("response")[0]

        except Exception as e:
            msg = "An error occurred during get wireless profile: {0}".format(str(e))
            self.log(msg, "ERROR")
            self.set_operation_result("failed", False, msg, "ERROR")
            return None

    def get_ssid_details(self, site_id, site_name):
        """
        Get SSID details from the given playbook data and response with SSID information.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_id (str) : Site ID contain string of UUID for the global site
            site_name (str): A str containing Site name to collect the SSID information.

        Returns:
            global_ssids (list): Contains list of dict SSID details for the SSID validation

        Description:
            This function used to get the list of SSID informations for the given site.
        """

        self.log(
            "Fetching SSID information for site {0}: {1}".format(site_name, site_id),
            "INFO",
        )
        offset_limit = int(self.payload.get("offset_limit", 500))
        payload = {"site_id": site_id, "limit": offset_limit, "offset": 1}
        global_ssids = []
        try:
            while True:
                response = self.dnac._exec(
                    family="wireless", function="get_ssid_by_site", params=payload
                )
                self.log(
                    "Response from get_enterprise_ssid API: {0}".format(
                        self.pprint(response)
                    ),
                    "DEBUG",
                )

                if not response or not isinstance(response, dict):
                    self.log(
                        "Unexpected or empty response received from API, "
                        + "expected a non-empty dictionary.",
                        "ERROR",
                    )
                    break

                self.log(
                    "Received the SSID details response: {0}".format(
                        self.pprint(response.get("response"))
                    ),
                    "INFO",
                )
                ssid_list = response.get("response")

                if not ssid_list:
                    self.log(
                        "No SSID data found at offset {0}. Exiting pagination.".format(
                            payload["offset"]
                        ),
                        "DEBUG",
                    )
                    break

                self.log(
                    "Retrieved {0} SSID detail(s) from API (Offset={1}).".format(
                        len(ssid_list), payload["offset"]
                    ),
                    "DEBUG",
                )
                global_ssids.extend(ssid_list)

                if len(ssid_list) < offset_limit:
                    self.log(
                        "Fetched fewer than the limit ({0}), assuming last page. Exiting.".format(
                            offset_limit
                        ),
                        "DEBUG",
                    )
                    break

                payload["offset"] += offset_limit
                self.log(
                    "Incrementing offset to {0} for next API request.".format(
                        payload["offset"]
                    ),
                    "DEBUG",
                )

            if not global_ssids:
                msg = "No SSID details available for Global to validate input playbook SSIDs"
                self.log(msg, "ERROR")
                self.fail_and_exit(msg)

            self.log(
                "Total {0} SSID detail(s) retrieved for the site: '{1}'.".format(
                    len(global_ssids), site_name
                ),
                "DEBUG",
            )
            return global_ssids

        except Exception as e:
            msg = "An error occurred during get wireless profile: {0}".format(str(e))
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

    def check_ssid_details(self, ssid_name, ssid_list):
        """
        Check the SSID Name is available in the SSID list collected based on the site id.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            ssid_name (str): A str containing input data of SSID name.
            ssid_list (list): A list of dict contains SSID name and other details.

        Returns:
            bool: Update True or False if SSID exist
            dict: A string contains SSID information.

        Description:
            This function used to get the SSID information from the input config.
        """
        self.log(
            "Checking if SSID '{0}' exists in the provided SSID list.".format(
                ssid_name
            ),
            "INFO",
        )

        try:
            ssid_details = {}
            global_ssids = []

            for each_ssid in ssid_list:
                global_ssids.append(each_ssid["ssid"])
                if ssid_name == each_ssid.get("ssid"):
                    ssid_details["ssid_name"] = ssid_name
                    ssid_details["wlan_profile_name"] = each_ssid.get("profileName")
                    ssid_details["policy_profile_name"] = each_ssid.get(
                        "policyProfileName"
                    )
                    msg = "Verified SSID: {0} exist in Global SSID list.".format(
                        ssid_name
                    )
                    self.log(msg, "INFO")
                    return True, ssid_details

            if not ssid_details:
                msg = "Given SSID: {0} not in the Global SSID list: {1}.".format(
                    ssid_name, global_ssids
                )
                self.log(msg, "ERROR")
                self.fail_and_exit(msg)

        except Exception as e:
            msg = "An error occurred during ssid checking: {0}".format(str(e))
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

    def parse_input_data_for_payload(self, wireless_data, payload_data):
        """
        Parse input playbook data to payload for the profile creation and updation.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            wireless_data (dict): A dictionary containing input config data from playbook.
            payload_data (dict): A dictionary contain parsed data for the payload.

        Returns:
            No return, parse the input data and load the parsed data to the payload_data
        """
        self.log(
            "Parsing input data for payload: {0}".format(self.pprint(wireless_data)),
            "DEBUG",
        )
        exclude_keys = [
            "site_names",
            "onboarding_templates",
            "day_n_templates",
            "provision_group",
        ]

        try:
            for key, value in wireless_data.items():
                if value is None or key in exclude_keys:
                    continue

                mapped_key = self.keymap.get(key, key)
                if key not in exclude_keys:
                    if key == "ssid_details" and isinstance(value, list):
                        payload_data["ssidDetails"] = []
                        ssid_details = value
                        if ssid_details:
                            for each_ssid in ssid_details:
                                ssid_data = {}
                                for ssid_key, ssid_value in each_ssid.items():
                                    mapped_ssidkey = self.keymap.get(ssid_key, ssid_key)

                                    if ssid_key != "policy_profile_name":
                                        ssid_data[mapped_ssidkey] = ssid_value
                                        if ssid_key == "local_to_vlan" and ssid_value:
                                            ssid_data["flexConnect"] = dict(
                                                enableFlexConnect=True,
                                                localToVlan=ssid_value,
                                            )

                                        if (
                                            ssid_key == "dot11be_profile_name"
                                            and ssid_value
                                        ):
                                            dot11be_id = self.get_dot11be_profile(
                                                ssid_value
                                            )
                                            if dot11be_id:
                                                ssid_data["dot11beProfileId"] = (
                                                    dot11be_id
                                                )

                                if ssid_data.get("enableFabric"):
                                    remove_keys = [
                                        "flexConnect",
                                        "localToVlan",
                                        "interfaceName",
                                        "anchorGroupName",
                                        "vlanGroupName",
                                    ]
                                    for rm_key in remove_keys:
                                        ssid_data.pop(rm_key, None)
                                ssid_data.pop("localToVlan", None)
                                payload_data["ssidDetails"].append(ssid_data)

                    elif key == "ap_zones" and isinstance(value, list):
                        payload_data["apZones"] = []
                        ap_zones = wireless_data[key]
                        if ap_zones:
                            for ap_zone in ap_zones:
                                ap_zone_data = {}
                                for zone_key, zone_value in ap_zone.items():
                                    mapped_zonekey = self.keymap.get(zone_key, zone_key)
                                    if zone_key != "device_tags":
                                        if zone_key == "ssids" and zone_value:
                                            ap_zone_data["ssids"] = zone_value
                                        ap_zone_data[mapped_zonekey] = zone_value
                                payload_data["apZones"].append(ap_zone_data)

                    elif key == "additional_interfaces" and isinstance(value, list):
                        payload_data["additionalInterfaces"] = []
                        addi_interfaces = wireless_data[key]
                        if addi_interfaces:
                            for interface in addi_interfaces:
                                if interface.get("interface_name") is not None:
                                    payload_data["additionalInterfaces"].append(
                                        interface.get("interface_name")
                                    )

                    elif (
                        key == "feature_template_designs"
                        and isinstance(value, list)
                        and self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") >= 0
                    ):
                        payload_data["featureTemplates"] = []
                        feature_template_designs = wireless_data[key]
                        if feature_template_designs:
                            have_feature = self.have.get("wireless_profile").get("feature_template_designs", [])
                            for template in have_feature:
                                mapped_template = {}
                                if template.get("design_id"):
                                    mapped_template["id"] = template.get("design_id")

                                if template.get("ssids"):
                                    mapped_template["ssids"] = template.get("ssids")

                                if mapped_template:
                                    payload_data["featureTemplates"].append(
                                        mapped_template
                                    )

                    else:
                        payload_data[mapped_key] = value

            if self.params.get("state") == "merged" and self.have.get("wireless_profile", {}).get("profile_info"):
                self.log(
                    "Merging input data with existing wireless profile data", "INFO"
                )
                existing_profile = copy.deepcopy(self.have.get("wireless_profile", {}).get("profile_info"))
                self.log(
                    "Starting profile data merge operation with {0} existing components "
                    "and {1} new components".format(
                        len(existing_profile.keys()) if existing_profile else 0,
                        len(payload_data.keys()) if payload_data else 0
                    ),
                    "DEBUG"
                )
                self.parse_with_existing_profile_data(existing_profile, payload_data)
                self.log(
                    "Profile data merge completed successfully - merged configuration "
                    "contains {0} components".format(
                        len(payload_data.keys()) if payload_data else 0
                    ),
                    "INFO"
                )
            self.log(
                "Parsed payload data: {0}".format(self.pprint(payload_data)), "INFO"
            )

        except Exception as e:
            msg = "An error occurred during Parsing for payload: {0}".format(str(e))
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

    def parse_with_existing_profile_data(self, existing_profile, payload_data):
        """
        Parse the existing profile data and merge it with the new payload data.

        Parameters:
            existing_profile (dict): The existing wireless profile data.
            payload_data (dict): The new payload data to merge.

        Returns:
            No return, parse the input data and load the parsed data to the payload_data
        """
        self.log(
            "Starting merged profile data processing for wireless network profile management",
            "INFO"
        )

        self.log(
            "Processing profile data merge with existing profile components: {0} and new payload size: {1}".format(
                len(existing_profile.keys()) if existing_profile else 0,
                len(payload_data.keys()) if payload_data else 0
            ),
            "DEBUG"
        )

        # Statistics tracking for merge operations
        merge_stats = {
            'ssids_preserved': 0,
            'ap_zones_preserved': 0,
            'feature_templates_preserved': 0,
            'interfaces_preserved': 0,
            'components_processed': 0
        }

        # SSID details from existing profile data
        existing_ssids = existing_profile.get("ssidDetails", [])
        if existing_ssids:
            # Initialize ssidDetails if not present
            merge_stats['components_processed'] += 1
            payload_data.setdefault("ssidDetails", [])

            self.log(
                "Processing SSID merge operation - existing SSIDs: {0}, new SSIDs: {1}".format(
                    len(existing_ssids), len(payload_data.get("ssidDetails", []))
                ),
                "DEBUG"
            )

            ssids_preserved = []

            for existing_ssid in existing_ssids:
                ssid_name = existing_ssid.get("ssidName")

                # Skip invalid entries
                if not ssid_name:
                    self.log("Skipping SSID entry without name in existing profile", "WARNING")
                    continue

                # Check if SSID already exists in payload
                if not self.value_exists(payload_data["ssidDetails"], "ssidName", ssid_name):
                    self.log(
                        "Preserving existing SSID '{0}' in updated profile configuration".format(ssid_name),
                        "INFO"
                    )
                    payload_data["ssidDetails"].append(existing_ssid)
                    ssids_preserved.append(ssid_name)
                    merge_stats['ssids_preserved'] += 1
                else:
                    self.log(
                        "SSID '{0}' already exists in new configuration - using new configuration".format(ssid_name),
                        "DEBUG"
                    )

            # Summary logging
            if ssids_preserved:
                self.log(
                    "Preserved {0} existing SSID(s) in profile update: {1}".format(
                        len(ssids_preserved), ", ".join(ssids_preserved)
                    ),
                    "INFO"
                )

        # AP Zones details from existing profile data
        existing_ap_zones = existing_profile.get("apZones", [])
        if existing_ap_zones:
            merge_stats['components_processed'] += 1
            payload_data.setdefault("apZones", [])
            zones_preserved = []
            self.log(
                "Processing AP Zones merge operation - existing zones: {0}, new zones: {1}".format(
                    len(existing_ap_zones), len(payload_data.get("apZones", []))
                ),
                "DEBUG"
            )

            for existing_apzone in existing_ap_zones:
                apzone_name = existing_apzone.get("apZoneName")

                if not apzone_name:
                    self.log("Skipping AP Zone entry without name in existing profile", "WARNING")
                    continue

                if not self.value_exists(payload_data["apZones"], "apZoneName", apzone_name):
                    self.log(
                        "Preserving existing AP Zone '{0}' in updated profile configuration".format(apzone_name),
                        "INFO"
                    )
                    payload_data["apZones"].append(existing_apzone)
                    zones_preserved.append(apzone_name)
                    merge_stats['ap_zones_preserved'] += 1
                else:
                    self.log(
                        "AP Zone '{0}' being updated with new configuration".format(apzone_name),
                        "DEBUG"
                    )

            if zones_preserved:
                self.log(
                    "Preserved {0} existing AP Zone(s): {1}".format(
                        len(zones_preserved), ", ".join(zones_preserved)
                    ),
                    "INFO"
                )

        # Feature Templates data from existing profile data
        existing_feature_templates = existing_profile.get("featureTemplates", [])
        if existing_feature_templates:
            payload_data.setdefault("featureTemplates", [])
            templates_preserved = []
            self.log(
                "Processing feature templates merge operation - existing templates: {0}, new templates: {1}".format(
                    len(existing_feature_templates), len(payload_data.get("featureTemplates", []))
                ),
                "DEBUG"
            )

            for existing_template in existing_feature_templates:
                template_id = existing_template.get("id")
                template_name = existing_template.get("designName", "Unknown")

                if not template_id:
                    self.log(
                        "Skipping feature template entry without ID in existing profile",
                        "WARNING"
                    )
                    continue

                if not self.value_exists(payload_data["featureTemplates"], "id", template_id):
                    self.log(
                        "Preserving existing feature template '{0}' (ID: {1}) in profile update".format(
                            template_name, template_id
                        ),
                        "INFO"
                    )
                    payload_data["featureTemplates"].append(existing_template)
                    templates_preserved.append(template_name)
                    merge_stats['feature_templates_preserved'] += 1
                else:
                    self.log(
                        "Feature template '{0}' being updated with new configuration".format(template_name),
                        "DEBUG"
                    )

            if templates_preserved:
                self.log(
                    "Preserved {0} existing feature template(s): {1}".format(
                        len(templates_preserved), ", ".join(templates_preserved)
                    ),
                    "INFO"
                )

        # Additional Interfaces data from existing profile data
        existing_interfaces = existing_profile.get("additionalInterfaces", [])
        if existing_interfaces:
            payload_data.setdefault("additionalInterfaces", [])
            interfaces_preserved = []
            merge_stats['components_processed'] += 1
            self.log(
                "Processing additional interfaces merge operation - existing interfaces: {0}, new interfaces: {1}".format(
                    len(existing_interfaces), len(payload_data.get("additionalInterfaces", []))
                ),
                "DEBUG"
            )

            for existing_interface in existing_interfaces:
                if existing_interface and existing_interface not in payload_data["additionalInterfaces"]:
                    self.log(
                        "Preserving existing interface '{0}' in updated profile configuration".format(
                            existing_interface
                        ),
                        "INFO"
                    )
                    payload_data["additionalInterfaces"].append(existing_interface)
                    interfaces_preserved.append(existing_interface)
                    merge_stats['interfaces_preserved'] += 1
                elif existing_interface:
                    self.log(
                        "Interface '{0}' already in new configuration".format(existing_interface),
                        "DEBUG"
                    )

            if interfaces_preserved:
                self.log(
                    "Preserved {0} existing interface(s): {1}".format(
                        len(interfaces_preserved), ", ".join(interfaces_preserved)
                    ),
                    "INFO"
                )

        total_preserved = (
            merge_stats['ssids_preserved'] +
            merge_stats['ap_zones_preserved'] +
            merge_stats['feature_templates_preserved'] +
            merge_stats['interfaces_preserved']
        )

        self.log(
            "Profile data merge completed - processed {0} component types, preserved {1} total items".format(
                merge_stats['components_processed'], total_preserved
            ),
            "INFO"
        )

        if total_preserved > 0:
            self.log(
                "Merge statistics - SSIDs: {0}, AP Zones: {1}, Feature Templates: {2}, Interfaces: {3}".format(
                    merge_stats['ssids_preserved'],
                    merge_stats['ap_zones_preserved'],
                    merge_stats['feature_templates_preserved'],
                    merge_stats['interfaces_preserved']
                ),
                "INFO"
            )

        return

    def create_update_wireless_profile(self, wireless_data, profile_id=None):
        """
        Create/Update the wireless profile for the given config with site and SSID details.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            wireless_data (dict): A dictionary containing input config data from playbook.
            profile_id (str, optional): ID of the wireless profile to update.

        Returns:
            dict: A dictionary of execution task details.

        Description:
            This function create/update the wireless profile with the site the and SSID details.
        """
        payload_data = {}
        self.log(
            "Parse the input playbook to payload for: {0}".format(wireless_data), "INFO"
        )
        self.parse_input_data_for_payload(wireless_data, payload_data)

        profile_name = payload_data.get("wirelessProfileName")
        profile = self.have.get("wireless_profile", {})

        profile_exist = self.value_exists(profile, "name", profile_name)
        function_name = "create_wireless_profile_connectivity"
        profile_payload = payload_data  # Default case for creation

        if profile_exist:
            function_name = "update_wireless_profile_connectivity"
            profile = self.have.get("wireless_profile")
            if profile and isinstance(profile, dict):
                if profile.get("profile_info", {}).get(
                    "wirelessProfileName"
                ) == payload_data.get("wirelessProfileName"):
                    profile_id = profile.get("profile_info", {}).get("id")
                    profile_payload = {"id": profile_id, "payload": payload_data}
                    self.log(
                        "Updating wireless profile with parameters: {0}".format(
                            self.pprint(payload_data)
                        ),
                        "INFO",
                    )
        elif profile_id:
            function_name = "update_wireless_profile_connectivity"
            profile_payload = {"id": profile_id, "payload": payload_data}
            self.log(
                "Updating wireless profile for template with parameters: {0}".format(
                    self.pprint(payload_data)
                ),
                "INFO",
            )
        else:
            self.log(
                "Creating wireless profile with parameters: {0}".format(
                    self.pprint(payload_data)
                ),
                "INFO",
            )

        return self.execute_process_task_data(
            "wireless", function_name, profile_payload
        )

    def compare_each_config_with_have(self, input_data, have_data, type_of):
        """
        Compare input configuration data with existing ("have") data and return
        a boolean indicating whether they match, along with any unmatched data.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            input_data (dict): A dict containing playbook config of ssid info and ap zone data.
            have_data (dict): A dict contain the data exist with specific ssid retrived data
            type_of (str): A string contain the ssid details or ap_zone for check data

        Returns:
            tuple: (matched (bool), unmatched_data (dict or None))

        Description:
            This function used to compare the data same have and input config data.
        """
        if type_of not in ["ssid_details", "ap_zones"]:
            self.log("Unsupported type for comparison: {0}".format(type_of), "ERROR")
            return False, None

        self.log(
            "Comparing Have SSID: {0}, Want SSID: {1}".format(
                self.pprint(have_data), self.pprint(input_data)
            ),
            "DEBUG",
        )

        un_match_data = {}
        self.log("Comparing configuration type: {0}".format(type_of), "DEBUG")
        if type_of == "ssid_details":
            for ssid_key in input_data.keys():
                if ssid_key == "ssid_name":
                    if input_data[ssid_key] != have_data.get("ssidName"):
                        un_match_data[ssid_key] = input_data[ssid_key]
                        self.log(
                            "SSID name mismatch. Expected: {0}, Found: {1}".format(
                                input_data[ssid_key], have_data.get("ssidName")
                            ),
                            "DEBUG",
                        )

                elif ssid_key == "dot11be_profile_name" and input_data.get(ssid_key):
                    dot11be_id = self.get_dot11be_profile(input_data.get(ssid_key))
                    if dot11be_id != have_data.get(self.keymap[ssid_key]):
                        un_match_data[ssid_key] = input_data[ssid_key]
                        self.log(
                            "dot11be_profile_name mismatch for SSID '{0}'. Expected ID: {1}, Found: {2}".format(
                                input_data.get("ssid_name"),
                                dot11be_id,
                                have_data.get(self.keymap[ssid_key]),
                            ),
                            "DEBUG",
                        )

                elif ssid_key in [
                    "wlan_profile_name",
                    "policy_profile_name",
                    "enable_fabric",
                ]:
                    if input_data[ssid_key] != have_data.get(self.keymap[ssid_key]):
                        un_match_data[ssid_key] = input_data[ssid_key]
                        self.log(
                            "{0} mismatch for SSID '{1}'. Expected: {2}, Found: {3}".format(
                                ssid_key,
                                input_data.get("ssid_name"),
                                input_data[ssid_key],
                                have_data.get(self.keymap[ssid_key]),
                            ),
                            "DEBUG",
                        )

                elif ssid_key in [
                    "interface_name",
                    "anchor_group_name",
                ] and not input_data.get("enable_fabric"):
                    self.log(f"Comparing the '{ssid_key}' while 'Enable Fabric' is False", "DEBUG")
                    if input_data[ssid_key] != have_data.get(self.keymap[ssid_key]):
                        un_match_data[ssid_key] = input_data[ssid_key]
                        self.log(
                            "{0} mismatch for SSID '{1}'. Expected: {2}, Found: {3}".format(
                                ssid_key,
                                input_data.get("ssid_name"),
                                input_data[ssid_key],
                                have_data.get(self.keymap[ssid_key]),
                            ),
                            "DEBUG",
                        )

                elif ssid_key == "local_to_vlan" and not input_data.get("enable_fabric"):
                    input_vlan = int(input_data.get(ssid_key, 0))
                    have_vlan = int(
                        have_data.get("flexConnect", {}).get(self.keymap[ssid_key], 0)
                    )
                    if input_vlan != have_vlan:
                        un_match_data[ssid_key] = input_data[ssid_key]
                        self.log(
                            "local_to_vlan mismatch for SSID '{0}'. Expected: {1}, Found: {2}".format(
                                input_data.get("ssid_name"), input_vlan, have_vlan
                            ),
                            "DEBUG",
                        )
        else:
            for zone_key, zone_value in input_data.items():
                if zone_key == "ssids" and isinstance(zone_value, list):
                    for each_ssid in zone_value:
                        if each_ssid not in have_data.get(zone_key):
                            un_match_data[zone_key] = each_ssid
                            self.log(
                                "SSID '{0}' not found in existing AP Zone config.".format(
                                    each_ssid
                                ),
                                "DEBUG",
                            )

                    have_zone_value = have_data.get(zone_key)
                    if zone_value != have_zone_value:
                        self.log(
                            "SSID list mismatch in AP Zone. Expected: {0}, Found: {1}".format(
                                zone_value, have_zone_value
                            ),
                            "DEBUG",
                        )
                        un_match_data[zone_key] = zone_value

                elif zone_key in ["ap_zone_name", "rf_profile_name"]:
                    if input_data[zone_key] != have_data.get(self.keymap[zone_key]):
                        un_match_data[zone_key] = zone_value
                        self.log(
                            "{0} mismatch in AP Zone. Expected: {1}, Found: {2}".format(
                                zone_key,
                                zone_value,
                                have_data.get(self.keymap[zone_key]),
                            ),
                            "DEBUG",
                        )

        if not un_match_data:
            return True, None

        self.log(
            "Found the unmatched data {0}".format(self.pprint(un_match_data)), "INFO"
        )
        return False, un_match_data

    def get_dot11be_profile(self, dot11be_profile):
        """
        Retrieve the dot11be profile details based on the profile name from Cisco Catalyst Center.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            dot11be_profile (str): A string containing dot11be profile name.

        Returns:
            str or None: Profile ID string if found, else None.
        """
        self.log(
            "Retrieving dot11be profile ID for profile: {0}".format(dot11be_profile),
            "DEBUG",
        )

        param = {"profile_name": dot11be_profile}
        func_name = "get80211be_profiles"

        try:
            response = self.execute_get_request("wireless", func_name, param)
            self.log(
                "Response from get dot11be profile API: {0}".format(
                    self.pprint(response)
                ),
                "DEBUG",
            )

            if not response or "response" not in response or not response["response"]:
                self.log(
                    "No valid response received for profile: {0}, response type: {1}".format(
                        dot11be_profile, type(response).__name__
                    ),
                    "ERROR",
                )
                return None

            dot11be_id = response.get("response")[0].get("id")
            if dot11be_id:
                self.log(
                    "Successfully retrieved dot11be profile ID: {0}".format(dot11be_id),
                    "DEBUG",
                )
            else:
                self.log(
                    "Profile ID not found in API response for profile: {0}".format(
                        dot11be_profile
                    ),
                    "ERROR",
                )
            return dot11be_id

        except Exception as e:
            msg = "Exception occurred while retrieving dot11be profile '{0}': ".format(
                dot11be_profile
            )
            self.log(msg + str(e), "ERROR")
            self.set_operation_result("failed", False, msg, "INFO")
            return None

    def process_templates(
        self, templates, previous_templates, profile_name, profile_id
    ):
        """
        Check and assign the list of template from the input config.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            templates (list): A list containing template name from input config.
            previous_templates (list): A list containing existing template name and id
                                       assigned to the profile.
            profile_name (str): A string containing profile name used to assign template to profile.
            profile_id (str): A string containing profile id used to assign the onboarding or
                              day n template.

        Returns:
            list: A list contains templates assigned to the profile status.
        """
        self.log(
            "Processing {0} templates for profile: {1}".format(
                len(templates), profile_name
            ),
            "DEBUG",
        )
        template_response = []

        for each_template in templates:
            template_name = each_template.get("name")
            self.log("Checking template: {0}".format(template_name), "DEBUG")

            if not each_template.get("template_exist"):
                self.log(
                    "Template '{0}' does not exist, skipping.".format(template_name),
                    "DEBUG",
                )
                continue  # Skip the rest of the loop if template doesn't exist

            template_id = each_template.get("template_id")
            self.log(
                "Template '{0}' exists, attaching network profile.".format(
                    template_name
                ),
                "DEBUG",
            )

            # If no previous templates, we can directly attach
            if not previous_templates:
                self.log(
                    "No previous templates to check, attaching '{0}'.".format(
                        template_name
                    ),
                    "DEBUG",
                )
                template_response.append(
                    self.attach_networkprofile_cli_template(
                        profile_name, profile_id, template_name, template_id
                    )
                )
                continue  # Continue to the next template

            # If template already exists in previous templates, skip it
            if self.value_exists(previous_templates, "name", template_name):
                self.log(
                    "Template '{0}' already exists in previous templates, skipping.".format(
                        template_name
                    ),
                    "DEBUG",
                )
                continue  # Skip the rest of the loop if template already exists in previous_templates

            # Otherwise, attach the template
            self.log(
                "Template '{0}' not found in previous templates, attaching.".format(
                    template_name
                ),
                "DEBUG",
            )
            template_response.append(
                self.attach_networkprofile_cli_template(
                    profile_name, profile_id, template_name, template_id
                )
            )

        self.log(
            "Finished processing templates. Total attached: {0}".format(
                len(template_response)
            ),
            "DEBUG",
        )
        return template_response

    def get_diff_merged(self, config):
        """
        Create or update the wireless profile in Cisco Catalyst Center based on the playbook

        Parameters:
            config (dict) - Playbook details containing wireless profile information.

        Returns:
            self - The current object with create or update message with task response.
        """
        self.changed = False
        profile_id = None

        profile_name = config.get("profile_name")
        ssid_details = config.get("ssid_details")
        ap_zones = config.get("ap_zones")
        additional_interfaces = config.get("additional_interfaces")
        feature_template_designs = config.get("feature_template_designs")

        profile_unmatch_stat = self.have["wireless_profile"].get("profile_compare_stat")
        template_unmatch_stat = self.have["wireless_profile"].get(
            "template_compare_stat"
        )
        site_unmatch_stat = self.have["wireless_profile"].get("site_compare_stat")
        profile_response = {"profile_name": config["profile_name"]}

        self.log(
            "Checking for existing wireless profile with name: '{0}'".format(
                profile_name
            ),
            "DEBUG",
        )

        if feature_template_designs \
           and self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") < 0:
            del config["feature_template_designs"]

        for profile in self.have["wireless_profile_list"]:
            if profile.get("name") == config.get("profile_name"):
                self.log("Found existing profile: {0}".format(profile), "DEBUG")
                if profile_unmatch_stat and template_unmatch_stat and site_unmatch_stat:
                    self.msg = "No changes required, profile(s) already exist"
                    self.log(self.msg, "INFO")
                    self.set_operation_result(
                        "success", False, self.msg, "INFO"
                    ).check_return_status()
                    return self
                profile_id = profile.get("id")
                self.log(
                    "Matching profile found with ID: {0}".format(profile_id), "DEBUG"
                )
                break
        else:
            self.log(
                "No existing profile matched for name: '{0}'. Proceeding to create a new one.".format(
                    profile_name
                ),
                "DEBUG",
            )

        if not profile_id:
            self.log(
                "Creating wireless profile for the config: {0}".format(config), "INFO"
            )
            task_details = self.create_update_wireless_profile(config)

            if task_details:
                profile_response["profile_status"] = task_details["progress"]
                self.log(
                    "Task response for the profile creation: {0}".format(
                        profile_response
                    ),
                    "INFO",
                )
                uuid_pattern = r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
                match = re.search(uuid_pattern, task_details["progress"])
                if match:
                    profile_id = match.group()
                    self.log(
                        "Profile created: {0} and found the profile id: {1}".format(
                            config["profile_name"], profile_id
                        ),
                        "INFO",
                    )
            else:
                self.not_processed.append(config)
                self.msg = "Unable to create wireless profile: '{0}'.".format(
                    str(self.not_processed)
                )
                self.fail_and_exit(self.msg)

        elif (
            profile_id
            and not profile_unmatch_stat
            and (ssid_details or ap_zones or additional_interfaces or feature_template_designs)
        ):
            self.log(
                "Starting update for existing wireless profile '{0}' (ID: {1}) with new configuration.".format(
                    profile_name, profile_id
                ),
                "INFO",
            )
            task_details = self.create_update_wireless_profile(config, profile_id)
            if task_details:
                profile_response["profile_status"] = task_details["progress"]
                self.log(
                    "Profile update initiated. Task response received: {0}".format(
                        profile_response
                    ),
                    "INFO",
                )
                self.log(
                    "Profile update progress: {0}%".format(
                        profile_response.get("profile_status", "Not Available")
                    ),
                    "DEBUG",
                )
            else:
                self.log(
                    "No task details received for profile update. Update might have failed or not started.",
                    "ERROR",
                )

        have_site = self.have["wireless_profile"].get("site_response")
        site_id_list = []
        site_name_list = []
        assign_response = []
        if have_site and isinstance(have_site, list) and profile_id:
            self.log(
                "Collecting site IDs and names for profile: '{0}'".format(profile_name),
                "DEBUG",
            )
            for each_site in have_site:
                if each_site["site_exist"]:
                    site_id_list.append(each_site["site_id"])
                    site_name_list.append(each_site["site_names"])
                    self.log(
                        "Site exists: ID={0}, Name={1}".format(
                            each_site["site_id"], each_site["site_names"]
                        ),
                        "DEBUG",
                    )

        if site_id_list and profile_id and not site_unmatch_stat:
            self.log(
                "Assigning wireless profile '{0}' to sites.".format(profile_name),
                "INFO",
            )
            site_index = 0
            for site in site_id_list:
                self.log(
                    "Assigning profile ID '{0}' to site: {1}".format(
                        profile_id, site_name_list[site_index]
                    ),
                    "DEBUG",
                )
                assign_response.append(
                    self.assign_site_to_network_profile(
                        profile_id,
                        site,
                        config.get("profile_name"),
                        site_name_list[site_index],
                    )
                )
                site_index += 1
            if assign_response:
                msg = "Sites '{0}' successfully associated to network profile: {1}.".format(
                    str(site_name_list), profile_name
                )
                profile_response["site_status"] = msg

        ob_template = self.have["wireless_profile"].get("onboarding_templates")
        dn_template = self.have["wireless_profile"].get("day_n_templates")
        previous_templates = self.have["wireless_profile"].get("previous_templates")
        template_response = []

        if ob_template and profile_id and not template_unmatch_stat:
            template_response = self.process_templates(
                ob_template, previous_templates, profile_name, profile_id
            )
            self.log(
                "Template Response (ob_template): {0}".format(template_response),
                "DEBUG",
            )

        if dn_template and profile_id and not template_unmatch_stat:
            template_response = self.process_templates(
                dn_template, previous_templates, profile_name, profile_id
            )
            self.log(
                "Template Response (dn_template): {0}".format(template_response),
                "DEBUG",
            )

        if template_response:
            msg = "Template(s) successfully attached to the network profile: '{0}'".format(
                profile_name
            )
            profile_response["template_status"] = msg

        self.created.append(profile_response)
        self.msg = "Wireless Profile created/updated successfully for '{0}'.".format(
            str(self.created)
        )
        self.changed = True
        self.log(self.msg, "INFO")
        self.set_operation_result(
            self.status, self.changed, self.msg, "INFO", self.created
        ).check_return_status()

        return self

    def verify_diff_merged(self, config):
        """
        Verify the merged status(Creation/Updation) of wireless profile in Cisco Catalyst Center.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.
        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the merged status of a configuration in Cisco Catalyst Center by
            retrieving the current state (have) and desired state (want) of the configuration,
            logs the states, and validates whether the specified profiles exists in the Catalyst
            Center.
        """
        success_profile = []
        self.changed = False
        self.get_have(config)
        self.log(
            "Current profile Config (have): {0}".format(self.pprint(self.have)), "INFO"
        )
        self.log(
            "Desired profile Config (want): {0}".format(self.pprint(self.want)), "INFO"
        )

        profile_stat = self.have["wireless_profile"].get("profile_compare_stat")
        site_stat = self.have["wireless_profile"].get("site_compare_stat")
        template_stat = self.have["wireless_profile"].get("template_compare_stat")
        if not profile_stat or not site_stat or not template_stat:
            msg = "Profile verification failed, Unable to create/update profile: {0}".format(
                config
            )
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

        msg = "Profile created/updated are verified successfully for '{0}'.".format(
            config
        )
        self.log(msg, "INFO")
        self.set_operation_result(
            self.status, self.changed, msg, "INFO", self.created
        ).check_return_status()

        return self

    def remove_network_profile_data(self, each_profile, each_have_profile):
        """
        Remove the network profile data from Cisco Catalyst Center based on the playbook details.

        Parameters:
            each_profile (dict): The profile details to be deleted from Cisco Catalyst Center.
            each_have_profile (dict): Contain existing details of the profile

        Returns:
            dict: A dictionary containing the status of the removable data from profile or None.
        """
        self.log(
            "Starting comprehensive network profile data removal for wireless profile management",
            "INFO"
        )

        profile_name = each_profile.get("profile_name")
        self.log(
            "Processing profile data removal for profile '{0}' with configuration: {1}".format(
                profile_name, self.pprint(each_profile)
            ),
            "DEBUG"
        )

        # Input validation
        if not isinstance(each_profile, dict) or not isinstance(each_have_profile, dict):
            self.log("Invalid parameters provided for profile data removal", "ERROR")
            return None

        if not profile_name:
            self.log("Profile name missing in removal configuration", "ERROR")
            return None

        removable_data = copy.deepcopy(each_have_profile.get("profile_info", {}))
        have_profile_id = each_have_profile.get("profile_info", {}).get("id")
        have_profile_name = each_have_profile.get("profile_info", {}).get("wirelessProfileName")

        if not have_profile_id or not have_profile_name:
            self.log(
                "Missing essential profile information - ID: {0}, Name: {1}".format(
                    have_profile_id, have_profile_name
                ),
                "ERROR"
            )
            return None

        # Statistics tracking for removal operations
        remove_required = {
            "ssid_status": False,
            "additional_interfaces_status": False,
            "ap_zones_status": False,
            "feature_template_designs_status": False,
            "day_n_templates_status": False,
            "site_remove_status": False,
        }

        # Execute removal operations using helper functions
        if each_profile.get("ssid_details"):
            remove_required["ssid_status"] = self._remove_ssid_details(
                each_profile, removable_data, have_profile_name
            )

        if each_profile.get("additional_interfaces"):
            remove_required["additional_interfaces_status"] = self._remove_additional_interfaces(
                each_profile, removable_data, have_profile_name
            )

        if each_profile.get("ap_zones"):
            remove_required["ap_zones_status"] = self._remove_ap_zones(
                each_profile, removable_data, have_profile_name
            )

        if each_profile.get("feature_template_designs"):
            remove_required["feature_template_designs_status"] = self._remove_feature_template_designs(
                each_profile, removable_data, have_profile_name
            )

        unassign_templates = []
        if each_profile.get("day_n_templates"):
            unassign_templates = self._remove_day_n_templates(
                each_profile, each_have_profile, have_profile_id
            )
            remove_required["day_n_templates_status"] = len(unassign_templates) > 0

        unassign_sites = []
        if each_profile.get("site_names"):
            unassign_sites = self._remove_site_names(
                each_profile, each_have_profile, have_profile_name, have_profile_id
            )
            remove_required["site_remove_status"] = len(unassign_sites) > 0

        # Profile update processing
        profile_update_required = (
            remove_required["ssid_status"] or
            remove_required["additional_interfaces_status"] or
            remove_required["ap_zones_status"] or
            remove_required["feature_template_designs_status"]
        )

        if profile_update_required:
            self.log(
                "Profile update required - applying removable data changes to profile '{0}'".format(
                    have_profile_name
                ),
                "INFO"
            )

            update_response = self.create_update_wireless_profile(removable_data, have_profile_id)

            if update_response:
                self.log(
                    "Successfully applied profile data removal changes to profile '{0}'".format(
                        have_profile_name
                    ),
                    "INFO"
                )
                return remove_required
            else:
                self.msg = (
                    "Failed to apply profile data removal changes to profile: '{0}'.".format(
                        each_profile["profile_name"]
                    )
                )
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

        # Final comprehensive logging
        total_operations = sum(1 for status in remove_required.values() if status)

        self.log(
            "Network profile data removal completed for profile '{0}' - "
            "processed {1} component types, templates unassigned: {2}, sites unassigned: {3}".format(
                profile_name, total_operations, len(unassign_templates), len(unassign_sites)
            ),
            "INFO"
        )

        return remove_required

    def _remove_ssid_details(self, each_profile, removable_data, have_profile_name):
        """
        Remove SSID details from the wireless network profile during deletion operations.

        Parameters:
            each_profile (dict): Profile configuration containing SSIDs to remove
            removable_data (dict): Current profile data to modify
            have_profile_name (str): Name of existing profile for logging

        Returns:
            bool: True if SSIDs were removed, False otherwise
        """
        self.log(
            "Starting SSID details removal process for wireless network profile",
            "DEBUG"
        )

        ssid_details = each_profile.get("ssid_details")
        if not ssid_details:
            self.log("No SSID details specified for removal - skipping SSID processing", "DEBUG")
            return False

        ssids_removed = 0
        total_ssids = len(ssid_details)

        self.log(
            "Processing SSID removal for {0} SSID configurations from profile '{1}'".format(
                total_ssids, have_profile_name
            ),
            "INFO"
        )

        for ssid in ssid_details:
            ssid_name = ssid.get("ssid_name")

            if not ssid_name:
                self.log(
                    "Skipping SSID entry with missing name in removal configuration",
                    "WARNING"
                )
                continue

            if self.value_exists(removable_data.get("ssidDetails", []), "ssidName", ssid_name):
                self.log(
                    "Removing SSID '{0}' from profile '{1}' during deletion process".format(
                        ssid_name, have_profile_name
                    ),
                    "INFO"
                )
                removable_data["ssidDetails"] = [
                    have_ssid for have_ssid in removable_data.get("ssidDetails", [])
                    if have_ssid.get("ssidName") != ssid_name
                ]
                ssids_removed += 1
            else:
                self.log(
                    "SSID '{0}' not found in current profile configuration - skipping removal".format(
                        ssid_name
                    ),
                    "WARNING"
                )

        self.log(
            "SSID removal completed - removed {0}/{1} SSID configurations from profile".format(
                ssids_removed, total_ssids
            ),
            "INFO"
        )

        return ssids_removed > 0

    def _remove_additional_interfaces(self, each_profile, removable_data, have_profile_name):
        """
        Remove additional interface configurations from the wireless network profile.

        Parameters:
            each_profile (dict): Profile configuration containing interfaces to remove
            removable_data (dict): Current profile data to modify
            have_profile_name (str): Name of existing profile for logging

        Returns:
            bool: True if interfaces were removed, False otherwise
        """

        self.log(
            "Starting additional interfaces removal process for wireless network profile",
            "DEBUG"
        )

        additional_interfaces = each_profile.get("additional_interfaces")
        if not additional_interfaces:
            self.log(
                "No additional interfaces specified for removal - skipping interface processing",
                "DEBUG"
            )
            return False

        interfaces_removed = 0
        total_interfaces = len(additional_interfaces)

        self.log(
            "Processing interface removal for {0} additional interfaces from profile '{1}'".format(
                total_interfaces, have_profile_name
            ),
            "INFO"
        )

        for interface in additional_interfaces:
            interface_name = interface.get("interface_name")

            if not interface_name:
                self.log(
                    "Skipping interface entry with missing name in removal configuration",
                    "WARNING"
                )
                continue

            if interface_name in removable_data.get("additionalInterfaces", []):
                self.log(
                    "Removing additional interface '{0}' from profile '{1}' during deletion".format(
                        interface_name, have_profile_name
                    ),
                    "INFO"
                )
                removable_data["additionalInterfaces"].remove(interface_name)
                interfaces_removed += 1
            else:
                self.log(
                    "Additional interface '{0}' not found in profile - skipping removal".format(
                        interface_name
                    ),
                    "WARNING"
                )

        self.log(
            "Interface removal completed - removed {0}/{1} additional interfaces from profile".format(
                interfaces_removed, total_interfaces
            ),
            "INFO"
        )

        return interfaces_removed > 0

    def _remove_ap_zones(self, each_profile, removable_data, have_profile_name):
        """
        Remove AP zone configurations from the wireless network profile.

        Parameters:
            each_profile (dict): Profile configuration containing AP zones to remove
            removable_data (dict): Current profile data to modify
            have_profile_name (str): Name of existing profile for logging

        Returns:
            bool: True if AP zones were removed, False otherwise
        """

        self.log(
            "Starting AP zones removal process for wireless network profile",
            "DEBUG"
        )

        ap_zones = each_profile.get("ap_zones")
        if not ap_zones:
            self.log("No AP zones specified for removal - skipping AP zone processing", "DEBUG")
            return False

        zones_removed = 0
        total_zones = len(ap_zones)

        self.log(
            "Processing AP zone removal for {0} zones from profile '{1}'".format(
                total_zones, have_profile_name
            ),
            "INFO"
        )

        for ap_zone in ap_zones:
            ap_zone_name = ap_zone.get("ap_zone_name")

            if not ap_zone_name:
                self.log(
                    "Skipping AP zone entry with missing name in removal configuration",
                    "WARNING"
                )
                continue

        if self.value_exists(removable_data.get("apZones", []), "apZoneName", ap_zone_name):
            self.log(
                "Removing AP zone '{0}' from profile '{1}' during deletion process".format(
                    ap_zone_name, have_profile_name
                ),
                "INFO"
            )
            removable_data["apZones"] = [
                have_apzone for have_apzone in removable_data.get("apZones", [])
                if have_apzone.get("apZoneName") != ap_zone_name
            ]
            zones_removed += 1
        else:
            self.log(
                "AP zone '{0}' not found in current profile configuration - skipping removal".format(
                    ap_zone_name
                ),
                "WARNING"
            )

        self.log(
            "AP zone removal completed - removed {0}/{1} AP zones from profile".format(
                zones_removed, total_zones
            ),
            "INFO"
        )

        return zones_removed > 0

    def _remove_feature_template_designs(self, each_profile, removable_data, have_profile_name):
        """
        Remove feature template design configurations from the wireless network profile.

        Parameters:
            each_profile (dict): Profile configuration containing feature templates to remove
            removable_data (dict): Current profile data to modify
            have_profile_name (str): Name of existing profile for logging

        Returns:
            bool: True if feature templates were removed, False otherwise
        """

        self.log(
            "Starting feature template designs removal process for wireless network profile",
            "DEBUG"
        )

        feature_template_designs = each_profile.get("feature_template_designs")
        if not feature_template_designs:
            self.log(
                "No feature template designs specified for removal - skipping template processing",
                "DEBUG"
            )
            return False

        templates_removed = 0
        total_templates = len(feature_template_designs)

        self.log(
            "Processing feature template removal for {0} template designs from profile '{1}'".format(
                total_templates, have_profile_name
            ),
            "INFO"
        )

        for feature_template in feature_template_designs:
            feature_template_names = feature_template.get("feature_templates")

            if not feature_template_names:
                self.log(
                    "Skipping feature template entry with missing template names",
                    "WARNING"
                )
                continue

            for each_feature_template in feature_template_names:
                if self.value_exists(
                    removable_data.get("featureTemplates", []),
                    "designName",
                    each_feature_template,
                ):
                    self.log(
                        "Removing feature template '{0}' from profile '{1}' during deletion".format(
                            each_feature_template, have_profile_name
                        ),
                        "INFO"
                    )
                    removable_data["featureTemplates"] = [
                        have_feature_template
                        for have_feature_template in removable_data.get("featureTemplates", [])
                        if have_feature_template.get("designName") != each_feature_template
                    ]
                    templates_removed += 1
                else:
                    self.log(
                        "Feature template '{0}' not found in profile - skipping removal".format(
                            each_feature_template
                        ),
                        "WARNING"
                    )

        self.log(
            "Feature template removal completed - removed {0} template designs from profile".format(
                templates_removed
            ),
            "INFO"
        )

        return templates_removed > 0

    def _remove_day_n_templates(self, each_profile, each_have_profile, have_profile_id):
        """
        Remove Day-N template assignments from the wireless network profile.

        Parameters:
            each_profile (dict): Profile configuration containing Day-N templates to remove
            each_have_profile (dict): Current profile state information
            have_profile_id (str): Profile ID for template unassignment

        Returns:
            list: Results of template unassignment operations
        """

        self.log(
            "Starting Day-N templates removal process for wireless network profile",
            "DEBUG"
        )

        day_n_templates = each_profile.get("day_n_templates")
        if not day_n_templates:
            self.log("No Day-N templates specified for removal - skipping template processing", "DEBUG")
            return []

        unassign_templates = []
        templates_removed = 0
        profile_name = each_profile.get("profile_name")

        self.log(
            "Processing Day-N template removal for {0} templates from profile '{1}'".format(
                len(day_n_templates), profile_name
            ),
            "INFO"
        )

        for day_n_template in day_n_templates:
            if not self.value_exists(
                each_have_profile.get("day_n_templates", {}),
                "template_name",
                day_n_template,
            ):
                self.log(
                    "Day-N template '{0}' not found in current profile assignments - skipping".format(
                        day_n_template
                    ),
                    "WARNING"
                )
                continue

            for have_day_n_template in each_have_profile.get("day_n_templates", {}):
                template_name = have_day_n_template.get("template_name")
                template_id = have_day_n_template.get("template_id")

                if template_name == day_n_template:
                    self.log(
                        "Unassigning Day-N template '{0}' (ID: {1}) from profile '{2}'".format(
                            template_name, template_id, profile_name
                        ),
                        "INFO"
                    )

                    result = self.detach_networkprofile_cli_template(
                        profile_name, have_profile_id, template_name, template_id
                    )
                    unassign_templates.append(result)
                    templates_removed += 1

                    self.log(
                        "Successfully unassigned Day-N template '{0}' from profile '{1}'".format(
                            template_name, profile_name
                        ),
                        "INFO"
                    )

        self.log(
            "Day-N template removal completed - removed {0} template assignments from profile".format(
                templates_removed
            ),
            "INFO"
        )

        return unassign_templates

    def _remove_site_names(self, each_profile, each_have_profile, have_profile_name, have_profile_id):
        """
        Remove site name assignments from the wireless network profile.

        Parameters:
            each_profile (dict): Profile configuration containing site names to remove
            each_have_profile (dict): Current profile state information
            have_profile_name (str): Name of existing profile for logging
            have_profile_id (str): Profile ID for site unassignment

        Returns:
            list: Results of site unassignment operations
        """

        self.log(
            "Starting site names removal process for wireless network profile",
            "DEBUG"
        )

        site_names = each_profile.get("site_names")
        if not site_names:
            self.log("No site names specified for removal - skipping site processing", "DEBUG")
            return []

        unassign_sites = []
        sites_removed = 0

        self.log(
            "Processing site removal for {0} sites from profile '{1}'".format(
                len(site_names), have_profile_name
            ),
            "INFO"
        )

        for site_name in site_names:
            if not self.value_exists(
                each_have_profile.get("site_response", {}),
                "site_names",
                site_name,
            ):
                self.log(
                    "Site '{0}' not found in current profile assignments - skipping removal".format(
                        site_name
                    ),
                    "WARNING"
                )
                continue

            for have_site in each_have_profile.get("site_response", {}):
                have_site_name = have_site.get("site_names")
                have_site_id = have_site.get("site_id")

                if have_site_name == site_name:
                    self.log(
                        "Unassigning site '{0}' from profile '{1}' during removal process".format(
                            site_name, have_profile_name
                        ),
                        "INFO"
                    )

                    unassign_response = self.unassign_site_to_network_profile(
                        have_profile_name, have_profile_id, have_site_name, have_site_id
                    )
                    unassign_sites.append(unassign_response)
                    sites_removed += 1

                    self.log(
                        "Successfully unassigned site '{0}' from profile '{1}'".format(
                            have_site_name, have_profile_name
                        ),
                        "INFO"
                    )

        self.log(
            "Site removal completed - removed {0} site assignments from profile".format(
                sites_removed
            ),
            "INFO"
        )

        return unassign_sites

    def get_diff_deleted(self, each_profile):
        """
        Delete Network profile based on the given profile ID
        Network configurations in Cisco Catalyst Center based on the playbook details

        Parameters:
            each_profile (dict): The profile details to be deleted from Cisco Catalyst Center.

        Returns:
            self - The current object with deleted status and return response with task details.
        """
        self.log(
            "Starting comprehensive wireless network profile deletion process for profile management",
            "INFO"
        )

        profile_name = each_profile.get("profile_name")
        self.log(
            "Processing profile deletion request for profile configuration: {0}".format(
                self.pprint(each_profile)
            ),
            "DEBUG"
        )

        if not isinstance(each_profile, dict):
            self.log(
                "Invalid each_profile parameter - expected dict, got: {0}".format(
                    type(each_profile).__name__
                ),
                "ERROR"
            )
            self.msg = "Invalid profile configuration provided for deletion"
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        if not profile_name:
            self.log(
                "Profile name missing in deletion configuration - cannot proceed with deletion",
                "ERROR"
            )
            self.msg = "Profile name is required for deletion operations"
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        # Phase 1: Validate profile existence
        if not self.value_exists(
            self.have["wireless_profile_list"], "name", profile_name
        ):
            self.msg = "No changes required, profile(s) are already deleted"
            self.log(self.msg, "INFO")
            self.set_operation_result(
                "success", False, self.msg, "INFO"
            ).check_return_status()
            return self

        each_have = self.have.get("wireless_profile")
        have_profile_info = each_have.get("profile_info")

        if not have_profile_info:
            self.msg = (
                "No changes were made. The specified profile(s) either do not exist "
                "or have already been deleted."
            )
            self.log(self.msg, "INFO")
            self.set_operation_result(
                "success", False, self.msg, "INFO"
            ).check_return_status()
            return self

        have_profile_name = have_profile_info.get("wirelessProfileName")
        have_profile_id = have_profile_info.get("id")

        if have_profile_name != profile_name:
            self.msg = "Profile name not matching: {0}".format(profile_name)
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        if not have_profile_id:
            self.log(
                "Profile ID missing for profile '{0}' - cannot proceed with deletion".format(
                    profile_name
                ),
                "ERROR"
            )
            self.msg = "Profile ID not found for deletion operations"
            self.fail_and_exit(self.msg)

        self.log(
            "Profile validation completed - proceeding with deletion for profile '{0}' "
            "with ID '{1}'".format(have_profile_name, have_profile_id),
            "INFO"
        )

        have_profile_id = each_have.get("profile_info", {}).get("id")

        # Determine deletion type based on profile components
        profile_components_specified = any(each_profile.get(key) for key in [
            "site_names", "ssid_details", "day_n_templates",
            "additional_interfaces", "ap_zones", "feature_template_designs"
        ])

        if not profile_components_specified:
            self.log(
                "No specific components specified - proceeding with complete profile deletion "
                "for profile '{0}'".format(have_profile_name),
                "INFO"
            )

            # Phase 2: Complete Profile Deletion
            sites = each_have.get("previous_sites")

            if sites:
                self.log(
                    "Phase 2a: Unassigning {0} sites before complete profile deletion".format(
                        len(sites)
                    ),
                    "INFO"
                )

                unassign_site = []
                sites_unassigned = 0

                for each_site in sites:
                    site_id = each_site.get("id")
                    site_name = each_site.get("name", "Unknown")

                    self.log(
                        "Unassigning site '{0}' (ID: {1}) from profile '{2}' before deletion".format(
                            site_name, site_id, have_profile_name
                        ),
                        "INFO"
                    )
                    unassign_response = self.unassign_site_to_network_profile(
                        have_profile_name,
                        have_profile_id,
                        site_id,
                        site_id,
                    )

                    if unassign_response:
                        sites_unassigned += 1
                        unassign_site.append(unassign_response)
                        self.log(
                            "Successfully unassigned site '{0}' from profile '{1}'".format(
                                site_name, have_profile_name
                            ),
                            "INFO"
                        )

                self.log(
                    "Site unassignment completed - unassigned {0}/{1} sites from profile".format(
                        sites_unassigned, len(sites)
                    ),
                    "INFO"
                )
            else:
                self.log(
                    "No sites associated with profile '{0}' - skipping site unassignment".format(
                        have_profile_name
                    ),
                    "INFO"
                )

            # Phase 2b: Delete the complete profile
            self.log(
                "Phase 2b: Executing complete profile deletion for profile '{0}' "
                "with ID '{1}'".format(have_profile_name, have_profile_id),
                "INFO"
            )

            task_details = None
            if have_profile_id:
                task_details = self.delete_network_profiles(
                    profile_name, have_profile_id
                )

            if not task_details:
                self.not_processed.append(each_profile)
                self.msg = "Unable to delete profile: '{0}'.".format(
                    str(self.not_processed)
                )
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

            profile_response = dict(
                profile_name=profile_name,
                status=task_details["progress"]
            )

            self.deleted.append(profile_response)
            self.msg = "Wireless Profile deleted successfully for '{0}'.".format(
                str(self.deleted)
            )

            self.log(self.msg, "INFO")
            self.set_operation_result(
                "success", True, self.msg, "INFO", each_profile
            ).check_return_status()

        else:
            # Phase 3: Selective Component Removal
            self.log(
                "Specific profile components specified - proceeding with selective "
                "component removal for profile '{0}'".format(have_profile_name),
                "INFO"
            )

            remove_status = self.remove_network_profile_data(each_profile, each_have) or {}

            self.log(
                "Profile component removal status: {0}".format(
                    self.pprint(remove_status)
                ),
                "DEBUG"
            )

            # Validate removal operation results
            removal_occurred = any(remove_status.get(key, False) for key in [
                "site_remove_status", "day_n_templates_status", "ssid_status",
                "ap_zones_status", "feature_template_designs_status",
                "additional_interfaces_status"
            ])

            if not remove_status or not removal_occurred:
                self.msg = (
                    "Profile data already removed or not exist to remove data from "
                    "profile: '{0}'.".format(have_profile_name)
                )
                self.log(self.msg, "DEBUG")
                self.already_removed.append(have_profile_name)
                self.set_operation_result(
                    "success", False, self.msg, "INFO", have_profile_name
                ).check_return_status()
                return self

            # Build comprehensive removal success message
            self.msg = "Wireless Profile data removed successfully for '{0}'.".format(
                profile_name
            )

            response_status = {}
            # Process site removal status
            if remove_status.get("site_remove_status"):
                sites = each_profile.get("site_names", [])
                sites_message = "Sites '{0}' unassigned successfully.".format(
                    "', '".join(sites)
                )
                self.msg += " " + sites_message
                response_status["site_remove_status"] = sites_message

            # Process Day N template removal status
            if remove_status.get("day_n_templates_status"):
                templates = each_profile.get("day_n_templates", [])
                templates_message = "Day N templates '{0}' unassigned successfully.".format(
                    "', '".join(templates)
                )
                self.msg += " " + templates_message
                response_status["day_n_templates_status"] = templates_message

            # Process SSID removal status
            if remove_status.get("ssid_status"):
                ssids = each_profile.get("ssid_details", [])
                ssid_names = [ssid.get("ssid_name") for ssid in ssids if ssid.get("ssid_name")]

                if ssid_names:
                    ssids_message = "SSIDs '{0}' removed successfully.".format(
                        "', '".join(ssid_names)
                    )
                    self.msg += " " + ssids_message
                    response_status["ssid_status"] = ssids_message

            # Process additional interfaces removal status
            if remove_status.get("additional_interfaces_status"):
                additional_interfaces = each_profile.get("additional_interfaces", [])
                interface_names = [
                    interface.get("interface_name")
                    for interface in additional_interfaces
                    if interface.get("interface_name")
                ]

                if interface_names:
                    interfaces_message = "Additional Interfaces '{0}' removed successfully.".format(
                        "', '".join(interface_names)
                    )
                    self.msg += " " + interfaces_message
                    response_status["additional_interfaces_status"] = interfaces_message

            # Process AP zones removal status
            if remove_status.get("ap_zones_status"):
                ap_zones = each_profile.get("ap_zones", [])
                zone_names = [
                    zone.get("ap_zone_name")
                    for zone in ap_zones
                    if zone.get("ap_zone_name")
                ]

                if zone_names:
                    zones_message = "AP Zones '{0}' removed successfully.".format(
                        "', '".join(zone_names)
                    )
                    self.msg += " " + zones_message
                    response_status["ap_zones_status"] = zones_message

            # Process feature template designs removal status
            if remove_status.get("feature_template_designs_status"):
                feature_template_designs = each_profile.get("feature_template_designs", [])
                template_names = []
                for design in feature_template_designs:
                    template_names.extend(design.get("feature_templates", []))

                if template_names:
                    feature_templates_message = (
                        "Feature Template Designs '{0}' removed successfully.".format(
                            "', '".join(template_names)
                        )
                    )
                    self.msg += " " + feature_templates_message
                    response_status["feature_template_designs_status"] = feature_templates_message

            self.remove_profile_data.append({profile_name: response_status})

            self.log(self.msg, "INFO")
            self.set_operation_result(
                "success", True, self.msg, "INFO", remove_status
            ).check_return_status()

        # Comprehensive deletion operation logging
        total_components_processed = sum([
            1 if each_profile.get("site_names") else 0,
            1 if each_profile.get("ssid_details") else 0,
            1 if each_profile.get("day_n_templates") else 0,
            1 if each_profile.get("additional_interfaces") else 0,
            1 if each_profile.get("ap_zones") else 0,
            1 if each_profile.get("feature_template_designs") else 0
        ])

        deletion_type = "Complete profile deletion" if not profile_components_specified else "Selective component removal"

        self.log(
            "Wireless network profile deletion process completed for profile '{0}' - "
            "operation type: {1}, components processed: {2}".format(
                profile_name, deletion_type, total_components_processed
            ),
            "INFO"
        )

        return self

    def verify_diff_deleted(self, config):
        """
        Verify the deletion status of wireless network profile in Cisco Catalyst Center.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.

        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Description:
            This method checks the deletion status of a configuration in Cisco Catalyst Center.
            It validates whether the specified profile exists in the Cisco Catalyst Center.
        """
        if self.remove_profile_data:
            msg = "Wireless profile data removed successfully for: {0}".format(
                self.remove_profile_data
            )
            self.log(msg, "INFO")
            self.set_operation_result(
                "success", True, msg, "INFO", self.remove_profile_data
            ).check_return_status()
            return self

        if self.already_removed:
            self.log(self.msg, "INFO")
            self.set_operation_result(
                "success", False, self.msg, "INFO", self.already_removed
            ).check_return_status()
            return self

        if self.get_wireless_profile(config.get("profile_name")):
            msg = "Unable to delete below wireless profile '{0}'.".format(
                config.get("profile_name")
            )
            self.log(msg, "INFO")
            self.set_operation_result(
                "failed", False, msg, "INFO", config.get("profile_name")
            ).check_return_status()

        msg = "Wireless profile deleted and verified successfully"
        self.log(msg, "INFO")
        self.set_operation_result(
            "success", True, msg, "INFO", msg
        ).check_return_status()

        return self

    def final_response_message(self, state):
        """
        To show the final message with Wireless profile response

        Parameters:
            configs (list of dict) - Playbook config contains Wireless profile
            playbook information.

        Returns:
            self - Return response as verified created/updated/deleted
            Wireless profile messages
        """
        if state == "merged":
            if self.created:
                self.msg = "Wireless profile(s) created/updated and verified successfully: {0}".format(
                    self.created
                )
                status = "success"
                if self.not_processed:
                    self.msg += " Unable to create the following profiles: {0}".format(
                        self.not_processed
                    )
                    status = "failed"
                self.log(self.msg, "INFO")
                self.set_operation_result(
                    status, True, self.msg, "INFO", self.created
                ).check_return_status()
            elif not self.created and not self.not_processed:
                self.msg = "No changes required, profile(s) already exist."
                self.log(self.msg, "INFO")
                self.set_operation_result(
                    "success", False, self.msg, "INFO"
                ).check_return_status()
            else:
                self.msg = "Unable to create the following profiles: {0}".format(
                    self.not_processed
                )
                self.log(self.msg, "ERROR")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR", self.not_processed
                ).check_return_status()

        elif state == "deleted":
            if self.deleted:
                self.msg = (
                    "Wireless profile(s) deleted and verified successfully: {0}".format(
                        self.deleted
                    )
                )
                status = "success"
                if self.not_processed:
                    self.msg += " Unable to delete the following profiles: {0}".format(
                        self.not_processed
                    )
                    status = "failed"
                self.log(self.msg, "INFO")
                self.set_operation_result(
                    status, True, self.msg, "INFO", self.deleted
                ).check_return_status()
            elif self.not_processed:
                self.msg = "Unable to delete the following profiles: {0}".format(
                    self.not_processed
                )
                self.log(self.msg, "ERROR")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR", self.not_processed
                ).check_return_status()
            elif self.remove_profile_data:
                self.msg = "Wireless profile data removed successfully for: {0}".format(
                    self.remove_profile_data
                )
                self.log(self.msg, "INFO")
                self.set_operation_result(
                    "success", True, self.msg, "INFO", self.remove_profile_data
                ).check_return_status()
            elif self.already_removed:
                self.log(self.msg, "INFO")
                self.set_operation_result(
                    "success", False, self.msg, "INFO", self.already_removed
                ).check_return_status()
                return self
            else:
                self.msg = "Wireless profile(s) already deleted for: {0}".format(
                    self.config
                )
                self.log(self.msg, "INFO")
                self.set_operation_result(
                    "success", False, self.msg, "INFO", self.config
                ).check_return_status()

        return self


def main():
    """main entry point for module execution"""

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
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"type": "list", "required": True, "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
        "validate_response_schema": {"type": "bool", "default": True},
    }

    # Create an AnsibleModule object with argument specifications
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    ccc_wireless_profile = NetworkWirelessProfile(module)
    state = ccc_wireless_profile.params.get("state")

    if (
        ccc_wireless_profile.compare_dnac_versions(
            ccc_wireless_profile.get_ccc_version(), "2.3.7.9"
        )
        < 0
    ):
        ccc_wireless_profile.status = "failed"
        ccc_wireless_profile.msg = (
            "The specified version '{0}' does not support the network profile workflow feature."
            "Supported version(s) start from '2.3.7.9' onwards.".format(
                ccc_wireless_profile.get_ccc_version()
            )
        )
        ccc_wireless_profile.log(ccc_wireless_profile.msg, "ERROR")
        ccc_wireless_profile.check_return_status()

    if state not in ccc_wireless_profile.supported_states:
        ccc_wireless_profile.status = "invalid"
        ccc_wireless_profile.msg = "State {0} is invalid".format(state)
        ccc_wireless_profile.check_return_status()

    ccc_wireless_profile.validate_input().check_return_status()
    config_verify = ccc_wireless_profile.params.get("config_verify")

    for config in ccc_wireless_profile.validated_config:
        if not config:
            ccc_wireless_profile.msg = "Playbook configuration is missing."
            ccc_wireless_profile.log(ccc_wireless_profile.msg, "ERROR")
            ccc_wireless_profile.fail_and_exit(ccc_wireless_profile.msg)

        ccc_wireless_profile.reset_values()
        ccc_wireless_profile.get_want(config).check_return_status()
        ccc_wireless_profile.get_have(config).check_return_status()
        ccc_wireless_profile.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_wireless_profile.verify_diff_state_apply[state](
                config
            ).check_return_status()

    ccc_wireless_profile.final_response_message(state).check_return_status()
    module.exit_json(**ccc_wireless_profile.result)


if __name__ == "__main__":
    main()
