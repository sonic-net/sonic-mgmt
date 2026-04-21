#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to perform Network Compliance Operations on devices in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Rugvedi Kapse, Madhan Sankaranarayanan, Sonali Deepthi Kesali"
DOCUMENTATION = r"""
---
module: network_compliance_workflow_manager
short_description: Network Compliance module for managing
  network compliance tasks on reachable device(s) in
  Cisco Catalyst Center.
description:
  - Perform compliance checks or sync configurations
    on reachable devices using IP Address(s) or Site.
  - API to perform full compliance checks or specific
    category checks on reachable device(s).
  - API to sync device configuration on device(s).
version_added: "6.14.0"
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Rugvedi Kapse (@rukapse) Madhan Sankaranarayanan
  (@madhansansel) Sonali Deepthi (@skesali)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst
      Center config after applying the playbook config.
    type: bool
    default: false
  state:
    description: State of Cisco Catalyst Center after
      module completion.
    type: str
    choices: [merged]
    default: merged
  config:
    description: List of device details for running
      a compliance check or synchronizing device configuration.
    type: list
    elements: dict
    required: true
    suboptions:
      ip_address_list:
        description: List of IP addresses of devices
          to run a compliance check on or synchronize
          device configurations. Either "ip_address_list"
          or "site_name" is required for module to execute.
          If both "site_name" and "ip_address_list"
          are provided, operations are performed on
          devices that are present in both the "ip_address_list"
          and the specified site. (e.g. ["204.1.2.2",
          "204.1.2.5", "204.1.2.4"])
        type: list
        elements: str
      site_name:
        description: When "site_name" is specified,
          the module executes the operation on all the
          devices located within the specified site.
          This is a string value that should represent
          the complete hierarchical path of the site.
          Either "site_name" or "ip_address_list" is
          required for module to execute. If both "site_name"
          and "ip_address_list" are provided, operations
          are performed on devices that are present
          in both the "ip_address_list" and the specified
          site. (e.g. "Global/USA/San Francisco/Building_2/floor_1")
        type: str
      run_compliance:
        description: Determines if a full compliance
          check should be triggered on the devices specified
          in the "ip_address_list" and/or "site_name".
          if it is True then compliance will be triggered
          for all categories. If it is False then compliance
          will be not be triggered even if run_compliance
          categories are provided. Note - This operation
          cannot be performed on Access Points (APs)
          and if APs are provided, they will be skipped.
        type: bool
        default: true
      run_compliance_batch_size:
        description: Specifies the number of devices
          to be included in a single batch for compliance
          operations. This parameter is crucial for
          optimizing performance during large-scale
          compliance checks. By processing devices in
          manageable batches, the system can enhance
          the speed and efficiency of the operation,
          reducing the overall time required and minimizing
          the risk of overloading system resources.
          Adjusting this parameter allows for a balance
          between throughput and resource utilization,
          ensuring smooth and effective compliance management.
          Note - Having a higher value for run_compliance_batch_size
          may cause errors due to the increased load
          on the system.
        type: int
        default: 100
      run_compliance_categories:
        description: Specifying compliance categories
          allows you to trigger compliance checks only
          for the mentioned categories. Category can
          have one or more values from among the options
          "INTENT", "RUNNING_CONFIG", "IMAGE", "PSIRT",
          "EOX", "NETWORK_SETTINGS". Category "INTENT"
          is mapped to compliance types "NETWORK_SETTINGS",
          "NETWORK_PROFILE", "WORKFLOW", "FABRIC", "APPLICATION_VISIBILITY".
          If "run_compliance" is False then compliance
          will be not be triggered even if "run_compliance_categories"
          are provided. (e.g. ["INTENT", "RUNNING_CONFIG",
          "IMAGE", "PSIRT", "EOX", "NETWORK_SETTINGS"])
        type: list
        elements: str
      sync_device_config:
        description: Determines whether to synchronize
          the device configuration on the devices specified
          in the "ip_address_list" and/or "site_name".
          Sync device configuration, primarily addresses
          the status of the `RUNNING_CONFIG`. If set
          to True, and if `RUNNING_CONFIG` status is
          non-compliant this operation would commit
          device running configuration to startup by
          issuing "write memory" to device. Note - This
          operation cannot be performed on Access Points
          (APs) and if APs are provided, they will be
          skipped.
        type: bool
        default: false
requirements:
  - dnacentersdk == 2.7.0
  - python >= 3.9
notes:
  - SDK Methods used are compliance.Compliance.run_compliance
    compliance.Compliance.commit_device_configuration
    task.Task.get_task_by_id task.Task.get_task_details_by_id
    task.Task.get_tasks compliance.Compliance.compliance_details_of_device
    devices.Devices.get_device_list devices.Devices.get_device_by_id
    site.Site.get_site site.Site.get_membership site_design.Site_design.get_sites
    site_design.Site_design.get_site_assigned_network_devices
  - Paths used are
    post /dna/intent/api/v1/compliance/
    post /dna/intent/api/v1/network-device-config/write-memory
    get /dna/intent/api/v1/task/{taskId} get /dna/intent/api/v1/compliance/${deviceUuid}/detail
    get /dna/intent/api/v1/membership/${siteId} get
    /dna/intent/api/v1/site get /dna/intent/api/v1/networkDevices/assignedToSite
    get /dna/intent/api/v1/sites get /dna/intent/api/v1/tasks/${id}/detail
    get /dna/intent/api/v1/tasks get /dna/intent/api/v1/network-device/${id}
    get /dna/intent/api/v1/network-device
"""
EXAMPLES = r"""
---
- name: Run Compliance check on device(s) using IP address
    list (run_compliance by default is True)
  cisco.dnac.network_compliance_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    config:
      - ip_address_list: ["204.1.2.2", "204.1.2.5", "204.1.2.4"]
- name: Run Compliance check on device(s) using IP address
    list
  cisco.dnac.network_compliance_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    config:
      - ip_address_list: ["204.1.2.2", "204.1.2.5", "204.1.2.4"]
        run_compliance: true
- name: Run Compliance check on device(s) using Site
  cisco.dnac.network_compliance_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    config:
      - site_name: "Global/USA/San Francisco/Building_1/floor_1"
        run_compliance: true
- name: Run Compliance check on device(s) using both
    IP address list and Site
  cisco.dnac.network_compliance_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    config:
      - ip_address_list: ["204.1.2.2", "204.1.2.5", "204.1.2.4"]
        site_name: "Global/USA/San Francisco/Building_1/floor_1"
        run_compliance: true
- name: Run Compliance check with specific categories
    on device(s) using IP address list
  cisco.dnac.network_compliance_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    config:
      - ip_address_list: ["204.1.2.2", "204.1.2.5", "204.1.2.4"]
        run_compliance: true
        run_compliance_categories: ["INTENT", "RUNNING_CONFIG", "IMAGE", "PSIRT"]
- name: Run Compliance check with specific categories
    on device(s) using Site
  cisco.dnac.network_compliance_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    config:
      - site_name: "Global/USA/San Francisco/Building_1/floor_1"
        run_compliance: true
        run_compliance_categories: ["INTENT", "RUNNING_CONFIG", "IMAGE", "PSIRT"]
- name: Run Compliance check with specific categories
    on device(s) using both IP address list and Site
  cisco.dnac.network_compliance_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    config:
      - ip_address_list: ["204.1.2.2", "204.1.2.5", "204.1.2.4"]
        site_name: "Global/USA/San Francisco/Building_1/floor_1"
        run_compliance: true
        run_compliance_categories: ["INTENT", "RUNNING_CONFIG", "IMAGE", "PSIRT"]
- name: Sync Device Configuration on device(s) using
    IP address list
  cisco.dnac.network_compliance_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    config:
      - site_name: "Global"
        sync_device_config: true
        run_compliance: false
- name: Sync Device Configuration on device(s) using
    Site
  cisco.dnac.network_compliance_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    config:
      - site_name: "Global/USA/San Francisco/Building_1/floor_1"
        sync_device_config: true
        run_compliance: false
- name: Sync Device Configuration on device(s) using
    both IP address list and Site
  cisco.dnac.network_compliance_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    config:
      - ip_address_list: ["204.1.2.2", "204.1.2.5", "204.1.2.4"]
        site_name: "Global/USA/San Francisco/Building_1/floor_1"
        sync_device_config: true
        run_compliance: false
- name: Run Compliance and Sync Device Configuration
    using both IP address list and Site
  cisco.dnac.network_compliance_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    config:
      - ip_address_list: ["204.1.2.2", "204.1.2.5", "204.1.2.4"]
        site_name: "Global/USA/San Francisco/Building_1/floor_1"
        run_compliance: true
        run_compliance_categories: ["INTENT", "RUNNING_CONFIG", "IMAGE", "PSIRT"]
        sync_device_config: true
"""
RETURN = r"""
#Case_1: Response when Run Compliance operation is performed successfully on device/s.
sample_response_1:
  description: A dictionary with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "status": "string",
      "changed": bool,
      "msg": "string"
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "data": dict,
      "version": "string"
    }
#Case_2: Response when Sync Device Configuration operation is performed successfully on device/s.
sample_response_2:
  description: A dictionary with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "status": "string",
      "changed": bool,
      "msg": "string"
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
#Case_3: Response when Error Occurs in performing Run Compliance or Sync Device Configuration operation on device/s.
sample_response_3:
  description: A dictionary with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "changed": bool,
      "msg": "string"
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)


class NetworkCompliance(DnacBase):
    """Class containing member attributes for network_compliance_workflow_manager module"""

    def __init__(self, module):
        """
        Initialize an instance of the class.
        Args:
          - module: The module associated with the class instance.
        Returns:
          The method does not return a value.
        """
        super().__init__(module)
        self.supported_states = ["merged"]
        self.skipped_run_compliance_devices_list = []
        self.skipped_sync_device_configs_list = []

    def validate_input(self):
        """
        Validate the fields provided in the playbook against a predefined specification
        to ensure they adhere to the expected structure and data types.
        Args:
            state (optional): A state parameter that can be used to customize validation
                              based on different conditions.
        Returns:
            object: An instance of the class with updated attributes:
              - self.msg: A message describing the validation result.
              - self.status: The status of the validation (either "success" or "failed").
              - self.validated_config: If successful, a validated version of the "config" parameter.
        Description:
            This method validates the fields provided in the playbook against a predefined specification.
            It checks if the required fields are present and if their data types match the expected types.
            If any parameter is found to be invalid, it logs an error message and sets the validation status to "failed".
            If the validation is successful, it logs a success message and returns an instance of the class
            with the validated configuration.
        """
        if not self.config:
            self.msg = "config not available in playbook for validation"
            self.status = "success"
            self.log(self.msg, "ERROR")
            return self

        temp_spec = {
            "ip_address_list": {"type": "list", "elements": "str", "required": False},
            "site_name": {"type": "str", "required": False},
            "run_compliance": {"type": "bool", "required": False, "default": True},
            "run_compliance_categories": {
                "type": "list",
                "elements": "str",
                "required": False,
            },
            "run_compliance_batch_size": {
                "type": "int",
                "required": False,
                "default": 100,
            },
            "sync_device_config": {"type": "bool", "required": False, "default": False},
        }

        # Validate device params
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(invalid_params)
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.validated_config = valid_temp

        self.msg = "Successfully validated playbook configuration parameters using 'validated_input': {0}".format(
            str(valid_temp)
        )
        self.log(self.msg, "INFO")
        self.status = "success"

        return self

    def validate_ip4_address_list(self, ip_address_list):
        """
        Validates the list of IPv4 addresses provided in the playbook.
        Args:
            ip_address_list (list): A list of IPv4 addresses to be validated.
        Description:
            This method iterates through each IP address in the list and checks if it is a valid IPv4 address.
            If any address is found to be invalid, it logs an error message and fails.
            After validating all IP addresses, it logs a success message.
        """
        self.log(
            "Validating the IP addresses in the ip_address_list: {0}".format(
                ip_address_list
            ),
            "DEBUG",
        )

        for ip in ip_address_list:
            if not self.is_valid_ipv4(ip):
                self.msg = "IP address: {0} is not valid".format(ip)
                self.log(self.msg, "ERROR")
                self.module.fail_json(self.msg)

        ip_address_list_str = ", ".join(ip_address_list)
        self.log(
            "Successfully validated the IP address(es): {0}".format(
                ip_address_list_str
            ),
            "DEBUG",
        )

    def validate_iplist_and_site_name(self, ip_address_list, site_name):
        """
        Validates that either an IP address list or a site name is provided.
        This function checks if at least one of the parameters `ip_address_list` or `site_name` is provided.
        If neither is provided, it logs an error message and exits the process. If validation is successful,
        it logs a success message.
        Args:
            ip_address_list (list): A list of IP addresses to be validated.
            site_name (str): A site name to be validated.
        Raises:
            SystemExit: If neither `ip_address_list` nor `site_name` is provided, the function logs an error message and exits the process.
        """
        self.log(
            "Validating 'ip_address_list': '{0}' or 'site_name': '{1}'".format(
                ip_address_list, site_name
            ),
            "DEBUG",
        )

        # Check if IP address list or hostname is provided
        if not any([ip_address_list, site_name]):
            self.msg = "Error: Neither 'ip_address_list' nor 'site_name' was provided. Provided values: 'ip_address_list': {0}, 'site_name': {1}.".format(
                ip_address_list, site_name
            )
            self.fail_and_exit(self.msg)

        # Validate if valid ip_addresses in the ip_address_list
        if ip_address_list:
            self.validate_ip4_address_list(ip_address_list)

        self.log(
            "Validation successful: Provided IP address list or Site name is valid"
        )

    def validate_compliance_operation(
        self, run_compliance, run_compliance_categories, sync_device_config
    ):
        """
        Validates if any network compliance operation is requested.
        Args:
            run_compliance (bool): Indicates if a compliance check operation is requested.
            run_compliance_categories (list): A list of compliance categories to be checked.
            sync_device_config (bool): Indicates if a device configuration synchronization is requested.
        Raises:
            Exception: If no compliance operation is requested, raises an exception with a message.
        """
        self.log(
            "Validating if any network compliance operation is requested: "
            "run_compliance={0}, run_compliance_categories={1}, sync_device_config={2}".format(
                run_compliance, run_compliance_categories, sync_device_config
            ),
            "DEBUG",
        )

        if not any([run_compliance, run_compliance_categories, sync_device_config]):
            self.msg = (
                "No actions were requested. This network compliance module can perform the following tasks: "
                "Run Compliance Check or Sync Device Config."
            )
            self.set_operation_result("ok", False, self.msg, "INFO")
            self.module.exit_json(**self.result)

        self.log("Validation successful: Network Compliance operation present")

    def validate_run_compliance_categories(self, run_compliance_categories):
        """
        Validates the provided Run Compliance categories.
        Args:
        run_compliance_categories (list): A list of compliance categories to be checked.
        Raises:
            Exception: If invalid categories are provided, raises an exception with a message.
        """
        self.log(
            "Validating the provided run compliance categories: {0}".format(
                run_compliance_categories
            ),
            "DEBUG",
        )

        valid_categories = [
            "INTENT",
            "RUNNING_CONFIG",
            "IMAGE",
            "PSIRT",
            "EOX",
            "NETWORK_SETTINGS",
        ]
        if not all(
            category.upper() in valid_categories
            for category in run_compliance_categories
        ):
            valid_categories_str = ", ".join(valid_categories)
            self.msg = "Invalid category provided. Valid categories are {0}.".format(
                valid_categories_str
            )
            self.fail_and_exit(self.msg)

        self.log(
            "Validation successful: valid run compliance categorites provided: {0}".format(
                run_compliance_categories
            ),
            "DEBUG",
        )

    def validate_params(self, config):
        """
        Validates the provided configuration for network compliance operations.
        Args:
            config (dict): A dictionary containing the configuration parameters.
        Validations:
            - Ensures that either ip_address_list or site_name is provided.
            - Checks if a network compliance operation is requested.
            - Validates the compliance categories if provided.
        Raises:
            Exception: If any validation fails, raises an exception with a message.
        """
        self.log("Validating the provided configuration: {0}".format(config), "INFO")
        ip_address_list = config.get("ip_address_list")
        site_name = config.get("site_name")
        run_compliance = config.get("run_compliance")
        run_compliance_categories = config.get("run_compliance_categories")
        sync_device_config = config.get("sync_device_config")
        self.log(
            "Extracted parameters - IP Address List: {0}, Site Name: {1}, Run Compliance: {2}, "
            "Run Compliance Categories: {3}, Sync Device Config: {4}".format(
                ip_address_list,
                site_name,
                run_compliance,
                run_compliance_categories,
                sync_device_config,
            ),
            "DEBUG",
        )

        # Validate either ip_address_list OR site_name is present
        self.validate_iplist_and_site_name(ip_address_list, site_name)

        # Validate if a network compliance operation is present
        self.validate_compliance_operation(
            run_compliance, run_compliance_categories, sync_device_config
        )

        # Validate the categories if provided
        if run_compliance_categories:
            self.validate_run_compliance_categories(run_compliance_categories)

        self.log("Validation completed for configuration: {0}".format(config), "INFO")

    def get_run_compliance_params(
        self, mgmt_ip_to_instance_id_map, run_compliance, run_compliance_categories
    ):
        """
        Validate and prepare parameters for running compliance checks.
        Args:
            - mgmt_ip_to_instance_id_map (dict): A dictionary mapping management IP addresses to device instance IDs.
            - run_compliance (bool or None): A boolean indicating whether to run compliance checks.
            - run_compliance_categories (list): A list of compliance categories to check.
        Returns:
        tuple: A tuple containing two dictionaries:
            - run_compliance_params: Parameters for running compliance checks.
        Notes:
            - This method prepares parameters for running compliance checks based on the provided inputs.
            - If invalid categories are provided in `run_compliance_categories`, a `ValueError` is raised.
            - If `run_compliance_categories` is provided and neither `run_compliance` nor `run_compliance_categories` is set, an error
              is logged and the method fails.
            - If `run_compliance` is set and `run_compliance_categories` is not, full compliance checks are triggered.
            - If both `run_compliance` and `run_compliance_categories` are set, compliance checks are triggered for specific categories.
        """
        # Initializing empty dicts/lists
        run_compliance_params = {}

        # Create run_compliance_params
        if run_compliance:
            run_compliance_params["deviceUuids"] = list(
                mgmt_ip_to_instance_id_map.values()
            )
            run_compliance_params["triggerFull"] = not bool(run_compliance_categories)
            if run_compliance_categories:
                run_compliance_params["categories"] = run_compliance_categories

        # Check for devices with Compliance Status of "IN_PROGRESS" and update parameters accordingly
        if run_compliance_params:
            device_in_progress = set()

            response = self.get_compliance_report(
                run_compliance_params, mgmt_ip_to_instance_id_map
            )

            if not response:
                ip_address_list_str = ", ".join(list(mgmt_ip_to_instance_id_map.keys()))
                self.msg = (
                    "Error occurred when retrieving Compliance Report to identify if there are "
                    "devices with 'IN_PROGRESS' status. This is required on device(s): {0}".format(
                        ip_address_list_str
                    )
                )
                self.fail_and_exit(self.msg)

            # Iterate through the response to identify devices with 'IN_PROGRESS' status
            for device_ip, compliance_details_list in response.items():
                for compliance_type in compliance_details_list:
                    if compliance_type.get("status") == "IN_PROGRESS":
                        device_in_progress.add(compliance_type.get("deviceUuid"))

            self.log(
                "Number of devices with Compliance Status 'IN_PROGRESS': {0}. Device UUIDs: {1}".format(
                    len(device_in_progress), list(device_in_progress)
                ),
                "DEBUG",
            )
            if device_in_progress:
                # Update run_compliance_params to exclude devices with 'IN_PROGRESS' status
                run_compliance_params["deviceUuids"] = [
                    device_id
                    for device_id in mgmt_ip_to_instance_id_map.values()
                    if device_id not in device_in_progress
                ]
                msg = "Excluding 'IN_PROGRESS' devices from compliance check. Updated run_compliance_params: {0}".format(
                    run_compliance_params
                )
                self.log(msg, "DEBUG")

        self.log("run_compliance_params: {0}".format(run_compliance_params), "DEBUG")
        return run_compliance_params

    def get_sync_device_config_params(
        self, mgmt_ip_to_instance_id_map, categorized_devices
    ):
        """
        Generates parameters for syncing device configurations, excluding compliant and other categorized devices.
        Args:
            mgmt_ip_to_instance_id_map (dict): A dictionary mapping management IP addresses to instance IDs of devices.
            categorized_devices (dict): A dictionary categorizing devices by their compliance status.
        Returns:
            dict: A dictionary containing the device IDs to be used for syncing device configurations.
        Description:
            This method generates a dictionary of parameters required for syncing device configurations. It initially includes all device
            IDs from `mgmt_ip_to_instance_id_map`. It then excludes devices categorized as "OTHER" or "COMPLIANT" from the sync operation.
            The excluded devices' IPs are logged and added to the `skipped_sync_device_configs_list`. The updated list of device IDs to be synced
            is returned.
        """
        self.log(
            "Entering get_sync_device_config_params method with mgmt_ip_to_instance_id_map: {0}, categorized_devices: {1}".format(
                mgmt_ip_to_instance_id_map, categorized_devices
            ),
            "DEBUG",
        )

        sync_device_config_params = {
            "deviceId": list(mgmt_ip_to_instance_id_map.values())
        }

        other_device_ips = categorized_devices.get("OTHER", {}).keys()
        compliant_device_ips = categorized_devices.get("COMPLIANT", {}).keys()
        excluded_device_ips = set(other_device_ips) | set(compliant_device_ips)

        self.log(
            "Identified other device IPs: {0}".format(", ".join(other_device_ips)),
            "DEBUG",
        )
        self.log(
            "Identified compliant device IPs: {0}".format(
                ", ".join(compliant_device_ips)
            ),
            "DEBUG",
        )
        self.log(
            "Identified excluded device IPs: {0}".format(
                ", ".join(excluded_device_ips)
            ),
            "DEBUG",
        )

        if excluded_device_ips:
            self.skipped_sync_device_configs_list.extend(excluded_device_ips)
            excluded_device_uuids = [
                mgmt_ip_to_instance_id_map[ip]
                for ip in excluded_device_ips
                if ip in mgmt_ip_to_instance_id_map
            ]
            sync_device_config_params["deviceId"] = [
                device_id
                for device_id in mgmt_ip_to_instance_id_map.values()
                if device_id not in excluded_device_uuids
            ]
            excluded_device_ips_str = ", ".join(excluded_device_ips)
            msg = "Skipping these devices because their compliance status is not 'NON_COMPLIANT': {0}".format(
                excluded_device_ips_str
            )
            self.log(msg, "WARNING")
            self.log(
                "Updated 'sync_device_config_params' parameters: {0}".format(
                    sync_device_config_params
                ),
                "DEBUG",
            )

        self.log(
            "Final sync_device_config_params: {0}".format(sync_device_config_params),
            "DEBUG",
        )
        return sync_device_config_params

    def get_device_list_params(self, ip_address_list):
        """
        Generates a dictionary of device parameters for querying Cisco Catalyst Center.
        Args:
            config (dict): A dictionary containing device filter criteria.
        Returns:
            dict: A dictionary mapping internal parameter names to their corresponding values from the config.
        Description:
            This method takes a configuration dictionary containing various device filter criteria and maps them to the internal parameter
            names required by Cisco Catalyst Center.
            It returns a dictionary of these mapped parameters which can be used to query devices based on the provided filters.
        """
        self.log(
            "Entering get_device_list_params method with ip_address_list: {0}".format(
                ip_address_list
            ),
            "DEBUG",
        )

        # Initialize an empty dictionary to store the mapped parameters
        get_device_list_params = {"management_ip_address": ip_address_list}

        self.log(
            "Generated get_device_list_params: {0}".format(get_device_list_params),
            "DEBUG",
        )
        return get_device_list_params

    def get_device_ids_from_ip(self, get_device_list_params):
        """Retrieves device IDs based on specified parameters from Cisco Catalyst Center.
        Args:
            get_device_list_params (dict): A dictionary of parameters to filter devices.
        Returns:
            dict: A dictionary mapping management IP addresses to instance IDs of reachable devices that are not Unified APs.
        Description:
            This method queries Cisco Catalyst Center to retrieve device information based on the provided filter parameters.
            It paginates through the results, filters out unreachable devices and Unified APs, and returns a dictionary of management IP addresses
            mapped to their instance IDs.
            Logs detailed information about the number of devices processed, skipped, and the final list of devices available for configuration backup.
        """
        self.log(
            "Entering 'get_device_ids_from_ip' method with parameters: {0}".format(
                get_device_list_params
            ),
            "DEBUG",
        )

        mgmt_ip_to_instance_id_map = {}
        processed_device_count = 0
        skipped_device_count = 0

        try:
            offset = 1
            limit = 500
            while True:
                # Update params with current offset and limit
                get_device_list_params.update({"offset": offset, "limit": limit})

                # Query Cisco Catalyst Center for device information using the parameters
                response = self.dnac._exec(
                    family="devices",
                    function="get_device_list",
                    op_modifies=False,
                    params=get_device_list_params,
                )
                self.log(
                    "Response received post 'get_device_list' API call with offset {0}: {1}".format(
                        offset, str(response)
                    ),
                    "DEBUG",
                )

                # Check if a valid response is received
                if not response.get("response"):
                    self.log(
                        "Exiting the loop because no devices were returned after increasing the offset. Current offset: {0}".format(
                            offset
                        )
                    )
                    break  # Exit loop if no devices are returned

                response = response.get("response")
                # Iterate over the devices in the response
                for device_info in response:
                    processed_device_count += 1
                    device_ip = device_info.get("managementIpAddress", "Unknown IP")
                    reachability_status = device_info.get("reachabilityStatus")
                    collection_status = device_info.get("collectionStatus")
                    device_family = device_info.get("family")
                    device_id = device_info.get("id")

                    self.log(
                        "Processing device with IP: {0}, Reachability: {1}, Collection Status: {2}, Family: {3}".format(
                            device_ip,
                            reachability_status,
                            collection_status,
                            device_family,
                        ),
                        "DEBUG",
                    )
                    # Check if the device is reachable and managed
                    if reachability_status == "Reachable" and collection_status in [
                        "In Progress",
                        "Managed",
                    ]:
                        # Skip Unified AP devices
                        if device_family != "Unified AP":
                            mgmt_ip_to_instance_id_map[device_ip] = device_id
                        else:
                            skipped_device_count += 1
                            self.skipped_run_compliance_devices_list.append(device_ip)
                            self.skipped_sync_device_configs_list.append(device_ip)
                            msg = "Skipping device {0} as its family is: {1}.".format(
                                device_ip, device_family
                            )
                            self.log(msg, "INFO")

                    else:
                        self.skipped_run_compliance_devices_list.append(device_ip)
                        self.skipped_sync_device_configs_list.append(device_ip)
                        skipped_device_count += 1
                        msg = "Skipping device {0} as its status is {1} or its collectionStatus is {2}.".format(
                            device_ip, reachability_status, collection_status
                        )
                        self.log(msg, "INFO")

                # Check if the response size is less than the limit
                if len(response) < limit:
                    self.log(
                        "Received less than limit ({0}) results, assuming last page. Exiting pagination.".format(
                            limit
                        ),
                        "DEBUG",
                    )
                    break

                # Increment offset for next batch
                offset += limit

            # Check if the IP from get_device_list_params is in mgmt_ip_to_instance_id_map
            for ip in get_device_list_params.get("management_ip_address", []):
                if ip not in mgmt_ip_to_instance_id_map:
                    self.skipped_run_compliance_devices_list.append(ip)
                    self.skipped_sync_device_configs_list.append(ip)

            # Log the total number of devices processed and skipped
            self.log(
                "Total number of devices received: {0}".format(processed_device_count),
                "INFO",
            )
            self.log(
                "Number of devices that are Unreachable or APs: {0}".format(
                    skipped_device_count
                ),
                "INFO",
            )
            self.log(
                "Config Backup Operation can be performed on the following filtered devices: {0}".format(
                    len(mgmt_ip_to_instance_id_map)
                ),
                "INFO",
            )

        except Exception as e:
            # Log an error message if any exception occurs during the process
            self.msg = "Error fetching device IDs from Cisco Catalyst Center. Error details: {0}".format(
                str(e)
            )
            self.fail_and_exit(self.msg)

        # Log an error if no reachable devices are found
        if not mgmt_ip_to_instance_id_map:
            self.log(
                "No reachable devices found among the provided parameters: {0}".format(
                    mgmt_ip_to_instance_id_map
                ),
                "ERROR",
            )

        return mgmt_ip_to_instance_id_map

    def get_device_id_list(self, ip_address_list, site_name):
        """
        Get the list of unique device IDs for a specified list of management IP addresses or devices associated with a site
        in Cisco Catalyst Center.
        Args:
            ip_address_list (list): The management IP addresses of devices for which you want to retrieve the device IDs.
            site_name (str): The name of the site for which you want to retrieve the device IDs.
        Returns:
            dict: A dictionary mapping management IP addresses to device IDs for the specified devices.
        Description:
            This method queries Cisco Catalyst Center to retrieve the unique device IDs associated with devices having the
            specified IP addresses or belonging to the specified site.
        """
        self.log(
            "Entering get_device_id_list with args: ip_address_list={0}, site_name={1}".format(
                ip_address_list, site_name
            ),
            "DEBUG",
        )

        # Initialize a dictionary to store management IP addresses and their corresponding device IDs
        mgmt_ip_to_instance_id_map = {}

        if ip_address_list:
            self.log(
                "Starting retrieval of device IDs for IP addresses: {0}".format(
                    ", ".join(ip_address_list)
                ),
                "DEBUG",
            )
            self.log(
                "Initial size of IP address list: {0}".format(len(ip_address_list)),
                "DEBUG",
            )

            # Split the IP address list into batches of 200
            batch_size = 200

            # Calculate total number of batches
            total_batches = (len(ip_address_list) + batch_size - 1) // batch_size
            self.log(
                "Calculating total number of batches. "
                "IP address list length: {0}, Batch size: {1}. "
                "Computed total batches: {2}".format(
                    len(ip_address_list), batch_size, total_batches
                ),
                "INFO",
            )
            for batch_number, i in enumerate(
                range(0, len(ip_address_list), batch_size), start=1
            ):
                ip_batch = ip_address_list[i : i + batch_size]
                self.log(
                    "Processing batch {0} of {1}: IP addresses: {2}".format(
                        batch_number, total_batches, ", ".join(ip_batch)
                    ),
                    "DEBUG",
                )

                # Get device list parameters for the current batch
                get_device_list_params = self.get_device_list_params(ip_batch)
                self.log(
                    "Device list parameters for batch {0}: {1}".format(
                        batch_number, get_device_list_params
                    ),
                    "DEBUG",
                )

                # Retrieve device IDs for the current batch
                iplist_mgmt_ip_to_instance_id_map = self.get_device_ids_from_ip(
                    get_device_list_params
                )
                self.log(
                    "Retrieved device IDs for batch {0}: {1}".format(
                        batch_number, iplist_mgmt_ip_to_instance_id_map
                    ),
                    "DEBUG",
                )

                # Update the main map with the results from the current batch
                mgmt_ip_to_instance_id_map.update(iplist_mgmt_ip_to_instance_id_map)

            self.log("Completed retrieval of device IDs.", "DEBUG")

        # Check if both site name and IP address list are provided
        if site_name:
            self.log("Retrieving device IDs for site: {0}".format(site_name), "DEBUG")
            site_mgmt_ip_to_instance_id_map, skipped_devices_list = (
                self.get_reachable_devices_from_site(site_name)
            )
            self.skipped_run_compliance_devices_list.extend(skipped_devices_list)
            self.skipped_sync_device_configs_list.extend(skipped_devices_list)
            mgmt_ip_to_instance_id_map.update(site_mgmt_ip_to_instance_id_map)

        if not mgmt_ip_to_instance_id_map:
            # Log an error message if mgmt_ip_to_instance_id_map is empty
            self.msg = (
                "No device UUIDs were fetched for network compliance operations with the provided IP address(es): {0} "
                "or site name: {1}. This could be due to Unreachable devices or access points (APs)."
            ).format(ip_address_list, site_name)
            self.fail_and_exit(self.msg)

        return mgmt_ip_to_instance_id_map

    def is_sync_required(self, response, mgmt_ip_to_instance_id_map):
        """
        Determine if synchronization of device configurations is required.

        Args:
            response (dict): A dictionary containing modified responses for each device.
            mgmt_ip_to_instance_id_map (dict): A dictionary mapping management IP addresses to instance IDs.

        Returns:
            tuple: A tuple containing a boolean indicating whether synchronization is required
                   and a message explaining the result.

        Note:
            This method categorizes devices based on compliance status ("COMPLIANT", "NON_COMPLIANT", "OTHER")
            and checks if synchronization is necessary. If all devices are "COMPLIANT", synchronization is not
            required. If there are devices that are not "NON_COMPLIANT", synchronization is also not required.
        """
        task_name = "Sync Device Configuration"
        required = True
        msg = None

        # Validate if sync is required
        self.log(
            "Compliance Report for {0} operation for device(s) {1} : {2}".format(
                task_name, list(mgmt_ip_to_instance_id_map.keys()), response
            ),
            "INFO",
        )

        # Categorize the devices based on status - "COMPLIANT", "NON_COMPLIANT", "OTHER"(status other than COMPLIANT and NON_COMPLIANT)
        categorized_devices = {"COMPLIANT": {}, "NON_COMPLIANT": {}, "OTHER": {}}
        for ip_address, compliance_type in response.items():
            status = compliance_type[0]["status"]
            if status == "NON_COMPLIANT":
                categorized_devices["NON_COMPLIANT"][ip_address] = compliance_type
            elif status == "COMPLIANT":
                categorized_devices["COMPLIANT"][ip_address] = compliance_type
            else:
                categorized_devices["OTHER"][ip_address] = compliance_type

        self.log(
            "Device(s) Categorized based on Compliance status: {0}".format(
                categorized_devices
            ),
            "INFO",
        )

        # Validate if all devices are "COMPLIANT" - then sync not required
        if len(categorized_devices["COMPLIANT"]) + len(
            categorized_devices["OTHER"]
        ) == len(mgmt_ip_to_instance_id_map):
            compliant_device_ips_str = ", ".join(
                list(mgmt_ip_to_instance_id_map.keys())
            )
            msg = (
                "Device(s) with IP address(es): {0} are already compliant with the RUNNING_CONFIG compliance type. "
                "Therefore, the task '{1}' is not required."
            ).format(compliant_device_ips_str, task_name)
            required = False

        return required, msg, categorized_devices

    def get_compliance_details_of_device(
        self, compliance_details_of_device_params, device_ip
    ):
        """
        Retrieve compliance details for a specific device.
        This function makes an API call to fetch compliance details for a given device
        using the specified parameters. It handles the API response and logs the
        necessary information.
        Args:
            compliance_details_of_device_params (dict): Parameters required for the compliance details API call.
            device_ip (str): The IP address of the device for which compliance details are being fetched.
        Returns:
            dict or None: The response from the compliance details API call if successful,
                          None if an error occurs or no response is received.
        """
        self.log(
            "Attempting to retrieve Compliance details for device: '{0}'".format(
                device_ip
            ),
            "INFO",
        )
        response = self.execute_get_request(
            "compliance",
            "compliance_details_of_device",
            compliance_details_of_device_params,
        )
        if response:
            self.log(
                "Sucessfully retrieved Compliance details for device: '{0}'".format(
                    device_ip
                ),
                "INFO",
            )
            return response.get("response")
        else:
            self.log(
                "No Compliance details retrieved for device: '{0}' with parameters: {1}".format(
                    device_ip, compliance_details_of_device_params
                ),
                "WARNING",
            )
            return None

    def get_compliance_report(self, run_compliance_params, mgmt_ip_to_instance_id_map):
        """
        Generate a compliance report for devices based on provided parameters.
        This function fetches the compliance details for a list of devices specified
        in the run_compliance_params. It maps the device UUIDs to their corresponding
        management IPs, and then retrieves the compliance details for each device.
        Args:
            run_compliance_params (dict): Parameters for running compliance checks.
                                          Expected to contain "deviceUuids" and optionally "categories".
            mgmt_ip_to_instance_id_map (dict): Mapping of device management IPs to device UUIDs.

        Returns:
            dict: A dictionary with device management IPs as keys and lists of compliance details as values.
        """
        # Initialize the lists/dicts
        final_response = {}
        device_list = []
        compliance_details_of_device_params = {}
        device_ip = None

        # Iterate through each device UUID in the run compliance parameters
        for device_uuid in run_compliance_params["deviceUuids"]:

            # Find the corresponding device IP for the given device UUID
            for ip, device_id in mgmt_ip_to_instance_id_map.items():
                if device_uuid == device_id:
                    device_ip = ip
                    break

            if device_ip is None:
                self.log(
                    "Device UUID: {0} not found in mgmt_ip_to_instance_id_map: {1}".format(
                        device_uuid, mgmt_ip_to_instance_id_map
                    ),
                    "DEBUG",
                )
                continue

            # Add the device IP to the device list
            device_list.append(device_ip)

            # Initialize the response list for the device IP if not already present
            if device_ip not in final_response.keys():
                final_response[device_ip] = []

            # Check if categories are specified and fetch details for each category of the device
            if "categories" in run_compliance_params.keys():
                for category in run_compliance_params["categories"]:
                    compliance_details_of_device_params["category"] = category
                    compliance_details_of_device_params["device_uuid"] = device_uuid
                    compliance_details_of_device_params["diff_list"] = True

                    response = self.get_compliance_details_of_device(
                        compliance_details_of_device_params, device_ip
                    )
                    if response:
                        final_response[device_ip].extend(response)

            else:
                # Fetch compliance details for the device without specific category
                compliance_details_of_device_params["device_uuid"] = device_uuid
                compliance_details_of_device_params["diff_list"] = True
                response = self.get_compliance_details_of_device(
                    compliance_details_of_device_params, device_ip
                )
                if response:
                    final_response[device_ip].extend(response)

        # If no compliance details were found, update the result with an error message
        if not final_response:
            device_list_str = ", ".join(device_list)
            self.msg = "No Compliance Details found for the devices: {0}".format(
                device_list_str
            )
            self.fail_and_exit(self.msg)

        return final_response

    def run_compliance(self, run_compliance_params, batch_size):
        """
        Executes a compliance check operation in Cisco Catalyst Center.
        Args:
            run_compliance_params (dict): Parameters for running the compliance check.
            batch_size (int): The number of devices to include in each batch.
        Returns:
            batches_dict: A dictionary containing task IDs and parameters for each batch, or an empty dictionary if unsuccessful
        Description:
            This method initiates a compliance check operation in Cisco Catalyst Center by calling the "run_compliance" function
            from the "compliance" family of APIs. It passes the provided parameters and updates the result accordingly.
        """
        # Execute the compliance check operation
        device_uuids = run_compliance_params.get("deviceUuids")
        if not device_uuids:
            self.msg = "No device UUIDs were found for the execution of the compliance operation."
            self.set_operation_result("ok", False, self.msg, "INFO")
            self.module.exit_json(**self.result)

        batches_dict = {}

        if len(device_uuids) > batch_size:
            batches = [
                device_uuids[i : i + batch_size]
                for i in range(0, len(device_uuids), batch_size)
            ]
        else:
            batches = [device_uuids]
        self.log(
            "Created {0} batch(es) for run compliance operation: {1}".format(
                len(batches), batches
            ),
            "DEBUG",
        )

        for idx, batch in enumerate(batches):
            self.log(
                "Executing 'run_compliance' operation on batch: {0} - {1}".format(
                    idx, batch
                ),
                "DEBUG",
            )
            batch_params = run_compliance_params.copy()
            batch_params["deviceUuids"] = batch
            self.log("Batch {0} Parameters: {1}".format(idx, batch_params), "DEBUG")

            task_id = self.get_taskid_post_api_call(
                "compliance", "run_compliance", batch_params
            )
            if task_id:
                batches_dict[idx] = {"task_id": task_id, "batch_params": batch_params}
            else:
                self.log(
                    "No response received from the 'run_compliance' API call for batch: {0}.".format(
                        batch_params
                    ),
                    "ERROR",
                )

        return batches_dict

    def sync_device_config(self, sync_device_config_params):
        """
        Synchronize the device configuration using the specified parameters.
        Args:
            - sync_device_config_params (dict): Parameters for synchronizing the device configuration.
        Returns:
            task_id (str): The ID of the task created for the synchronization operation.
        Note:
            This method initiates the synchronization of device configurations by making an API call to the Cisco Catalyst Center.
            It logs the response received from the API call and extracts the task ID from the response for further monitoring.
            If an error occurs during the API call, it will be caught and logged.
        """
        # Make an API call to synchronize device configuration
        return self.get_taskid_post_api_call(
            "compliance", "commit_device_configuration", sync_device_config_params
        )

    def handle_error(self, task_name, mgmt_ip_to_instance_id_map, failure_reason=None):
        """
        Handle error encountered during task execution.
        Args:
            - task_name (str): Name of the task being performed.
            - mgmt_ip_to_instance_id_map (dict): Mapping of management IP addresses to instance IDs.
            - failure_reason (str, optional): Reason for the failure, if available.
        Returns:
            self (object): An instance of the class used for interacting with Cisco Catalyst Center.
        """
        # If failure reason is provided, include it in the error message
        ip_address_list_str = ", ".join(list(mgmt_ip_to_instance_id_map.keys()))
        if failure_reason:
            self.msg = "An error occurred while performing {0} on device(s): {1}. The operation failed due to the following reason: {2}".format(
                task_name, ip_address_list_str, failure_reason
            )
        # If no failure reason is provided, generate a generic error message
        else:
            self.msg = (
                "An error occurred while performing {0} on device(s): {1}".format(
                    task_name, ip_address_list_str
                )
            )

        # Update the result with failure status and log the error message
        self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def get_batches_result(self, batches_dict):
        """
        Retrieves the results of compliance check tasks for a list of device batches.
        Args:
            batches_dict (dict): A dictionary where each key is a batch index and the value is a dictionary
                                 containing 'task_id' and 'batch_params'.
        Returns:
            list: A list of dictionaries where each dictionary contains the 'task_id', 'batch_params',
                  'task_status', and 'msg' for each batch.
        Description:
            This function iterates over the provided batches, retrieves the task status for each batch,
            and stores the result including task ID, batch parameters, task status, and message.
        """
        batches_result = []
        task_name = "Run Compliance"

        for idx, batch_info in batches_dict.items():
            task_id = batch_info["task_id"]
            device_ids = batch_info["batch_params"]["deviceUuids"]
            success_msg = "{0} Task with Task ID: '{1}' for batch number: '{2}' with {3} devices: {4} is successful.".format(
                task_name, task_id, idx, len(device_ids), device_ids
            )

            # Get task status for the current batch
            if self.dnac_version <= self.version_2_3_5_3:
                failure_msg = "{0} Task with Task ID: '{1}' Failed for batch number: '{2}' with {3} devices: {4}.".format(
                    task_name, task_id, idx, len(device_ids), device_ids
                )
                progress_validation = "report has been generated successfully"
                self.get_task_status_from_task_by_id(
                    task_id,
                    task_name,
                    failure_msg,
                    success_msg,
                    progress_validation=progress_validation,
                )
            else:
                self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

            task_status = self.status
            self.log(
                "The task status of batch: {0} with task id: {1} is {2}".format(
                    idx, task_id, task_status
                ),
                "INFO",
            )

            # Store the result for the current batch
            batch_result = {
                "task_id": task_id,
                "batch_params": batch_info["batch_params"],
                "task_status": task_status,
                "msg": success_msg,
            }

            # Append the current batch result to the batches_result list
            batches_result.append(batch_result)

        self.log(
            "Collective result of all batches: {0}".format(batches_result), "DEBUG"
        )
        return batches_result

    def validate_batch_result(self, batches_result, retried_batches=None):
        """
        Validates the results of compliance check tasks for device batches.
        Args:
            batches_status (list): A list of dictionaries where each dictionary contains 'task_id',
                                   'batch_params', 'task_status', and 'msg' for each batch.
        Returns:
            list: A list of device IDs that have successfully completed the compliance check.
        Description:
            This function iterates over the provided batches status, checks the task status for each batch,
            and collects the device IDs for batches that have completed successfully. For batches that failed,
            it re-runs the compliance check with a batch size of 1, validates the results recursively, and collects
            the successful device IDs.
        """
        if retried_batches is None:
            retried_batches = set()
        successful_devices = []

        # Iterate over each batch in the batches_status list
        for batch in batches_result:
            task_status = batch.get("task_status")
            batch_params = batch.get("batch_params")
            device_ids = tuple(batch_params.get("deviceUuids"))

            # Check if the task status is successful
            if task_status == "success":
                successful_devices.extend(device_ids)
            else:
                # Check if the batch has already been retried with batch size of 1
                if device_ids in retried_batches:
                    device_ids_str = ", ".join(device_ids)
                    self.log(
                        "Batch for device(s) {0} has already been retried with batch size of 1 and failed. "
                        "Stopping recursion.".format(device_ids_str),
                        "ERROR",
                    )
                    continue

                self.log(
                    "Re-running compliance check for batch {0} with batch_result: {1} ".format(
                        batch, batches_result
                    ),
                    "WARNING",
                )
                # Re-run the compliance check for the failed batch with batch size of 1
                retried_batches.add(device_ids)
                batches_dict = self.run_compliance(batch_params, batch_size=1)
                batches_result = self.get_batches_result(batches_dict)

                # Recursively validate the batch results and append the successful device IDs
                successful_devices.extend(
                    self.validate_batch_result(
                        batches_result, retried_batches=retried_batches
                    )
                )
        msg = (
            "The results of all batches have been validated, and the compliance checks "
            "were successfully executed on following devices: {0}".format(
                successful_devices
            )
        )
        self.log(msg, "DEBUG")

        return successful_devices

    def get_compliant_non_compliant_devices(self, compliance_report):
        """
        Classifies devices into compliant and non-compliant categories based on their compliance reports.
        Args:
            compliance_report (dict): A dictionary where each key is a device IP address (str), and the value is a list of dictionaries.
                                      Each dictionary in the list contains compliance information for the device,
                                      including a 'status' key.
        Returns:
            tuple: A tuple containing two lists:
                - compliant_devices (list of str): A list of device IPs that are fully compliant.
                - non_compliant_devices (list of str): A list of device IPs that have at least one non-compliant status.
        Description:
            This method iterates over each device's compliance report and determines its compliance status.
            A device is considered compliant if all compliance items have a status of "COMPLIANT".
            Devices are classified based on whether they are fully compliant or not, and the results are logged.
        """
        # Lists to store compliant and non-compliant devices
        compliant_devices = []
        non_compliant_devices = []

        # Iterate over each device's compliance report
        for device_ip, compliance_data in compliance_report.items():
            # Assume the device is compliant unless a non-compliant status is found
            is_compliant = True

            # Check each compliance type's status
            for item in compliance_data:
                if item["status"] != "COMPLIANT":
                    is_compliant = False
                    break

            # Classify the device based on its compliance status
            if is_compliant:
                compliant_devices.append(device_ip)
            else:
                non_compliant_devices.append(device_ip)

        # Log the results
        self.log("Compliant devices: {0}".format(compliant_devices), "INFO")
        self.log("Non-compliant devices: {0}".format(non_compliant_devices), "INFO")

        return compliant_devices, non_compliant_devices

    def get_compliance_task_status(self, batches_dict, mgmt_ip_to_instance_id_map):
        """
        Retrieves and processes compliance check task statuses for multiple batches.
        Args:
            batches_dict (dict): A dictionary containing information about each batch of compliance tasks.
            mgmt_ip_to_instance_id_map (dict): A dictionary mapping management IP addresses to instance IDs.
        Returns:
            self
        Description:
            This function processes the compliance check statuses for multiple batches of devices. It determines
            which devices were successful and which were unsuccessful. If any batches were successful, it logs
            the success message, updates the result, and retrieves compliance reports. If all batches failed,
            it logs the failure message and updates the result accordingly.
        """
        task_name = "Run Compliance Check"
        batches_result = self.get_batches_result(batches_dict)
        successful_devices = self.validate_batch_result(batches_result)
        successful_devices_str = ", ".join(successful_devices)
        self.log(
            "{0} successful on device(s): {1}".format(
                task_name, successful_devices_str
            ),
            "DEBUG",
        )

        # Reverse the mgmt_ip_to_instance_id_map to map device IDs to IPs
        id_to_ip_map = {v: k for k, v in mgmt_ip_to_instance_id_map.items()}

        # Determine unsuccessful devices
        all_device_ids = [
            device_id
            for batch in batches_dict.values()
            for device_id in batch["batch_params"]["deviceUuids"]
        ]
        unsuccessful_devices = list(set(all_device_ids) - set(successful_devices))
        unsuccessful_ips = [
            id_to_ip_map[device_id]
            for device_id in unsuccessful_devices
            if device_id in id_to_ip_map
        ]

        final_msg = {}

        if successful_devices:
            successful_ips = [
                id_to_ip_map[device_id]
                for device_id in successful_devices
                if device_id in id_to_ip_map
            ]

            successful_devices_params = self.want.get("run_compliance_params").copy()
            successful_devices_params["deviceUuids"] = successful_devices
            compliance_report = self.get_compliance_report(
                successful_devices_params, mgmt_ip_to_instance_id_map
            )
            self.log(
                "Compliance Report for device on which compliance operation was successful: {0}".format(
                    compliance_report
                ),
                "INFO",
            )

            compliant_devices, non_compliant_devices = (
                self.get_compliant_non_compliant_devices(compliance_report)
            )
            self.log(
                "{0} Succeeded for following device(s): {1}".format(
                    task_name, successful_ips
                ),
                "INFO",
            )
            final_msg["{0} Succeeded for following device(s)".format(task_name)] = {
                "Total Devices Checked": len(successful_ips),
                # "success_devices": successful_ips,
                "Compliant Devices": len(compliant_devices),
                "Non-Compliant Devices": len(non_compliant_devices),
            }

        if unsuccessful_ips:
            self.log(
                "{0} Failed for following device(s): {1}".format(
                    task_name, unsuccessful_ips
                ),
                "ERROR",
            )
            final_msg["{0} Failed for following device(s)".format(task_name)] = {
                "failed_count": len(unsuccessful_ips),
                "failed_devices": unsuccessful_ips,
            }

        self.msg = final_msg

        # Determine the final operation result
        if successful_devices and unsuccessful_devices:
            self.log(
                "Partial success: Some devices were successful, but others failed.",
                "DEBUG",
            )
            self.set_operation_result(
                "failed", True, self.msg, "ERROR", additional_info=compliance_report
            )
        elif successful_devices:
            self.log(
                "Operation successful: All devices processed successfully.", "DEBUG"
            )
            self.set_operation_result(
                "success", True, self.msg, "INFO", additional_info=compliance_report
            )
        elif unsuccessful_devices:
            self.log(
                "Operation failed: No devices were processed successfully.", "DEBUG"
            )
            self.set_operation_result("failed", True, self.msg, "ERROR")
        else:
            self.log("No devices to process.", "INFO")
            self.set_operation_result("ok", False, self.msg, "INFO")

        return self

    def get_sync_config_task_status(self, task_id, mgmt_ip_to_instance_id_map):
        """
        This function manages the status of device configuration synchronization tasks in Cisco Catalyst Center.
        Args:
            - task_id: ID of the synchronization task
            - mgmt_ip_to_instance_id_map: Mapping of management IP addresses to instance IDs
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            It validates if synchronization is required, categorizes devices based on compliance status, and checks task completion status.
            If all devices are already compliant, it logs a success message. If some devices have unexpected statuses, it logs an error.
            It continuously checks the task status until completion, updating the result accordingly.
        """
        task_name = "Sync Device Configuration"
        self.log(
            "Entering '{0}' with task_id: '{1}' and mgmt_ip_to_instance_id_map: {2}".format(
                task_name, task_id, mgmt_ip_to_instance_id_map
            ),
            "INFO",
        )
        msg = {}

        # Retrieve the parameters for sync device config
        sync_device_config_params = self.want.get("sync_device_config_params")
        self.log(
            "Sync device config parameters: {0}".format(sync_device_config_params),
            "DEBUG",
        )

        # Extract the list of device IDs from sync_device_config_params
        device_ids = sync_device_config_params.get("deviceId")
        self.log("Device IDs for synchronization: {0}".format(device_ids), "DEBUG")

        # Create device_ip_list by mapping the device IDs back to their corresponding IP addresses
        device_ip_list = [
            ip
            for ip, device_id in mgmt_ip_to_instance_id_map.items()
            if device_id in device_ids
        ]
        self.log("Device IPs to synchronize: {0}".format(device_ip_list), "DEBUG")

        msg["{0} Succeeded for following device(s)".format(task_name)] = {
            "success_count": len(device_ip_list),
            "success_devices": device_ip_list,
        }

        # Retrieve and return the task status using the provided task ID
        return self.get_task_status_from_tasks_by_id(task_id, task_name, msg)

    def process_final_result(self, final_status_list):
        """
        Processes a list of final statuses and returns a tuple indicating the result and a boolean flag.
        Args:
            final_status_list (list): List of status strings to process.
        Returns:
            tuple: A tuple containing a status string ("ok" or "success") and a boolean flag (False if all statuses are "ok", True otherwise).
        """
        status_set = set(final_status_list)

        if status_set == {"ok"}:
            return "ok", False
        else:
            return "success", True

    def verify_sync_device_config(self):
        """
        Verify the success of the "Sync Device Configuration" operation.
        Args:
            config (dict): A dictionary containing the configuration details.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies the success of the "Sync Device Configuration" operation in the context of network compliance management.
            It checks if the configuration includes the option to synchronize device configurations (`sync_device_config`).
            If this option is present, the function proceeds to compare compliance details before and after executing the synchronization operation.
            It logs relevant information at each step and concludes by determining whether the synchronization was successful.
        """
        # Get compliance details before running sync_device_config
        compliance_details_before = self.want.get("compliance_details")
        self.log(
            "Compliance details before running sync_device_config: {0}".format(
                compliance_details_before
            ),
            "INFO",
        )

        # Get compliance details after running sync_device_config
        compliance_details_after = self.get_compliance_report(
            self.want.get("compliance_detail_params_sync"),
            self.want.get("mgmt_ip_to_instance_id_map"),
        )
        if not compliance_details_after:
            self.msg = "Error occurred when Retrieving Compliance Details after for verifying configuration."
            self.fail_and_exit(self.msg)

        self.log(
            "Compliance details after running sync_device_config: {0}.".format(
                compliance_details_after
            ),
            "INFO",
        )

        # Get the device IDs to check
        sync_device_ids = self.want.get("sync_device_config_params").get("deviceId", [])
        if not sync_device_ids:
            self.log(
                "No device IDs found in sync_device_config_params, Sync Device Configuration "
                "operation may not have been performed.",
                "WARNING",
            )
            return self

        # Initialize the status lists
        all_statuses_before = []
        all_statuses_after = []

        # Iterate over the device IDs and check their compliance status
        self.log("Device IDs to check: {0}".format(sync_device_ids), "DEBUG")
        for device_id in sync_device_ids:
            # Find the corresponding IP address from the mgmt_ip_to_instance_id_map
            ip_address = next(
                (
                    ip
                    for ip, id in self.want.get("mgmt_ip_to_instance_id_map").items()
                    if id == device_id
                ),
                None,
            )
            self.log(
                "Found IP address for device ID {0}: {1}".format(device_id, ip_address),
                "DEBUG",
            )
            if ip_address:
                self.log(
                    "Checking compliance status for device ID: {0}".format(device_id),
                    "DEBUG",
                )
                # Get the status before
                compliance_before = compliance_details_before.get(ip_address, [])
                if compliance_before:
                    all_statuses_before.append(compliance_before[0]["status"])
                else:
                    self.log(
                        "No compliance details found for device IP: {0} before synchronization.".format(
                            ip_address
                        ),
                        "DEBUG",
                    )
                # Get the status after
                compliance_after = compliance_details_after.get(ip_address, [])
                if compliance_after:
                    all_statuses_after.append(compliance_after[0]["status"])
                else:
                    self.log(
                        "No compliance details found for device IP: {0} after synchronization.".format(
                            ip_address
                        ),
                        "DEBUG",
                    )

                self.log(
                    "Compliance statuses before synchronization: {0}".format(
                        all_statuses_before
                    ),
                    "DEBUG",
                )
                self.log(
                    "Compliance statuses after synchronization: {0}".format(
                        all_statuses_after
                    ),
                    "DEBUG",
                )

            else:
                self.log(
                    "No IP address found for device ID: {0}".format(device_id), "DEBUG"
                )

        # Check if all statuses changed from "NON_COMPLIANT" to "COMPLIANT"
        if all(
            all_status == "NON_COMPLIANT" for all_status in all_statuses_before
        ) and all(all_status == "COMPLIANT" for all_status in all_statuses_after):
            self.log("Verified the success of the Sync Device Configuration operation.")
        else:
            self.log(
                "Sync Device Configuration operation may have been unsuccessful "
                "since not all devices have 'COMPLIANT' status after the operation.",
                "WARNING",
            )

    def get_want(self, config):
        """
        Determines the desired state based on the provided configuration.
        Args:
            config (dict): The configuration specifying the desired state.
        Returns:
            dict: A dictionary containing the desired state parameters.
        Description:
            This method processes the provided configuration to determine the desired state. It validates the presence of
            either "ip_address_list" or "site_name" and constructs parameters for running compliance checks and syncing
            device configurations based on the provided configuration. It also logs the desired state for reference.
        """
        # Initialize parameters
        run_compliance_params = {}
        sync_device_config_params = {}
        compliance_detail_params_sync = {}
        compliance_details = {}

        # Store input parameters
        ip_address_list = config.get("ip_address_list")
        self.log("Original IP address list: {0}".format(ip_address_list), "DEBUG")
        # Remove Duplicates from list
        if ip_address_list:
            ip_address_list = list(set(ip_address_list))
            self.log(
                "Deduplicated IP address list: {0}".format(ip_address_list), "DEBUG"
            )
        site_name = config.get("site_name")

        run_compliance = config.get("run_compliance")
        run_compliance_categories = config.get("run_compliance_categories")
        sync_device_config = config.get("sync_device_config")

        # Validate the provided configuration parameters
        self.validate_params(config)

        # Retrieve device ID list
        mgmt_ip_to_instance_id_map = self.get_device_id_list(ip_address_list, site_name)
        self.log(
            "Management IP to Instance ID Map: {0}".format(mgmt_ip_to_instance_id_map),
            "DEBUG",
        )

        # Run Compliance Paramters
        run_compliance_params = self.get_run_compliance_params(
            mgmt_ip_to_instance_id_map, run_compliance, run_compliance_categories
        )

        # Sync Device Configuration Parameters
        if sync_device_config:
            self.log("Sync Device Configuration is requested.", "DEBUG")
            if self.dnac_version > self.version_2_3_5_3:
                compliance_detail_params_sync = {
                    "deviceUuids": list(mgmt_ip_to_instance_id_map.values()),
                    "categories": ["RUNNING_CONFIG"],
                }
                self.log(
                    "Retrieving compliance report with parameters: {0}".format(
                        compliance_detail_params_sync
                    ),
                    "DEBUG",
                )
                response = self.get_compliance_report(
                    compliance_detail_params_sync, mgmt_ip_to_instance_id_map
                )
                self.log(
                    "Response from get_compliance_report: {0}".format(response), "DEBUG"
                )
                if not response:
                    ip_address_list_str = ", ".join(
                        list(mgmt_ip_to_instance_id_map.keys())
                    )
                    self.msg = "Error occurred when retrieving Compliance Report to identify if Sync Device Config Operation "
                    self.msg += "is required on device(s): {0}".format(
                        ip_address_list_str
                    )
                    self.fail_and_exit(self.msg)

                compliance_details = response
                sync_required, self.msg, categorized_devices = self.is_sync_required(
                    response, mgmt_ip_to_instance_id_map
                )
                self.log(
                    "Is Sync Requied: {0} -- Message: {1}".format(
                        sync_required, self.msg
                    ),
                    "DEBUG",
                )
                if sync_required:
                    sync_device_config_params = self.get_sync_device_config_params(
                        mgmt_ip_to_instance_id_map, categorized_devices
                    )
                    self.log(
                        "Sync Device Configuration operation is required for provided parameters in the Cisco Catalyst Center."
                        "therefore setting 'sync_device_config_params' - {0}.".format(
                            sync_device_config_params
                        ),
                        "DEBUG",
                    )
                else:
                    self.log(
                        "Sync Device Configuration operation is not required for provided parameters in the Cisco Catalyst Center."
                        "therefore not setting the 'sync_device_config_params'",
                        "INFO",
                    )
                    self.skipped_sync_device_configs_list.extend(
                        list(mgmt_ip_to_instance_id_map.keys())
                    )
            else:
                self.msg = (
                    "The specified Cisco Catalyst Center version: '{0}' does not support the Sync Device Config operation. "
                    "Supported version start '2.3.7.6' onwards. Version '2.3.5.3' introduces APIs for "
                    "performing Compliance Checks. Version '2.3.7.6' expands support to include APIs "
                    "for Compliance Checks and Sync Device Config operations.".format(
                        self.get_ccc_version()
                    )
                )
                self.fail_and_exit(self.msg)

        # Construct the "want" dictionary containing the desired state parameters
        want = {}
        want = dict(
            ip_address_list=ip_address_list,
            site_name=site_name,
            mgmt_ip_to_instance_id_map=mgmt_ip_to_instance_id_map,
            run_compliance_params=run_compliance_params,
            run_compliance_batch_size=config.get("run_compliance_batch_size"),
            sync_device_config_params=sync_device_config_params,
            compliance_detail_params_sync=compliance_detail_params_sync,
            compliance_details=compliance_details,
        )
        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def get_diff_merged(self, config):
        """
        This method is designed to Perform Network Compliance Actions in Cisco Catalyst Center.
        Args: None
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method orchestrates compliance check operation and device configuration synchronization tasks specified in a playbook.
            It ensures all required tasks are present, executes them, and checks their status, facilitating smooth playbook execution.
        """
        # Action map for different network compliance operations
        self.log("Starting 'get_diff_merged' operation.", "INFO")

        action_map = {
            "run_compliance_params": (
                self.run_compliance,
                self.get_compliance_task_status,
            ),
            "sync_device_config_params": (
                self.sync_device_config,
                self.get_sync_config_task_status,
            ),
        }

        # Check if all action_map keys are missing in self.want
        if not any(action_param in self.want for action_param in action_map.keys()):
            self.msg = "Network Compliance operation(s) are not required for the provided input parameters in the Cisco Catalyst Center."
            self.set_operation_result("ok", False, self.msg, "INFO")
            return self

        final_status_list = []
        result_details = {}

        # Iterate through the action map and execute specified actions
        for action_param, (action_func, status_func) in action_map.items():
            req_action_param = self.want.get(action_param)
            # Execute the action and check its status
            if req_action_param:
                self.log(
                    "Executing action function: {0} with params: {1}".format(
                        action_func.__name__, req_action_param
                    ),
                    "INFO",
                )
                if action_param == "run_compliance_params":
                    batch_size = self.want.get("run_compliance_batch_size")
                    result_task_id = action_func(
                        self.want.get(action_param), batch_size=batch_size
                    )
                else:
                    result_task_id = action_func(self.want.get(action_param))

                if not result_task_id:
                    self.msg = "An error occurred while retrieving the task_id of the {0} operation.".format(
                        action_func.__name__
                    )
                    self.set_operation_result("failed", False, self.msg, "CRITICAL")
                else:
                    self.log(
                        "Task Id: {0} returned from the action function: {1}".format(
                            result_task_id, action_func.__name__
                        ),
                        "DEBUG",
                    )
                    status_func(
                        result_task_id, self.want.get("mgmt_ip_to_instance_id_map")
                    ).check_return_status()
                    result = self.msg
                    result_details.update(result)

        if config.get("sync_device_config"):
            skipped_sync_device_configs_list = set(
                self.skipped_sync_device_configs_list
            )
            if skipped_sync_device_configs_list:
                self.log(
                    "Sync Device Configuration skipped for devices: {0}".format(
                        skipped_sync_device_configs_list
                    ),
                    "DEBUG",
                )
                result_details[
                    "Sync Device Configuration operation Skipped for following device(s)"
                ] = {
                    "skipped_count": len(skipped_sync_device_configs_list),
                    "skipped_devices": skipped_sync_device_configs_list,
                }

        skipped_run_compliance_devices_list = set(
            self.skipped_run_compliance_devices_list
        )
        if skipped_run_compliance_devices_list:
            self.log(
                "Run Compliance Check skipped for devices: {0}".format(
                    skipped_run_compliance_devices_list
                ),
                "DEBUG",
            )
            result_details["Run Compliance Check Skipped for following device(s)"] = {
                "skipped_count": len(skipped_run_compliance_devices_list),
                "skipped_devices": skipped_run_compliance_devices_list,
            }

        final_status, is_changed = self.process_final_result(final_status_list)
        self.msg = result_details
        self.log(
            "Completed 'get_diff_merged' operation with final status: {0}, is_changed: {1}".format(
                final_status, is_changed
            ),
            "INFO",
        )
        self.set_operation_result(
            final_status, is_changed, self.msg, "INFO", self.result.get("response")
        )
        return self

    def verify_diff_merged(self, config):
        """
        Verify the success of the "Sync Device Configuration" operation.
        Args:
            config (dict): A dictionary containing the configuration details.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies the success of the "Sync Device Configuration" operation in the context of network compliance management.
            It checks if the configuration includes the option to synchronize device configurations (`sync_device_config`).
            If this option is present, the function proceeds to compare compliance details before and after executing the synchronization operation.
            It logs relevant information at each step and concludes by determining whether the synchronization was successful.
        """
        self.log("Starting 'verify_diff_merged' operation.", "INFO")

        sync_device_config_params = self.want.get("sync_device_config_params")
        run_compliance_params = self.want.get("run_compliance_params")

        if sync_device_config_params:
            self.log(
                "Starting verification of Sync Device Configuration operation.", "INFO"
            )
            self.verify_sync_device_config()
            self.log(
                "Completed verification of Sync Device Configuration operation.", "INFO"
            )

        if run_compliance_params:
            self.log(
                "Verification of configuration is not required for Run Compliance operation!",
                "INFO",
            )

        self.log("Completed 'verify_diff_merged' operation.", "INFO")
        return self


def main():
    """
    main entry point for module execution
    """

    # Define the specification for the module"s arguments
    element_spec = {
        "dnac_host": {"required": True, "type": "str"},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": "True"},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "dnac_log": {"type": "bool", "default": False},
        "validate_response_schema": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged"]},
    }

    # Initialize the Ansible module with the provided argument specifications
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    # Initialize the NetworkCompliance object with the module
    ccc_network_compliance = NetworkCompliance(module)

    if (
        ccc_network_compliance.compare_dnac_versions(
            ccc_network_compliance.get_ccc_version(), "2.3.7.6"
        )
        < 0
    ):
        ccc_network_compliance.msg = (
            "The specified version '{0}' does not support the  'Network Compliance' Operations. Supported versions start "
            "  from '2.3.7.6' onwards. Version '2.3.7.6' introduces APIs for running Compliance checks on devices and"
            " Syncing device configurations.".format(
                ccc_network_compliance.get_ccc_version()
            )
        )
        ccc_network_compliance.set_operation_result(
            "failed", False, ccc_network_compliance.msg, "ERROR"
        ).check_return_status()

    # Get the state parameter from the provided parameters
    state = ccc_network_compliance.params.get("state")

    # Check if the state is valid
    if state not in ccc_network_compliance.supported_states:
        ccc_network_compliance.status = "invalid"
        ccc_network_compliance.msg = "State {0} is invalid".format(state)
        ccc_network_compliance.check_return_status()

    # Validate the input parameters and check the return status
    ccc_network_compliance.validate_input().check_return_status()

    # Get the config_verify parameter from the provided parameters
    config_verify = ccc_network_compliance.params.get("config_verify")

    # Iterate over the validated configuration parameters
    for config in ccc_network_compliance.validated_config:
        ccc_network_compliance.get_want(config).check_return_status()
        ccc_network_compliance.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_network_compliance.verify_diff_state_apply[state](
                config
            ).check_return_status()

    # Exit with the result obtained from the NetworkCompliance object
    module.exit_json(**ccc_network_compliance.result)


if __name__ == "__main__":
    main()
