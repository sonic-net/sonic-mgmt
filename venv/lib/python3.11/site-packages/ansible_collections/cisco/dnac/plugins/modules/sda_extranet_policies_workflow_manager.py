#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to manage Extranet Policy Operations in SD-Access Fabric in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Rugvedi Kapse, Madhan Sankaranarayanan"
DOCUMENTATION = r"""
---
module: sda_extranet_policies_workflow_manager
short_description: SDA Extranet Policies Module provides
  functionality for managing SD-Access Extranet Policies
  in Cisco Catalyst Center.
description:
  - Manage SD-Access Extranet Policy operations such
    as create, update, or delete extranet policies in
    Cisco Catalyst Center.
  - API to create a new extranet policy.
  - API to update an existing or edit an existing extranet
    policy.
  - API for deletion of an existing extranet policy
    using the policy name.
version_added: "6.17.0"
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Rugvedi Kapse (@rukapse) Madhan Sankaranarayanan
  (@madhansansel)
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
    choices: [merged, deleted]
    default: merged
  config:
    description: List of Extranet Policy Details for
      Creating, Updating, or Deleting Operations.
    type: list
    elements: dict
    required: true
    suboptions:
      extranet_policy_name:
        description:
          - Name of the SDA Extranet Policy.
          - Used to create, update, or delete the policy.
          - Required for all operations (create, update,
            delete).
          - Cannot be modified once set.
        type: str
      provider_virtual_network:
        description:
          - Specifies the Provider Virtual Network containing
            shared services resources that subscribers
            need to access.
          - If a virtual network is already defined
            as a Provider, it cannot be assigned as
            a provider again.
          - Ensure the default route is present in the
            Global Routing Table if INFRA_VN is defined
            as the Provider.
          - For Subscriber Virtual Networks with multiple
            Providers having overlapping routes, traffic
            will be load-balanced across those Provider
            Virtual Networks.
          - Required for creating or updating the policy.
          - Updating this field is not allowed.
        type: str
      subscriber_virtual_networks:
        description:
          - Specifies a list of Subscriber Virtual Networks
            that require access to the Provider Virtual
            Network containing shared services resources.
          - A Virtual Network previously defined as
            a Provider cannot be selected as a subscriber.
          - Required for creating or updating the policy.
          - Can be modified.
          - Example - ["VN_2", "VN_4"]
        type: list
        elements: str
      fabric_sites:
        description:
          - Specifies the Fabric Site(s) where this
            Extranet Policy will be applied.
          - The Provider Virtual Network must already
            be added to a Fabric Site before applying
            the policy.
          - Updating this field is allowed, but once
            an extranet policy is applied to a site,
            it cannot be removed.
          - Fabric Site(s) connected to the same SD-Access
            Transit must have consistent Extranet Policies.
          - Selecting a Fabric Site connected to an
            SD-Access Transit will automatically select
            all other Sites connected to that Transit.
          - Example - ["Global/USA/San Jose/Building23",
            "Global/India/Bangalore/Building18"]
        type: list
        elements: str
requirements:
  - dnacentersdk == 2.7.0
  - python >= 3.9
notes:
  - SDK Methods used are sites.Sites.get_site sda.SDA.get_fabric_sites
    sda.SDA.get_extranet_policies sda.SDA.add_extranet_policy
    sda.SDA.update_extranet_policy sda.SDA.delete_extranet_policy_by_id
    task.Task.get_task_by_id
  - Paths used are
    get /dna/intent/api/v1/site get /dna/intent/api/v1/sda/fabricSites
    get /dna/intent/api/v1/sda/extranetPolicies post
    /dna/intent/api/v1/sda/extranetPolicies put /dna/intent/api/v1/sda/extranetPolicies
    delete dna/intent/api/v1/sda/extranetPolicies/${id}
    get /dna/intent/api/v1/task/{taskId}
"""
EXAMPLES = r"""
---
- name: Create Extranet Policy
  cisco.dnac.sda_extranet_policies_workflow_manager:
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
    config:
      - extranet_policy_name: "test_extranet_policy_1"
        provider_virtual_network: "VN_1"
        subscriber_virtual_networks: ["VN_2", "VN_3"]
- name: Create Extranet Policy with Fabric Site(s) specified
  cisco.dnac.sda_extranet_policies_workflow_manager:
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
    config:
      - extranet_policy_name: "test_extranet_policy_1"
        provider_virtual_network: "VN_1"
        subscriber_virtual_networks: ["VN_2", "VN_3"]
        fabric_sites: ["Global/Test_Extranet_Polcies/USA", "Global/Test_Extranet_Polcies/India"]
- name: Update existing Extranet Policy
  cisco.dnac.sda_extranet_policies_workflow_manager:
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
    config:
      - extranet_policy_name: "test_extranet_policy_1"
        provider_virtual_network: "VN_1"
        subscriber_virtual_networks: ["VN_2", "VN_4"]
- name: Update existing Extranet Policy with Fabric
    Site(s) specified
  cisco.dnac.sda_extranet_policies_workflow_manager:
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
    config:
      - extranet_policy_name: "test_extranet_policy_1"
        fabric_sites: ["Global/Test_Extranet_Polcies/USA", "Global/Test_Extranet_Polcies/India"]
        provider_virtual_network: "VN_1"
        subscriber_virtual_networks: ["VN_2", "VN_4"]
- name: Delete Extranet Policy
  cisco.dnac.sda_extranet_policies_workflow_manager:
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
    config:
      - extranet_policy_name: "test_extranet_policy_1"
"""
RETURN = r"""
#Case_1: Response when task is successful
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
#Case_3: Response when Error Occurs
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

import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)


class SDAExtranetPolicies(DnacBase):
    """
    A class for managing Extranet Policies within the Cisco DNA Center using the SDA API.
    """

    def __init__(self, module):
        """
        Initialize an instance of the class.
        Parameters:
          - module: The module associated with the class instance.
        Returns:
          The method does not return a value.
        """
        self.supported_states = ["merged", "deleted"]
        super().__init__(module)

    def validate_input(self):
        """
        Validates the input configuration parameters for the playbook.
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
        # Check if configuration is available
        if not self.config:
            self.status = "success"
            self.msg = "Configuration is not available in the playbook for validation"
            self.log(self.msg, "ERROR")
            return self

        # Expected schema for configuration parameters
        temp_spec = {
            "extranet_policy_name": {"type": "str", "required": True},
            "fabric_sites": {"type": "list", "elements": "str", "required": False},
            "provider_virtual_network": {"type": "str", "required": False},
            "subscriber_virtual_networks": {
                "type": "list",
                "elements": "str",
                "required": False,
            },
        }

        # Validate params
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(invalid_params)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        # Set the validated configuration and update the result with success status
        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validated_input': {0}".format(
            str(valid_temp)
        )
        self.set_operation_result("success", False, self.msg, "INFO")
        return self

    def get_fabric_ids_list(self, site_details):
        """
        Extracts a list of fabric IDs from the provided site details.
        Parameters:
            - site_details (dict): A dictionary containing site information. Each key-value pair
                                   represents a site, where the value is another dictionary that
                                   includes a 'fabric_id'.
        Returns:
            list: A list of fabric IDs extracted from the site details.
        Description:
            This method iterates over the values in the provided site_details dictionary, extracts
            the 'fabric_id' from each value, and appends it to a list. The resulting list of fabric IDs
            is then returned.
        """
        # Initialize an empty list to store the fabric IDs
        fabric_ids_list = []

        # Iterate over each site's information in the site details
        for site_info in site_details.values():
            fabric_ids_list.append(site_info["fabric_id"])
        return fabric_ids_list

    def validate_merged_parameters(self, config):
        """
        Validate that the required parameters are present in the configuration for performing
        Add or Update Extranet Policy operations.
        Parameters:
            - config (dict): A dictionary containing the configuration parameters to be validated.
        Returns:
            None: This function does not return a value. It logs messages and raises exceptions
                  if required parameters are missing.
        Description:
            This method checks the provided configuration for the presence of the required parameters:
            'provider_virtual_network' and 'subscriber_virtual_networks'. If any of these parameters
            are missing, it logs an error message and raises an exception to halt execution. If all
            required parameters are present, it logs a success message indicating successful validation.
        """
        # Check for provider_virtual_network
        provider_virtual_network = config.get("provider_virtual_network")
        if provider_virtual_network is None:
            msg = (
                "Missing required parameter: 'provider_virtual_network'. "
                "(extranet_policy_name, provider_virtual_network, and subscriber_virtual_networks) - "
                "are the required parameters for performing Add or Update Extranet Policy operations."
            )
            self.log(msg, "ERROR")
            self.module.fail_json(msg)

        # Check for subscriber_virtual_networks
        subscriber_virtual_networks = config.get("subscriber_virtual_networks")
        if subscriber_virtual_networks is None:
            msg = (
                "Missing required parameter: 'subscriber_virtual_networks'. "
                "(extranet_policy_name, provider_virtual_network, and subscriber_virtual_networks) - "
                "are the required parameters for performing Add or Update Extranet Policy operations."
            )
            self.log(msg, "ERROR")
            self.module.fail_json(msg)

        self.log(
            "Successfully validated that the required parameters — (extranet_policy_name, "
            "provider_virtual_network, and subscriber_virtual_networks) are provided",
            "INFO",
        )

    def get_add_extranet_policy_params(self, config, site_details=None):
        """
        Generate parameters required for adding an Extranet Policy based on the provided configuration and site details.
        Parameters:
            - config (dict): A dictionary containing the configuration parameters.
            - site_details (dict, optional): A dictionary containing site details. Default is None.
        Returns:
            dict: A dictionary containing the parameters for adding an Extranet Policy.
        Description:
            This method constructs a dictionary of parameters required for adding an Extranet Policy.
            It includes the 'extranetPolicyName', 'providerVirtualNetworkName', and 'subscriberVirtualNetworkNames'
            from the configuration. If 'fabric_sites' are provided in the configuration and site details are available,
            it also includes the 'fabricIds' obtained from the site details.
        """
        # Initialize the parameters dictionary with basic required parameters
        add_extranet_policy_params = {
            "extranetPolicyName": config.get("extranet_policy_name"),
            "providerVirtualNetworkName": config.get("provider_virtual_network"),
            "subscriberVirtualNetworkNames": config.get("subscriber_virtual_networks"),
        }

        # Check if 'fabric_sites' are provided and site details are available
        if config.get("fabric_sites") and site_details:
            add_extranet_policy_params["fabricIds"] = self.get_fabric_ids_list(
                site_details
            )
        else:
            add_extranet_policy_params["fabricIds"] = []

        return add_extranet_policy_params

    def get_update_extranet_policy_params(
        self, config, extranet_policy_id, site_details=None
    ):
        """
        Generate parameters required for updating an Extranet Policy based on the provided configuration,
        policy ID, and site details.
        Parameters:
            config (dict): A dictionary containing the configuration parameters.
            extranet_policy_id (str): The ID of the Extranet Policy to be updated.
            site_details (dict, optional): A dictionary containing site details. Default is None.
        Returns:
            dict: A dictionary containing the parameters for updating an Extranet Policy.
        Description:
            This method constructs a dictionary of parameters required for updating an Extranet Policy.
            It includes the 'id' of the policy, 'extranetPolicyName', 'providerVirtualNetworkName', and
            'subscriberVirtualNetworkNames' from the configuration. If 'fabric_sites' are provided in the
            configuration and site details are available, it also includes the 'fabricIds' obtained from the
            site details.
        """
        # Initialize the parameters dictionary with basic required parameters
        update_extranet_policy_params = {
            "id": extranet_policy_id,
            "extranetPolicyName": config.get("extranet_policy_name"),
            "providerVirtualNetworkName": config.get("provider_virtual_network"),
            "subscriberVirtualNetworkNames": config.get("subscriber_virtual_networks"),
        }

        # Check if 'fabric_sites' are provided and site details are available
        if config.get("fabric_sites") and site_details:
            update_extranet_policy_params["fabricIds"] = self.get_fabric_ids_list(
                site_details
            )
        else:
            update_extranet_policy_params["fabricIds"] = []

        return update_extranet_policy_params

    def get_delete_extranet_policy_params(self, extranet_policy_id):
        """
        Generate parameters required for deleting an Extranet Policy based on the provided policy ID.
        Parameters:
            extranet_policy_id (str): The unique identifier of the Extranet Policy to be deleted.
        Returns:
            dict: A dictionary containing the parameters for deleting an Extranet Policy.
        Description:
            This method constructs a dictionary of parameters required for deleting an Extranet Policy.
            It includes the 'id' of the policy, which is necessary for identifying the specific policy
            to be deleted.
        """
        # Create a dictionary with the extranet policy ID
        delete_extranet_policy_params = {"id": extranet_policy_id}

        return delete_extranet_policy_params

    def get_site_details(self, fabric_sites):
        """
        Retrieve details for each site in the provided fabric sites list.
        Parameters:
            - fabric_sites (list): A list of site names to be validated and detailed.
        Returns:
            dict: A dictionary containing the details for each site, including existence and site ID.
        Description:
            This method takes a list of fabric sites and checks if each site exists using the validate_site_exists method.
            It constructs a dictionary where each key is a site name and the value is another dictionary containing
            'site_exists' (a boolean indicating if the site exists) and 'site_id' (the unique identifier of the site).
        """
        # Initialize an empty dictionary to store site details
        site_details = {}

        # Iterate over each site in the provided fabric sites list
        for site in fabric_sites:
            self.log(
                "Starting to retrieve site details for the provided fabric site: {0}".format(
                    site
                ),
                "INFO",
            )
            # Validate if the site exists and retrieve its ID
            site_exists, site_id = self.get_site_id(site)
            self.log(
                "Site details for '{0}': exists={1}, id={2}".format(
                    site, site_exists, site_id
                ),
                "INFO",
            )
            site_details[site] = {
                "site_exists": site_exists,
                "site_id": site_id,
            }

        return site_details

    def get_fabric_sites(self, site_name, site_id):
        """
        Retrieve the fabric ID for a given site using the SDA 'get_fabric_sites' API call.
        Parameters:
            - site_name (str): The name of the site.
            - site_id (str): The unique identifier of the site.
        Returns:
            str: The fabric ID if found, otherwise None.
        Description:
            This method calls the SDA 'get_fabric_sites' API to retrieve the fabric ID for a specified site. It logs the response,
            processes the response to extract the fabric ID, and handles any exceptions that occur during the API call.
        """
        try:
            # Call the SDA 'get_fabric_sites' API with the provided site ID
            response = self.dnac._exec(
                family="sda",
                function="get_fabric_sites",
                op_modifies=False,
                params={"siteId": site_id},
            )
            self.log(
                "Response received post SDA - 'get_fabric_sites' API call: {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

            response = response["response"]

            if not response:
                self.log(
                    "No response received from the SDA - 'get_fabric_sites' API call.",
                    "WARNING",
                )
                return None

            # Process the response if available
            fabric_id = response[0]["id"]
            self.log(
                "Successfully retrieved fabric ID: '{0}' for Site: '{1}'".format(
                    fabric_id, site_name
                ),
                "INFO",
            )

            return fabric_id

        except Exception as e:
            # Log an error message and fail if an exception occurs
            self.msg = (
                "An error occurred while retrieving fabric Site 'Id' for Site '{0}' using SDA - "
                "'get_fabric_sites' API call: {1}".format(site_name, str(e))
            )
            self.fail_and_exit(self.msg)

    def get_fabric_sites_ids(self, site_details):
        """
        Retrieve and update fabric IDs for a list of sites.
        Parameters:
            - site_details (dict): A dictionary where each key is a site name and the value is another dictionary
              containing site information, including "site_id".
        Returns:
            dict: The updated dictionary with fabric IDs added to each site's information.
        Description:
            This method iterates through the provided `site_details` dictionary, retrieves the fabric ID for each site
            by calling the `get_fabric_sites` method, and logs the retrieved fabric IDs along with site details.
            It updates the `site_details` dictionary to include the fabric ID for each site and logs the updated
            information.
        """
        for site_name, site_info in site_details.items():
            site_id = site_info["site_id"]
            # Get the fabric ID using the site name and site ID
            fabric_id = self.get_fabric_sites(site_name, site_id)
            if fabric_id is not None:
                self.log(
                    "Fabric ID: {0} collected for the fabric site: {1} with siteId: {2}".format(
                        fabric_id, site_name, site_id
                    ),
                    "INFO",
                )
                site_info["fabric_id"] = fabric_id
            else:
                self.msg = "Failed to retrieve Fabric ID for site: {0} with siteId: {1}".format(
                    site_name, site_id
                )
                self.fail_and_exit(self.msg)
        self.log(
            "Updated 'site_details' with the fabric_ids of each site.  {0}".format(
                site_details
            )
        )
        return site_details

    def get_extranet_policies(self, extranet_policy_name):
        """
        Retrieve extranet policies for a given policy name using the SDA 'get_extranet_policies' API call.
        Parameters:
            - extranet_policy_name (str): The name of the extranet policy to retrieve.
        Returns:
            dict or None: The response dictionary containing policy details if found, otherwise None.
        Description:
            This method calls the SDA 'get_extranet_policies' API to retrieve details for the specified extranet
            policy name. It logs the response received from the API call and processes it. If the API call is successful
            and returns data, the first item in the response is returned. If no data is received or an exception occurs,
            appropriate warnings or error messages are logged.
        """
        try:
            # Execute the API call to get extranet policie
            response = self.dnac._exec(
                family="sda",
                function="get_extranet_policies",
                op_modifies=False,
                params={"extranetPolicyName": extranet_policy_name},
            )
            self.log(
                "Response received post SDA - 'get_extranet_policies' API call: {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

            # Process the response if available
            response = response["response"]
            if not response:
                self.log(
                    "No response received from the SDA - 'get_extranet_policies' API call.",
                    "WARNING",
                )
                return None
            return response[0]

        except Exception as e:
            # Log an error message and fail if an exception occurs
            self.msg = (
                "An error occurred while retrieving Extranet Policy Details: '{0}' using SDA - "
                "'get_extranet_policies' API call: {1}".format(
                    extranet_policy_name, str(e)
                )
            )
            self.fail_and_exit(self.msg)

    def validate_extranet_policy_exists(self, extranet_policy_name):
        """
        Check if an extranet policy exists and retrieve its details.
        Parameters:
            - config (dict): A dictionary containing configuration details, including the key "extranet_policy_name".
        Returns:
            tuple: A tuple containing:
                - bool: `True` if the extranet policy exists, otherwise `False`.
                - str or None: The ID of the extranet policy if it exists, otherwise `None`.
                - dict or None: The details of the extranet policy if it exists, otherwise `None`.
        Description:
            This method verifies the existence of an extranet policy based on the name provided in the `config` dictionary.
            It calls the `get_extranet_policies` method to retrieve policy details. If the policy is found, it sets
            `extranet_policy_exists` to `True` and extracts the policy ID and details. The method returns a tuple containing
            the existence status, policy ID, and policy details.
        """
        # Initialize variables to default values
        extranet_policy_exists = False
        extranet_policy_id = None

        self.log(
            "Validating existence of Extranet Policy: {0}".format(extranet_policy_name),
            "INFO",
        )

        extranet_policy_details = self.get_extranet_policies(extranet_policy_name)

        # Check if the policy details were retrieved successfully
        if extranet_policy_details:
            extranet_policy_exists = True
            extranet_policy_id = extranet_policy_details["id"]
            self.log(
                "Extranet Policy: '{0}' exists with ID: {1}".format(
                    extranet_policy_name, extranet_policy_id
                ),
                "INFO",
            )
        else:
            self.log(
                "Extranet Policy: '{0}' does not exist.".format(extranet_policy_name),
                "WARNING",
            )

        return (extranet_policy_exists, extranet_policy_id, extranet_policy_details)

    def compare_extranet_policies(
        self, extranet_policy_details, update_extranet_policy_params
    ):
        """
        Compare the details of two extranet policies to check if they are equivalent.
        Parameters:
            - extranet_policy_details (dict): A dictionary containing the current details of the extranet policy.
            - update_extranet_policy_params (dict): A dictionary containing the updated policy parameters to compare against.
        Returns:
            bool: `True` if all values for the keys match between the two dictionaries, `False` otherwise.
        Description:
            This method compares the details of two extranet policies by iterating over each key in the `extranet_policy_details`
            dictionary and checking if the corresponding values in the `update_extranet_policy_params` dictionary match.
            Lists are compared regardless of order, while other values are compared directly. The method returns `True` if
            all values are equivalent, and `False` if any values differ.
        """
        # Iterate over each key in the extranet policy details and compare the details
        for key in extranet_policy_details:
            current_value = extranet_policy_details.get(key)
            requested_value = update_extranet_policy_params.get(key)

            self.log(
                "Comparing key: {0}, existing_value: {1}, requested_value: {2}".format(
                    key, current_value, requested_value
                ),
                "INFO",
            )

            if key == "fabricIds":
                if current_value and not requested_value:
                    self.log(
                        "Skipping comparison for key: 'fabricIds' as the requested value is empty.",
                        "DEBUG",
                    )
                    continue

            if isinstance(current_value, list) and isinstance(requested_value, list):
                # Compare lists regardless of order
                if sorted(current_value) != sorted(requested_value):
                    self.log(
                        "Mismatch found for key: {0}, existing list: {1}, requested list: {2}".format(
                            key, current_value, requested_value
                        ),
                        "INFO",
                    )
                    return False
            else:
                # Compare values directly
                if current_value != requested_value:
                    self.log(
                        "Mismatch found for key: {0}, existing list: {1}, requested list: {2}".format(
                            key, current_value, requested_value
                        ),
                        "INFO",
                    )
                    return False

        self.log(
            "All keys and values match between the existing and requested policies.",
            "INFO",
        )

        return True

    def add_extranet_policy(self, add_extranet_policy_params):
        """
        Adds an extranet policy by making a POST API call with the provided parameters.
        Args:
            add_extranet_policy_params (dict): Parameters for adding the extranet policy.
        Returns:
            str: Task ID for the add extranet policy operation.
        """
        # Wrap the parameters in a payload dictionary
        add_extranet_policy_params = {"payload": [add_extranet_policy_params]}

        # Make the API call to add the extranet policy and return the task ID
        return self.get_taskid_post_api_call(
            "sda", "add_extranet_policy", add_extranet_policy_params
        )

    def get_add_extranet_policy_status(self, task_id):
        """
        Retrieves the status of the add extranet policy task using the provided task ID.
        Args:
            task_id (str): The task ID to check the status for.
        Returns:
            dict: The status of the add extranet policy task.
        """
        task_name = "Add Extranet Policy Task"
        msg = {}

        # Get the name of the extranet policy from the input parameters
        extranet_policy_name = self.want.get("add_extranet_policy_params").get(
            "extranetPolicyName"
        )
        msg["{0} Succeeded for the Extranet Policy".format(task_name)] = (
            extranet_policy_name
        )

        # Retrieve and return the task status using the provided task ID
        return self.get_task_status_from_tasks_by_id(task_id, task_name, msg)

    def update_extranet_policy(self, update_extranet_policy_params):
        """
        Updates an existing extranet policy by making a POST API call with the provided parameters.
        Args:
            update_extranet_policy_params (dict): Parameters for updating the extranet policy.
        Returns:
            str: Task ID for the update extranet policy operation.
        """
        # Wrap the parameters in a payload dictionary
        update_extranet_policy_params = {"payload": [update_extranet_policy_params]}

        # Make the API call to update the extranet policy and return the task ID
        return self.get_taskid_post_api_call(
            "sda", "update_extranet_policy", update_extranet_policy_params
        )

    def get_update_extranet_policy_status(self, task_id):
        """
        Retrieves the status of the update extranet policy task using the provided task ID.
        Args:
            task_id (str): The task ID to check the status for.
        Returns:
            dict: The status of the update extranet policy task.
        """
        task_name = "Update Extranet Policy Task"
        msg = {}

        # Get the name of the extranet policy from the input parameters
        extranet_policy_name = self.want.get("update_extranet_policy_params").get(
            "extranetPolicyName"
        )
        msg["{0} Succeeded for following Extranet Policy".format(task_name)] = (
            extranet_policy_name
        )

        # Retrieve and return the task status using the provided task ID
        return self.get_task_status_from_tasks_by_id(task_id, task_name, msg)

    def delete_extranet_policy(self, delete_extranet_policy_params):
        """
        Deletes an existing extranet policy by making a POST API call with the provided parameters.
        Args:
            delete_extranet_policy_params (dict): Parameters for deleting the extranet policy.
        Returns:
            str: Task ID for the delete extranet policy operation.
        """
        # Make the API call to delete the extranet policy and return the task ID
        return self.get_taskid_post_api_call(
            "sda", "delete_extranet_policy_by_id", delete_extranet_policy_params
        )

    def get_delete_extranet_policy_status(self, task_id):
        """
        Retrieves the status of the delete extranet policy task using the provided task ID.
        Args:
            task_id (str): The task ID to check the status for.
        Returns:
            dict: The status of the delete extranet policy task.
        """
        task_name = "Delete Extranet Policy Task"
        msg = {}

        # Get the name of the extranet policy from the input parameters
        extranet_policy_name = self.want.get("extranet_policy_name")
        msg["{0} Succeeded for following Extranet Policy".format(task_name)] = (
            extranet_policy_name
        )

        # Retrieve and return the task status using the provided task ID
        return self.get_task_status_from_tasks_by_id(task_id, task_name, msg)

    def get_have(self, config):
        """
        Retrieve the current state of the extranet policy based on the provided configuration.
        Parameters:
            - config (dict): Configuration dictionary containing site details.
        Returns:
            self: The instance of the class, allowing for method chaining.
        Description:
            This method checks if the extranet policy specified in the `config` exists. It uses the
            `validate_extranet_policy_exists` method to determine if the policy exists and to retrieve its details.
            The method logs the current state of the extranet policy and updates the instance attribute `have` with
            information about the existence, ID, and details of the extranet policy. It returns the instance for
            method chaining.
        """
        have = {}

        extranet_policy_name = config.get("extranet_policy_name")
        # check if given extranet policy exits, if exists store current extranet policy info
        (extranet_policy_exists, extranet_policy_id, extranet_policy_details) = (
            self.validate_extranet_policy_exists(extranet_policy_name)
        )

        self.log(
            "Current Extranet Policy details (have): {0}".format(
                str(extranet_policy_details)
            ),
            "DEBUG",
        )

        have["extranet_policy_exists"] = extranet_policy_exists
        have["extranet_policy_id"] = extranet_policy_id
        have["current_extranet_policy"] = extranet_policy_details

        self.have = have
        self.log(
            "Current Extranet Policy State (have): {0}".format(str(self.have)), "INFO"
        )

        return self

    def get_want(self, config, state):
        """
        Generate the desired state parameters for API calls based on the provided configuration and state.
        Parameters:
            - config (dict): Configuration dictionary containing site and policy details.
            - state (str): Desired state, which can be 'merged' or 'delete'.
        Returns:
            self: The instance of the class, allowing for method chaining.
        Description:
            This method determines the parameters required for API calls based on the desired state and configuration.
            It checks if the extranet policy exists and sets the appropriate parameters for creating, updating, or deleting
            the policy. For the 'merged' state, it prepares parameters for updating the policy if it exists or creating
            it if it does not. For the 'delete' state, it prepares parameters for deleting the policy if it exists. The
            method logs the created parameters and updates the instance attribute `want` with these parameters. It returns
            the instance for method chaining.
        """
        # Initialize want
        want = {}
        site_details = {}

        self.log("Creating Parameters for API Calls with state: {0}".format(state))

        # Identify if policy already exists or needs to be created
        extranet_policy_name = config.get("extranet_policy_name")
        extranet_policy_exists = self.have.get("extranet_policy_exists")
        extranet_policy_id = self.have.get("extranet_policy_id")
        extranet_policy_details = self.have.get("current_extranet_policy")

        if state == "merged":
            self.validate_merged_parameters(config)
            fabric_sites = config.get("fabric_sites")
            if fabric_sites:
                self.log(
                    "Attempting to get the 'site ID' for the provided fabric sites: {0}".format(
                        fabric_sites
                    ),
                    "DEBUG",
                )
                site_details = self.get_site_details(fabric_sites)
                self.log(
                    "Attempting to get the 'fabric ID' for the provided fabric sites: {0}".format(
                        fabric_sites
                    ),
                    "DEBUG",
                )
                site_details = self.get_fabric_sites_ids(site_details)

            if extranet_policy_exists:
                self.log(
                    "Extranet Policy - '{0}' exists in the Cisco Catalyst Center, "
                    "therefore setting 'update_extranet_policy_params'.".format(
                        extranet_policy_name
                    ),
                    "DEBUG",
                )
                want = dict(
                    update_extranet_policy_params=self.get_update_extranet_policy_params(
                        config, extranet_policy_id, site_details
                    )
                )
                if self.compare_extranet_policies(
                    extranet_policy_details, want["update_extranet_policy_params"]
                ):
                    self.msg = "Extranet Policy '{0}' is identical to the update requested. No update operation needed.".format(
                        extranet_policy_name
                    )
                    self.set_operation_result("ok", False, self.msg, "INFO")
                    self.check_return_status()
                    return self
            else:
                self.log(
                    "Extranet Policy - '{0}' does not exist in the Cisco Catalyst Center, "
                    "therefore setting 'add_extranet_policy_params'.".format(
                        extranet_policy_name
                    ),
                    "DEBUG",
                )
                want = dict(
                    add_extranet_policy_params=self.get_add_extranet_policy_params(
                        config, site_details
                    )
                )

        elif state == "deleted":
            if extranet_policy_exists:
                self.log(
                    "State is delete and Extranet Policy - '{0}' exists in the Cisco Catalyst Center, "
                    "therefore setting 'delete_extranet_policy_params'.".format(
                        extranet_policy_name
                    ),
                    "DEBUG",
                )
                want = dict(
                    extranet_policy_name=extranet_policy_name,
                    delete_extranet_policy_params=self.get_delete_extranet_policy_params(
                        extranet_policy_id
                    ),
                )
            else:
                self.msg = (
                    "Extranet Policy - '{0}' does not exist in the Cisco Catalyst Center and "
                    "hence delete operation not required.".format(extranet_policy_name)
                )
                self.set_operation_result("ok", False, self.msg, "INFO")
                self.check_return_status()
                return self

        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")
        self.msg = "Successfully collected all parameters from the playbook for creating/updating/deleting the extranet policy."
        self.status = "success"
        return self

    def get_diff_merged(self):
        """
        Executes actions based on the desired state parameters and checks their status.
        Parameters:
            - None
        Returns:
            self: The instance of the class, allowing for method chaining.
        Description:
            This method iterates through a map of action parameters to their corresponding functions for execution and status
            checking. For each action parameter present in the desired state (`want`), the associated action function is called
            to perform the action, and the corresponding status function is used to check the result. It ensures that all actions
            specified in the desired state are executed and their statuses are verified. The method returns the instance for method
            chaining.
        """
        self.log("Starting 'get_diff_merged' operation.", "INFO")
        action_map = {
            "add_extranet_policy_params": (
                self.add_extranet_policy,
                self.get_add_extranet_policy_status,
            ),
            "update_extranet_policy_params": (
                self.update_extranet_policy,
                self.get_update_extranet_policy_status,
            ),
        }

        for action_param, (action_func, status_func) in action_map.items():
            # Execute the action and check its status
            req_action_param = self.want.get(action_param)
            if req_action_param:
                self.log(
                    "Executing action for parameter: {0}".format(req_action_param),
                    "INFO",
                )
                result_task_id = action_func(req_action_param)
                status_func(result_task_id).check_return_status()

        self.log("Completed 'get_diff_merged' operation.", "INFO")
        return self

    def get_diff_deleted(self):
        """
        Executes deletion actions based on the desired state parameters and checks their status.
        Parameters:
            - None
        Returns:
            self: The instance of the class, allowing for method chaining.
        Description:
            This method iterates through a map of deletion action parameters to their corresponding functions for execution and
            status checking. For each deletion action parameter present in the desired state (`want`), the associated action
            function is called to perform the deletion, and the corresponding status function is used to check the result.
            It ensures that all deletion actions specified in the desired state are executed and their statuses are verified.
            The method returns the instance for method chaining.
        """
        self.log("Starting 'get_diff_deleted' operation.", "INFO")
        action_map = {
            "delete_extranet_policy_params": (
                self.delete_extranet_policy,
                self.get_delete_extranet_policy_status,
            )
        }
        for action_param, (action_func, status_func) in action_map.items():
            # Execute the action and check its status
            if self.want.get(action_param):
                result_task_id = action_func(self.want.get(action_param))
                status_func(result_task_id).check_return_status()

        self.log("Completed 'get_diff_deleted' operation.", "INFO")
        return self

    def verify_diff_merged(self, config):
        """
        Verifies the results of the merged state operations by comparing the state before and after the operations.
        Parameters:
            - config (dict): Configuration dictionary containing site and policy details.
        Returns:
            self: The instance of the class, allowing for method chaining.
        Description:
            This method performs verification of operations related to the 'merged' state. It first retrieves the state before
            performing any operations and then compares it with the state after the operations. For add and update operations,
            it logs the states before and after the operations and verifies the success based on the presence or absence of
            the extranet policy and whether any changes were detected. It ensures that the operations have been performed as
            expected and logs appropriate messages based on the results.
        """
        self.log("Starting 'verify_diff_merged' operation.", "INFO")

        pre_operation_state = self.have.copy()
        desired_state = self.want
        self.get_have(config)
        post_operation_state = self.have.copy()
        extranet_policy_name = config.get("extranet_policy_name")

        add_extranet_policy_params = desired_state.get("add_extranet_policy_params")
        if add_extranet_policy_params:
            self.log(
                "State before performing ADD Extranet Policy operation: {0}".format(
                    str(pre_operation_state)
                ),
                "INFO",
            )
            self.log(
                "Desired State: {0}".format(str(add_extranet_policy_params)), "INFO"
            )
            self.log(
                "State after performing ADD Extranet Policy operation: {0}".format(
                    str(post_operation_state)
                ),
                "INFO",
            )

            if post_operation_state["extranet_policy_exists"]:
                self.log(
                    "Verified the success of ADD Extranet Policy - '{0}' operation.".format(
                        extranet_policy_name
                    ),
                    "INFO",
                )
            else:
                self.log(
                    "The ADD Extranet Policy - '{0}' operation may not have been successful "
                    "since the Extranet Policy does not exist in the Cisco Catalyst Center.".format(
                        extranet_policy_name
                    ),
                    "WARNING",
                )
                self.log(
                    "Completed verification of ADD Extranet Policy operation.", "INFO"
                )

        update_extranet_policy_params = desired_state.get(
            "update_extranet_policy_params"
        )
        if update_extranet_policy_params:
            self.log(
                "State before performing UPDATE Extranet Policy operation: {0}".format(
                    str(pre_operation_state)
                ),
                "INFO",
            )
            self.log(
                "Desired State: {0}".format(str(update_extranet_policy_params)), "INFO"
            )
            self.log(
                "State after performing UPDATE Extranet Policy operation - '{0}'".format(
                    str(post_operation_state)
                ),
                "INFO",
            )

            if not self.compare_extranet_policies(
                pre_operation_state["current_extranet_policy"],
                post_operation_state["current_extranet_policy"],
            ):
                self.log(
                    "Verified the success of UPDATE Extranet Policy - '{0}' operation.".format(
                        extranet_policy_name
                    ),
                    "INFO",
                )
            else:
                self.log(
                    "The UPDATE Extranet Policy - '{0}' operation may not have been performed or "
                    "may not have been successful because no change was detected in the Extranet Policy "
                    "in the Cisco Catalyst Center".format(extranet_policy_name),
                    "WARNING",
                )
                self.log(
                    "Completed verification of UPDATE Extranet Policy operation.",
                    "INFO",
                )

        self.log("Completed 'verify_diff_merged' operation.", "INFO")
        return self

    def verify_diff_deleted(self, config):
        """
        Verifies the results of the delete state operation by comparing the state before and after the delete operation.
        Parameters:
            - config (dict): Configuration dictionary containing site and policy details.
        Returns:
            self: The instance of the class, allowing for method chaining.
        Description:
            This method performs verification of the delete operation by comparing the state before and after the operation.
            It introduces a delay to allow the deletion to process and then retrieves the state. It checks if the extranet policy
            no longer exists and logs the result of the delete operation. It ensures that the delete operation was successful
            by verifying the absence of the extranet policy and logs appropriate messages based on the outcome.
        """
        self.log("Starting 'verify_diff_deleted' operation.", "INFO")

        pre_operation_state = self.have.copy()
        desired_state = self.want
        time.sleep(10)
        self.get_have(config)
        post_operation_state = self.have.copy()
        extranet_policy_name = config.get("extranet_policy_name")

        self.log(
            "State before performing DELETE Extranet Policy operation: {0}".format(
                str(pre_operation_state)
            ),
            "INFO",
        )
        self.log("Desired State: {0}".format(str(desired_state)), "INFO")
        self.log(
            "State after performing DELETE Extranet Policy operation: {0}".format(
                str(post_operation_state)
            ),
            "INFO",
        )

        if not post_operation_state["extranet_policy_exists"]:
            self.log(
                "Verified the success of DELETE Extranet Policy - '{0}' operation".format(
                    extranet_policy_name
                ),
                "INFO",
            )
        else:
            self.log(
                "The DELETE Extranet Policy - '{0}' operation may not have been successful since "
                "the policy still exists in the Cisco Catalyst Center.".format(
                    extranet_policy_name
                ),
                "WARNING",
            )

        self.log("Completed 'verify_diff_deleted' operation.", "INFO")
        return self


def main():
    """main entry point for module execution"""
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
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
    }

    # Initialize the Ansible module with the provided argument specifications
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    # Initialize the NetworkCompliance object with the module
    ccc_sda_extranet_policies = SDAExtranetPolicies(module)

    if (
        ccc_sda_extranet_policies.compare_dnac_versions(
            ccc_sda_extranet_policies.get_ccc_version(), "2.3.7.6"
        )
        < 0
    ):
        ccc_sda_extranet_policies.msg = (
            "The specified version '{0}' does not support the 'SDA Extranet Policies' feature. Supported versions start "
            "  from '2.3.7.6' onwards. Version '2.3.7.6' introduces APIs for creating, updating and deleting the "
            "SDA Extranet Policies.".format(ccc_sda_extranet_policies.get_ccc_version())
        )
        ccc_sda_extranet_policies.set_operation_result(
            "failed", False, ccc_sda_extranet_policies.msg, "ERROR"
        ).check_return_status()

    # Get the state parameter from the provided parameters
    state = ccc_sda_extranet_policies.params.get("state")

    # Check if the state is valid
    if state not in ccc_sda_extranet_policies.supported_states:
        ccc_sda_extranet_policies.status = "invalid"
        ccc_sda_extranet_policies.msg = "State {0} is invalid".format(state)
        ccc_sda_extranet_policies.check_return_status()

    # Validate the input parameters and check the return status
    ccc_sda_extranet_policies.validate_input().check_return_status()

    # Get the config_verify parameter from the provided parameters
    config_verify = ccc_sda_extranet_policies.params.get("config_verify")

    # Iterate over the validated configuration parameters
    for config in ccc_sda_extranet_policies.validated_config:
        ccc_sda_extranet_policies.reset_values()
        ccc_sda_extranet_policies.get_have(config).check_return_status()
        ccc_sda_extranet_policies.get_want(config, state).check_return_status()
        ccc_sda_extranet_policies.get_diff_state_apply[state]().check_return_status()

        if config_verify:
            ccc_sda_extranet_policies.verify_diff_state_apply[state](
                config
            ).check_return_status()

    module.exit_json(**ccc_sda_extranet_policies.result)


if __name__ == "__main__":
    main()
