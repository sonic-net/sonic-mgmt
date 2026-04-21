#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type
__author__ = (
    "Madhan Sankaranarayanan, Rishita Chowdhary, Abhishek Maheshwari, Megha Kandari, Sonali Deepthi Kesali")
DOCUMENTATION = r"""
---
module: site_workflow_manager
short_description: Manage hierarchical sites in Cisco Catalyst Center
description:
  - Complete management of sites in Cisco Catalyst Center, including hierarchical structures of areas, buildings, and floors.
  - Creates single or multiple sites with specified hierarchical relationships.
  - Updates existing site configurations, including physical attributes and RF characteristics.
  - Deletes sites and their components when no longer needed.
  - Supports bulk operations for efficiently managing multiple sites simultaneously.
  - Handles floor maps and RF modeling for wireless network planning.
  - Provides verification of site configurations after changes are applied.
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Madhan Sankaranarayanan (@madhansansel)
  - Rishita Chowdhary (@rishitachowdhary)
  - Abhishek Maheshwari (@abhishekmaheshwari)
  - Megha Kandari (@kandarimegha)
  - Sonali Deepthi Kesali (@skesali)
options:
  config_verify:
    description:
      - Controls whether to verify site configurations after applying changes.
      - When set to true, the module will confirm that site creation, updates, or deletion
        operations have been successfully completed in Cisco Catalyst Center.
    type: bool
    default: false
  state:
    description:
      - Defines the intended state of the sites after module execution.
      - C(merged) will create new sites or update existing ones.
      - C(deleted) will remove the specified sites from Cisco Catalyst Center.
    type: str
    choices: ["merged", "deleted"]
    default: "merged"
  config:
    description:
      - List of site configurations to be created, updated, or deleted.
      - Each item represents a single site operation.
      - Required for all operations as it defines the target sites and their configurations.
    type: list
    elements: dict
    required: true
    suboptions:
      site_type:
        description:
          - Specifies the type of site component to manage.
          - Must be one of "area", "building", or "floor".
        type: str
        required: true
        choices:
          - "area"
          - "building"
          - "floor"
      site:
        description:
          - Contains the detailed configuration for the site being managed.
          - Only one site component type (area, building, or floor) should be specified in each config entry.
        type: dict
        suboptions:
          area:
            description:
              - Configuration specific to an area-type site.
              - Areas represent the highest level in the site hierarchy, typically representing
                geographical regions, campuses, or other logical divisions.
            type: dict
            suboptions:
              name:
                description:
                  - Name of the area to create, update, or delete.
                  - Must be unique within its parent site.
                type: str
                required: true
              parent_name:
                description:
                  - Full hierarchical path of the parent site.
                  - Format should be slash-separated notation (For example, "Global/USA").
                  - For top-level areas, the parent is typically "Global".
                type: str
                required: true
          building:
            description:
              - Configuration specific to a building-type site.
              - Buildings represent physical structures within an area and contain floors.
            type: dict
            suboptions:
              address:
                description:
                  - Physical street address of the building.
                  - Used for geographical positioning and identification.
                type: str
                required: true
              latitude:
                description:
                  - Geographical latitude coordinate of the building.
                  - Must be between -90.0 and +90.0 degrees.
                  - For Example, 37.338 for a location in San Jose, California.
                  - Required for creating buildings, optional when updating.
                type: float
                required: true
              longitude:
                description:
                  - Geographical longitude coordinate of the building.
                  - Must be between -180.0 and +180.0 degrees.
                  - For Example, -121.832 for a location in San Jose, California.
                  - Required for creating buildings, optional when updating.
                type: float
                required: true
              name:
                description:
                  - Name of the building to create, update, or delete.
                  - Must be unique within its parent area.
                type: str
                required: true
              parent_name:
                description:
                  - Full hierarchical path of the parent area.
                  - Format should be slash-separated (e.g., "Global/USA/California").
                  - The parent must exist before creating the building.
                type: str
                required: true
              country:
                description:
                  - The country where the building is located.
                  - Optional parameter for additional geolocation context.
                type: str
          floor:
            description:
              - Configuration specific to a floor-type site.
              - Floors represent levels within a building and can contain network devices and floor plans.
            type: dict
            suboptions:
              height:
                description:
                  - Height of the floor in the specified units (default is feet).
                  - Represents the ceiling height, important for RF planning and signal propagation modeling.
                type: float
                required: true
              length:
                description:
                  - Length of the floor in the specified units (default is feet).
                  - Used for defining the floor dimensions for mapping purposes.
                type: float
                required: true
              name:
                description:
                  - Name of the floor to create, update, or delete.
                  - Must be unique within its parent building.
                type: str
                required: true
              parent_name:
                description:
                  - Full hierarchical path of the parent building.
                  - Format should be slash-separated notation (For example, "Global/USA/California/Building_1").
                type: str
                required: true
              rf_model:
                description: |
                  RF (Radio Frequency) model type for the floor, essential for wireless network planning.
                  Select one of the following options based on your environment:

                  - "Cubes And Walled Offices": For indoor areas with cubicles or walled offices, where
                    signal propagation is affected by walls and partitions.
                  - "Drywall Office Only": For environments with drywall partitions (typically office spaces),
                    which have moderate signal attenuation.
                  - "Indoor High Ceiling": For spaces with high ceilings (e.g., auditoriums, warehouses),
                    where vertical propagation patterns differ significantly.
                  - "Outdoor Open Space": For outdoor areas with minimal obstruction, suitable for
                    outdoor deployments or open campuses.

                  The chosen RF model affects how the system calculates wireless coverage and capacity.
                type: str
                choices:
                  - "Cubes And Walled Offices"
                  - "Drywall Office Only"
                  - "Indoor High Ceiling"
                  - "Outdoor Open Space"
                required: true
              width:
                description:
                  - Width of the floor in the specified units (default is feet).
                  - Used for defining the floor dimensions for mapping purposes.
                type: float
                required: true
              floor_number:
                description: |
                  Numerical identifier for the floor within the building.
                  - Required for floor creation from Catalyst Center version 2.3.7.6 onwards.
                  - Once set, this value cannot be modified.
                  - For example, 1 for first floor, 0 for ground floor, -1 for basement.
                type: int
                required: true
              units_of_measure:
                description: |
                  Unit of measurement for floor dimensions (height, length, and width).
                  - Available from Catalyst Center version 2.3.7.6 onwards.
                  - Default is 'feet' if not specified.
                type: str
                choices: ["feet", "meters"]
                default: "feet"
              upload_floor_image_path:
                description:
                  - Local file path to an image that will be uploaded as the floor plan.
                  - Supported formats include JPG, PNG, and PDF.
                  - Feature available from Catalyst Center version 2.3.7.6 onwards.
                type: str
              force_upload_floor_image:
                description: |
                  Controls whether to upload or update the floor image.
                  - When true, the floor image specified in upload_floor_image_path will be uploaded
                    or updated, even if the floor already has an image.
                  - When false, image upload is skipped during updates.
                  - During initial floor creation, if upload_floor_image_path is provided, the image
                    will be uploaded regardless of this setting.
                  - Set to true to replace an existing floor image during an update operation.
                type: bool
                default: false
requirements:
  - dnacentersdk == 2.4.5
  - python >= 3.9
seealso:
  - name: Cisco Catalyst Center API Documentation
    description: Complete API reference for device management.
    link: https://developer.cisco.com/docs/dna-center/
  - name: Site Management API
    description: Specific documentation for site operations in Catalyst Center version.
    link: https://developer.cisco.com/docs/dna-center/#!sites
notes:
  # Version Compatibility
    - Floor number and units_of_measure require Catalyst Center version 2.3.7.6 or later.
    - Floor image upload is available from version 2.3.7.6 onwards.
    - Module requires dnacentersdk 2.4.5 or later.

  # API Methods and Endpoints
    - Primary SDK Methods
        - sites.Sites.create_site, sites.Sites.update_site, sites.Sites.delete_site
        - site.Sites.create_sites, site.Sites.update_a_floor, site.Sites.update_a_building
        - site.Sites.update_an_area, site.Sites.delete_a_floor, site.Sites.delete_a_building
        - site.Sites.delete_an_area, site.Sites.get_site_assigned_network_devices
    - API Endpoints
        - POST /dna/intent/api/v1/site, PUT dna/intent/api/v1/site/{siteId}
        - DELETE dna/intent/api/v1/site/{siteId} DELETE/dna/intent/api/v2/buildings/{id}
        - DELETE/dna/intent/api/v1/areas/{id} DELETE/dna/intent/api/v2/floors/{id} PUT/dna/intent/api/v2/floors/{id}
        - PUT/dna/intent/api/v1/areas/{id} PUT/dna/intent/api/v2/buildings/{id} GET/dna/intent/api/v1/sites
        - POST/dna/intent/api/v1/sites/bulk GET/dna/intent/api/v1/networkDevices/assignedToSite

  # Hierarchical Site Management
    - Sites must be created in order - areas first, then buildings, then floors.
    - Deleting a parent site will automatically delete all child sites.

  # Floor-Specific Considerations
    - RF models significantly impact wireless planning and should be selected based on the actual physical environment.
    - Floor dimensions (height, length, width) and RF models can be updated after creation, but floor_number cannot be modified once set.
    - Floor images, once uploaded, remain associated with the floor until explicitly replaced using force_upload_floor_image to true.
    - Large floor plan images may take time to upload; ensure the connection to Catalyst Center remains stable during upload.

  # Geographic Coordinates
    - Latitude must be between -90.0 and +90.0 degrees, with positive values representing north of the equator.
    - Longitude must be between -180.0 and +180.0 degrees, with positive values representing east of the prime meridian.
    - Use precise coordinates for buildings to ensure accurate positioning on maps and integration with location services.

  # Operational Best Practices
    - Use unique names for sites to avoid confusion in complex hierarchies.
    - For bulk operations, limit the number of sites to avoid timeout issues.

  # Performance and Limitations:
    - Floor image uploads for multiple floors may impact performance; consider spreading large uploads across multiple tasks.
    - Site operations on a large scale (many floors or buildings) may take considerable time to complete.
    - Site names are case-sensitive in Catalyst Center; ensure consistent casing in your playbooks.
"""
EXAMPLES = r"""
- name: Create a new area site
  cisco.dnac.site_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: "{{dnac_log}}"
    state: merged
    config:
      - site:
          area:
            name: Test
            parent_name: Global/India
        site_type: area

- name: Create a new building site
  cisco.dnac.site_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: "{{dnac_log}}"
    state: merged
    config:
      - site:
          building:
            name: Building_1
            parent_name: Global/India
            address: Bengaluru, Karnataka, India
            latitude: 24.12
            longitude: 23.45
        site_type: building

- name: Create a Floor site under the building
  cisco.dnac.site_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: "{{dnac_log}}"
    state: merged
    config:
      - site:
          floor:
            name: Floor_1
            parent_name: Global/India/Building_1
            length: 75.76
            width: 35.54
            height: 30.12
            rf_model: Cubes And Walled Offices
            floor_number: 2
        site_type: floor

- name: Updating the Floor details under the building
  cisco.dnac.site_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: "{{dnac_log}}"
    state: merged
    config:
      - site:
          floor:
            name: Floor_1
            parent_name: Global/India/Building_1
            length: 75.76
            width: 35.54
            height: 30.12
        site_type: floor

- name: Deleting any site you need site name and parent name
  cisco.dnac.site_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: "{{dnac_log}}"
    state: deleted
    config:
      - site:
          floor:
            name: Floor_1
            parent_name: Global/India/Building_1
        site_type: floor

- name: Create bulk sites and upload floor map
  cisco.dnac.site_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    state: merged
    config:
      - site:
          area:
            name: bangalore99
            parent_name: Global
        type: area
      - site:
          building:
            name: s1
            address: 1234 Elm Street3
            parent_name: Global/bangalore99
            latitude: 37.373
            longitude: -121.873
            country: india
        type: building
      - site:
          floor:
            name: cherry88
            parent_name: Global/bangalore99/s1
            rf_model: Outdoor Open Space
            width: 117
            length: 117
            height: 13
            floor_number: 3
            units_of_measure: "feet"
            upload_floor_image_path: "/Users/skesali/Downloads/pngegg.png"
            force_upload_floor_image: true
        type: floor
      - site:
          floor:
            name: cherry5
            parent_name: Global/bangalore9/s1
            rf_model: Outdoor Open Space
            width: 113
            length: 113
            height: 13
            floor_number: 3
            units_of_measure: "feet"
            upload_floor_image_path: "/Users/skesali/Downloads/pngegg.png"
            force_upload_floor_image: true
        type: floor
"""
RETURN = r"""
#Case_1: Site is successfully created/updated/deleted
response_1:
    description:
      - Detailed API execution results when a site is successfully created, updated, or deleted.
      - Contains execution IDs, timestamps, status, and site identifiers.
    returned: when a site operation succeeds
    type: dict
    sample: >
      {
        "response":
          {
               "bapiExecutionId": "2f259f38-a005-4f44-9feb-a168312b503c",
               "bapiKey": "12345",
               "bapiName": "Sites",
               "endTime": "2025-07-25 14:32:45",
               "endTimeEpoch": 1658756565000,
               "runtimeInstanceId": "cisco-catc-01",
               "siteId": "9d963198-8ea0-4b1b-afe7-04401c9fd345",
               "startTime": "2025-07-25 14:32:30",
               "startTimeEpoch": 1658756550000,
               "status": "SUCCESS",
               "timeDuration": 15
          },
        "msg": "Site Global/USA/California/San Jose/Building_1 successfully created"
      }

#Case_2: Site exists and does not need an update
response_2:
    description:
      - Information about sites that already exist and do not require an update.
      - Useful for idempotency checks and verification that sites are in the desired state.
    returned: when a site exists but doesn't need updating
    type: dict
    sample: >
      {
        "response":
        {
          "site": {
            "area": {
              "name": "California",
              "parentName": "Global/USA"
            }
          },
          "siteId": "9d963198-8ea0-4b1b-afe7-04401c9fd345",
          "type": "area"
        },
        "msg": "Site Global/USA/California already exists with the requested configuration"
      }

#Case_3: Error while creating/updating/deleting site
response_3:
    description:
      - Error details when site creation, update, or deletion operations fail.
      - Contains error messages, execution IDs, and timestamps to assist with troubleshooting.
    returned: when a site operation fails
    type: dict
    sample: >
      {
        "response":
          {
               "bapiError": "Parent site Global/NonExistentArea does not exist",
               "bapiExecutionId": "3e8721a9-b56f-43c2-8d01-5d7b318f7e22",
               "bapiKey": "12345",
               "bapiName": "Sites",
               "endTime": "2025-07-25 14:33:15",
               "endTimeEpoch": 1658756595000,
               "runtimeInstanceId": "cisco-catc-01",
               "startTime": "2025-07-25 14:33:00",
               "startTimeEpoch": 1658756580000,
               "status": "FAILURE",
               "timeDuration": 15
          },
        "msg": "Failed to create site: Parent site does not exist"
      }

#Case_4: Site not found when atempting to delete site
response_4:
    description:
      - Empty response returned when attempting to delete a site that doesn't exist.
      - Helps identify when deletion operations target non-existent sites.
    returned: when trying to delete a site that doesn't exist
    type: list
    sample: >
      {
         "response": [],
         "msg": "Site Global/USA/California/NonExistentBuilding not found for deletion"
      }

#Case_5: Bulk site created successfully
response_5:
    description:
      - Task status information for bulk site creation operations.
      - Includes progress indicators, operation IDs, and status details.
    returned: when bulk site creation is performed
    type: dict
    sample: >
      {
          "response": {
              "startTime": 1725427091204,
              "version": 1725427091204,
              "progress": "{\"TOTAL\":3,\"VALIDATION_FAILURE_COUNT\":0,\"VALIDATION_SUCCESS_COUNT\":3,\
              "VALIDATION_PENDING_COUNT\":0,\"CRAETION_SUCCESS_COUNT\":3,\"message\":\
              "Group import completed successfully.\"}",
              "serviceType": "Grouping Service",
              "operationIdList": [
              "3e7f1f73-b6f8-4ac6-b925-22e372e72510"
              ],
              "isError": false,
              "instanceTenantId": "6663114d388b29001399e46a",
              "id": "0191bb78-0704-767c-94c6-95a6e5a511d1"
          },
          "version": "1.0",
          "msg": "Successfully created 3 sites in bulk operation"
      }
"""

floor_plan = {
    '101101': 'Cubes And Walled Offices',
    '101102': 'Drywall Office Only',
    '101105': 'Free Space',
    '101104': 'Indoor High Ceiling',
    '101103': 'Outdoor Open Space'
}
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
    validate_str
)

import os
import copy


class Site(DnacBase):
    """Class containing member attributes for Site workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.created_site_list, self.updated_site_list, self.update_not_needed_sites = [], [], []
        self.deleted_site_list, self.site_absent_list = [], []
        self.keymap = {}
        self.handle_config = {}

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            The method returns an instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either 'success' or 'failed').
                - self.validated_config: If successful, a validated version of the 'config' parameter.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
            If the validation succeeds, 'self.status' will be 'success' and 'self.validated_config'
            will contain the validated configuration. If it fails, 'self.status' will be 'failed', and
            'self.msg' will describe the validation issues.
        """

        if not self.config:
            self.status = "success"
            self.msg = "Configuration is not available in the playbook for validation"
            self.log("Error: {0}".format(self.msg), "ERROR")
            return self

        self.log("Configuration details found in the playbook: {0}".format(self.config), "INFO")
        temp_spec = dict(
            type=dict(required=False, type='str'),
            site=dict(required=True, type='dict'),
        )
        self.config = self.update_site_type_key(self.config)
        valid_temp, invalid_params = validate_list_of_dicts(
            self.config, temp_spec
        )

        if valid_temp and isinstance(valid_temp, list):
            self.log("Valid site configurations received: {0}".format(
                len(valid_temp)), "DEBUG")
            duplicate_site_names = self.find_duplicate_site_name(valid_temp)
            if duplicate_site_names:
                msg = "Duplicate site names found in the playbook config: {0}".format(
                    ", ".join(duplicate_site_names)
                )
                self.log(msg, "ERROR")
                invalid_params.append(msg)

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(
                "\n".join(invalid_params)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook config params: {0}".format(
            str(valid_temp))
        self.log(self.msg, "INFO")
        self.status = "success"

        return self

    def find_duplicate_site_name(self, input_config):
        """
        Identifies duplicate site names under the same parent from a list of site dictionaries.
        Args:
            input_config (list): A list of dictionaries containing site information.
        Returns:
            list: A list of strings in the form "parent/name" that appear more than once.
        """
        self.log("Starting duplicate site name check.", "DEBUG")
        seen_sites = set()
        duplicates = set()

        for index, entry in enumerate(input_config, start=1):
            self.log("Processing entry {0}: {1}".format(index, entry), "DEBUG")
            site = entry.get("site", {})
            if not site:
                self.log("Entry {0} does not contain a 'site' key or it is empty. Skipping.".format(
                    index),
                    "WARNING"
                )
                continue

            site_types = ["area", "building", "floor"]
            site_name = None
            parent_name = None
            site_type_found = False  # Flag to track if any valid site type was found

            for site_type in site_types:
                if site_type in site:
                    site_data = site[site_type]
                    site_name = site_data.get("name")
                    parent_name = site_data.get("parentName") or site_data.get("parent_name")
                    self.log(
                        "Found site type '{0}' with name '{1}' and parent '{2}' in entry {3}.".format(
                            site_type, site_name, parent_name, index
                        ),
                        "DEBUG"
                    )
                    site_type_found = True
                    break

            if not site_type_found:
                self.log("No recognized site type (area, building, floor) found in site data for entry {0}. Skipping.".format(
                    index),
                    "WARNING"
                )
                continue

            if not site_name or not parent_name:
                self.log("Site name ('{0}') or parent name ('{1}') is missing or invalid in entry {2}. Skipping.".format(
                    site_name, parent_name, index),
                    "WARNING"
                )
                continue

            site_key = (parent_name.strip(), site_name.strip())

            if site_key in seen_sites:
                self.log(
                    "Duplicate site name found under same parent: {0} (Entry {1}). Adding to duplicates list.".format(
                        site_key, index), "ERROR"
                )
                duplicates.add("{}/{}".format(site_key[0], site_key[1]))
            else:
                self.log("Adding site to seen list: {0} (Entry {1})".format(site_key, index), "DEBUG")
                seen_sites.add(site_key)

        if duplicates:
            self.log("Duplicate site names detected: {0}".format(", ".join(duplicates)), "ERROR")
        else:
            self.log("No duplicate site names found.", "DEBUG")

        self.log("Finished duplicate site name check. Returning {0} duplicates.".format(
            len(duplicates)),
            "DEBUG"
        )
        return list(duplicates)

    def get_current_site(self, site):
        """
        Get the current site information.
        Parameters:
          self (object): An instance of a class used for interacting with Cisco Catalyst Center.
          - site (list): A list containing information about the site.
        Returns:
          - dict: A dictionary containing the extracted site information.
        Description:
            This method extracts information about the current site based on
          the provided 'site' list. It determines the type of the site
          (area, building, or floor) and retrieves specific details
          accordingly. The resulting dictionary includes the type, site
          details, and the site ID.
        """

        site_info = {}
        location = get_dict_result(site[0].get("additionalInfo"), 'nameSpace', "Location")
        typeinfo = location.get("attributes").get("type")

        if typeinfo == "area":
            site_info = dict(
                area=dict(
                    name=site[0].get("name"),
                    parentName=site[0].get("siteNameHierarchy").split(
                        "/" + site[0].get("name"))[0]
                )
            )

        elif typeinfo == "building":
            site_info = dict(
                building=dict(
                    name=site[0].get("name"),
                    parentName=site[0].get("siteNameHierarchy").split(
                        "/" + site[0].get("name"))[0],
                    address=location.get("attributes").get("address"),
                    latitude=location.get("attributes").get("latitude"),
                    longitude=location.get("attributes").get("longitude"),
                    country=location.get("attributes").get("country"),
                )
            )

        elif typeinfo == "floor":
            map_geometry = get_dict_result(site[0].get(
                "additionalInfo"), 'nameSpace', "mapGeometry")
            map_summary = get_dict_result(site[0].get(
                "additionalInfo"), 'nameSpace', "mapsSummary")
            rf_model = map_summary.get("attributes").get("rfModel")
            site_info = dict(
                floor=dict(
                    name=site[0].get("name"),
                    parentName=site[0].get("siteNameHierarchy").split(
                        "/" + site[0].get("name"))[0],
                    rf_model=floor_plan.get(rf_model),
                    width=map_geometry.get("attributes").get("width"),
                    length=map_geometry.get("attributes").get("length"),
                    height=map_geometry.get("attributes").get("height"),
                    floorNumber=map_summary.get('attributes').get('floorIndex')
                )
            )
        current_site = dict(
            type=typeinfo,
            site=site_info,
            siteId=site[0].get("id")
        )

        self.log("Current site details: {0}".format(str(current_site)), "INFO")
        return current_site

    def get_site_v1(self, site_name_hierarchy):
        """
        Retrieve site details from Cisco Catalyst Center based on the provided site name.
        Args:
            - site_name_hierarchy (str): The name or hierarchy of the site to be retrieved.
        Returns:
            - response (dict or None): The response from the API call, typically a dictionary containing site details.
                                    Returns None if an error occurs or if the response is empty.
        Criteria:
            - This function uses the Cisco Catalyst Center SDK to execute the 'get_sites' function from the 'site_design' family.
            - If the response is empty, a warning is logged.
            - Any exceptions during the API call are caught, logged as errors, and the function returns None.
        """
        self.log("Fetching site details for site hierarchy: '{0}'".format(site_name_hierarchy), "INFO")
        try:
            response = self.dnac._exec(
                family="sites",
                function='get_site',
                op_modifies=True,
                params={"name": site_name_hierarchy},
            )

            if not response:
                self.log("Empty response received for site: {0}".format(site_name_hierarchy), "WARNING")
                return None

            self.log("Received API response for site '{0}' from 'get_sites': {1}".format(site_name_hierarchy, response), "DEBUG")
            return response

        except Exception as e:
            self.log("An error occurred in 'get_sites':{0}".format(e), "ERROR")
            return None

    def site_exists(self, site_name_hierarchy=None):
        """

        Check if the site exists in Cisco Catalyst Center.
        Parameters:
        - self (object): An instance of the class containing the method.

        Returns:
        - tuple: A tuple containing a boolean indicating whether the site exists and
                a dictionary containing information about the existing site.
                The returned tuple includes two elements:
                - site_exists (bool): Indicates whether the site exists.
                - dict: Contains information about the existing site. If the
                        site doesn't exist, this dictionary is empty.

        Description:
            Checks the existence of a site in Cisco Catalyst Center by querying the
        'get_site' function in the 'sites' family. It utilizes the
        'site_name_hierarchy' parameter from the 'want' attribute to identify the site.
        """
        site_exists = False
        current_site = {}

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
            sites = None
            response = self.get_site(site_name_hierarchy)
            self.log("Raw response from get_site: {}".format(response), "DEBUG")

            if not response:
                self.log("Unexpected response received:", "ERROR")
                return site_exists, current_site

            if isinstance(response, list):
                self.log("Unexpected list returned from get_site, skipping: {}".format(response), "ERROR")
                return site_exists, current_site

            if isinstance(response, dict):
                sites = response.get("response", [])
                if not sites:
                    self.log("No site information found: {0}".format(response), "WARNING")
                    return site_exists, current_site

                for site in sites:
                    if isinstance(site, dict):
                        self.log("No site information found for name: {0}".format(site), "INFO")
                        current_site = dict(site.items())
                        current_site['parentName'] = site.get('nameHierarchy', '').rsplit('/', 1)[0] if site.get('nameHierarchy') else None
                        site_exists = True

        else:
            site_name_hierarchy = self.want.get("site_name_hierarchy")
            response = self.get_site_v1(site_name_hierarchy)

            if not response:
                self.log("No response received from 'get_site' API for site: {0}".format(site_name_hierarchy), "ERROR")
                return site_exists, current_site

            response_data = response.get("response")
            self.log("Received API response from 'get_site': {0}".format(str(response_data)), "DEBUG")

            current_site = self.get_current_site(response_data)
            if current_site:
                site_exists = True
                self.log("Site '{0}' exists in Cisco Catalyst Center".format(site_name_hierarchy), "INFO")
            else:
                self.log("No valid site details found for '{0}'".format(site_name_hierarchy), "WARNING")

        return site_exists, current_site

    def get_parent_id(self, parent_name):
        """
        Retrieve the ID of the parent site in Cisco Catalyst Center.

        Parameters:
        - parent_name (str): The name of the parent site for which the ID is to be retrieved.

        Returns:
        - str: The ID of the parent site if it exists. If the site is not found or an error occurs,
            it returns None.

        Description:
        This method checks whether the specified parent site exists in Cisco Catalyst Center by
        querying the 'get_site' function within the 'sites' family. If the site is found, its
        corresponding ID is returned. If the site does not exist, or if an error occurs during
        the query, the method logs the appropriate message and returns None.
        """
        parent_id = None
        self.log("Starting retrieval of parent site ID for site name: '{}'".format(parent_name), "DEBUG")

        try:
            parent_response = self.get_site(parent_name)
            parent_response = parent_response.get("response")
            if not parent_response:
                self.log("No data found for site '{}'. Site does not exist.".format(parent_name), "INFO")
                return None
            parent_id = parent_response[0].get("id")
            if parent_id:
                self.log("Parent site ID for site '{}' successfully retrieved: {}".format(parent_name, parent_id), "DEBUG")
            else:
                self.log("Parent site ID for site '{}' could not be retrieved from response.".format(parent_name), "WARNING")
        except Exception as e:
            self.log("An error occurred while retrieving site '{}': {}".format(parent_name, str(e)), "ERROR")
        return parent_id

    def get_site_params(self, params):
        """
        Store the site-related parameters.

        Parameters:
          self (object): An instance of a class used for interacting with Cisco Catalyst Center.
          - params (dict): Dictionary containing site-related parameters.
        Returns:
          - dict: Dictionary containing the stored site-related parameters.
                  The returned dictionary includes the following keys:
                  - 'type' (str): The type of the site.
                  - 'site' (dict): Dictionary containing site-related info.
        Description:
            This method takes a dictionary 'params' containing site-related
          information and stores the relevant parameters based on the site
          type. If the site type is 'floor', it ensures that the 'rfModel'
          parameter is stored in uppercase.
        """
        typeinfo = params.get("type")
        site_info = {}

        if typeinfo not in ["area", "building", "floor"]:
            self.status = "failed"
            self.msg = "Given bulk site create playbook is only applicable to DNAC version 2.3.7.6"
            self.log(self.msg, "ERROR")
            self.check_return_status()

        if typeinfo == 'area':
            area_details = params.get('site').get('area')
            site_info['area'] = {
                'name': area_details.get('name'),
                'parentName': area_details.get('parent_name')
            }
        elif typeinfo == 'building':
            building_details = params.get('site').get('building')
            site_info['building'] = {
                'name': building_details.get('name'),
                'address': building_details.get('address'),
                'parentName': building_details.get('parent_name'),
                'latitude': building_details.get('latitude'),
                'longitude': building_details.get('longitude'),
                'country': building_details.get('country')
            }
        else:
            floor_details = params.get('site').get('floor')
            site_info['floor'] = {
                'name': floor_details.get('name'),
                'parentName': floor_details.get('parent_name'),
                'length': floor_details.get('length'),
                'width': floor_details.get('width'),
                'height': floor_details.get('height'),
                'floorNumber': floor_details.get('floor_number', ''),
                'unitsOfMeasure': floor_details.get('units_of_measure')
            }

            if isinstance(floor_details, dict):
                rf_model = floor_details.get("rf_model")
                if not rf_model:
                    self.log("The attribute 'rf_model' is missing or has a falsy value in floor '{0}'.".format(
                        floor_details.get('name')), "WARNING")
                else:
                    site_info["floor"]["rfModel"] = rf_model

        site_params = dict(
            type=typeinfo,
            site=site_info,
        )
        self.log("Site parameters: {0}".format(str(site_params)), "DEBUG")
        return site_params

    def get_site_name_hierarchy(self, site):
        """
        Get and return the site name for a single site.

        Parameters:
        - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        - site (dict): A dictionary containing information about the site.

        Returns:
        - str: The constructed site name or None if not found.

        Description:
        This method constructs the site name by combining the parent name and site name.
        It handles single site operations based on the Cisco DNAC version.
        """
        try:
            self.log("Retrieving site name for site data: {}".format(site), "DEBUG")
            site_type = site.get("type")

            parent_name = site.get("site", {}).get(site_type, {}).get("parent_name")
            self.log("Identified site type: {}".format(site_type), "DEBUG")
            self.log("Retrieved parent name: {}".format(parent_name), "DEBUG")
            if not parent_name:
                self.msg = "Parent name is missing for site type '{}' in the playbook.".format(site_type)
                self.result["response"] = self.msg
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return None

            name = site.get("site", {}).get(site_type, {}).get("name")
            self.log("Retrieved site name: {}".format(name), "DEBUG")

            if not name:
                self.msg = "Site name is missing for site type '{}' in the playbook.".format(site_type)
                self.result["response"] = self.msg
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return None

            site_name_hierarchy = '/'.join([str(parent_name), str(name)])
            self.log("Constructed site name: {}".format(site_name_hierarchy), "INFO")
            return site_name_hierarchy

        except Exception as e:
            error_message = "An error occurred while getting site name: {}".format(str(e))
            self.log(error_message, "ERROR")
            return None

    def compare_float_values(self, ele1, ele2, precision=2):
        """
        Compare two floating-point values with a specified precision.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - ele1 (float): The first floating-point value to be compared.
            - ele2 (float): The second floating-point value to be compared.
            - precision (int, optional): The number of decimal places to consider in the comparison, Defaults to 2.
        Return:
            bool: True if the rounded values are equal within the specified precision, False otherwise.
        Description:
            This method compares two floating-point values, ele1 and ele2, by rounding them
            to the specified precision and checking if the rounded values are equal. It returns
            True if the rounded values are equal within the specified precision, and False otherwise.
        """
        # Check if both the requested and existing values are None or falsy
        if not ele1 and not ele2:
            return True

        # Check if only one of the values is None or falsy
        if bool(ele1) != bool(ele2):
            return False

        return round(float(ele1), precision) == round(float(ele2), precision)

    def is_area_updated(self, updated_site, requested_site):
        """
        Check if the area site details have been updated.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - updated_site (dict): The site details after the update.
            - requested_site (dict): The site details as requested for the update.
        Return:
            bool: True if the area details (name and parent name) have been updated, False otherwise.
        Description:
            This method compares the area details (name and parent name) of the updated site
            with the requested site and returns True if they are equal, indicating that the area
            details have been updated. Returns False if there is a mismatch in the area site details.
        """

        return (
            updated_site['name'] == requested_site['name'] and
            updated_site['parentName'] == requested_site['parentName']
        )

    def is_building_updated(self, updated_site, requested_site):
        """
        Check if the building details in a site have been updated.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - updated_site (dict): The site details after the update.
            - requested_site (dict): The site details as requested for the update.
        Return:
            bool: True if the building details have been updated, False otherwise.
        Description:
            This method compares the building details of the updated site with the requested site.
            It checks if the name, parent_name, latitude, longitude, and address (if provided) are
            equal, indicating that the building details have been updated. Returns True if the
            details match, and False otherwise.
        """
        return (
            updated_site['name'] == requested_site['name'] and
            updated_site['parentName'] == requested_site['parentName'] and
            ('latitude' in requested_site and (requested_site['latitude'] is None or
                                               self.compare_float_values(updated_site.get('latitude'),
                                                                         requested_site.get('latitude')))) and
            ('longitude' in requested_site and (requested_site['longitude'] is None or self.compare_float_values(
                updated_site.get('longitude'), requested_site.get('longitude')))) and
            ('address' in requested_site and (requested_site['address'] is None or updated_site.get(
                'address') == requested_site.get('address')))
        )

    def is_floor_updated(self, updated_site, requested_site):
        """
        Check if the floor details in a site have been updated.

        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - updated_site (dict): The site details after the update.
            - requested_site (dict): The site details as requested for the update.
        Return:
            bool: True if the floor details have been updated, False otherwise.
        Description:
            This method compares the floor details of the updated site with the requested site.
            It checks if the name, rf_model, length, width, and height are equal, indicating
            that the floor details have been updated. Returns True if the details match, and False otherwise.
        """
        self.log("Starting floor update check with updated_site: {} and requested_site: {}".format(updated_site, requested_site), "DEBUG")
        keys_to_compare = ['length', 'width', 'height']
        if updated_site['name'] != requested_site['name']:
            self.log("Floor names do not match: updated '{}', requested '{}'".format(updated_site['name'], requested_site['name']), "DEBUG")
            return False
        updated_rf_model = updated_site.get('rfModel', updated_site.get('rf_model'))
        if updated_rf_model != requested_site.get('rfModel'):
            self.log("RF model mismatch: updated '{}', requested '{}'".format(updated_rf_model, requested_site.get('rfModel')), "DEBUG")
            return False

        if str(requested_site.get('floorNumber')):
            if int(requested_site.get('floorNumber')) != int(updated_site.get('floorNumber')):
                self.log(
                    "Floor number mismatch: updated '{}', requested '{}'".format(updated_site.get('floorNumber'), requested_site.get('floorNumber')), "DEBUG")
                return False

        if requested_site.get("unitsOfMeasure"):
            if requested_site.get("unitsOfMeasure") != updated_site.get("unitsOfMeasure"):
                self.log("Units of measure mismatch: updated '{}', requested '{}'".
                         format(updated_site.get("unitsOfMeasure"), requested_site.get('unitsOfMeasure')), "DEBUG")
                return False

        for key in keys_to_compare:
            if not self.compare_float_values(updated_site[key], requested_site[key]):
                self.log("Mismatch in '{}': updated '{}', requested '{}'".format(key, updated_site[key], requested_site[key]), "DEBUG")
                return False

        self.log("Floor details match between updated and requested site.", "DEBUG")
        return True

    def site_requires_update(self, config=None):
        """
        Check if the site requires updates.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            bool: True if the site requires updates, False otherwise.
        Description:
            This method compares the site parameters of the current site
            ('current_site') and the requested site parameters ('requested_site')
            stored in the 'want' attribute. It checks for differences in
            specified parameters, such as the site type and site details.
        """
        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:
            current_site = self.have.get('current_site', {})
            site_type = current_site.get('type')
            updated_site = current_site.get('site', {}).get(site_type)
            requested_site = self.want['site_params']['site'].get(site_type)
        else:
            current_site = config.get('current_site', {})
            site_type = current_site.get('type')
            self.log("Current site details: {}".format(current_site), "INFO")
            updated_site = current_site
            requested_site = config.get('site_params', {}).get('site', {}).get(site_type)

        self.log("Updated Site details: {0}".format(self.pprint(updated_site)), "INFO")
        self.log("Requested Site details: {0}".format(self.pprint(requested_site)), "INFO")

        if site_type == "building":
            needs_update = not self.is_building_updated(updated_site, requested_site)
            self.log("Building site requires update: {}".format(needs_update), "DEBUG")
            return needs_update

        if site_type == "floor":
            needs_update = not self.is_floor_updated(updated_site, requested_site)
            self.log("Floor site requires update: {}".format(needs_update), "DEBUG")
            return needs_update

        if site_type == "area":
            needs_update = not self.is_area_updated(updated_site, requested_site)
            self.log("Area site requires update: {}".format(needs_update), "DEBUG")
            return needs_update

        self.msg = "Unsupported site type '{0}' given in the playbook.".format(site_type)
        self.set_operation_result("failed", False, self.msg, "ERROR")
        return False

    def get_have(self, config):
        """
        Get the site details from Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): A dictionary containing the configuration details.
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method queries Cisco Catalyst Center to check if a specified site
            exists. If the site exists, it retrieves details about the current
            site, including the site ID and other relevant information. The
            results are stored in the 'have' attribute for later reference.
        """
        site_exists = False
        current_site = None
        have = {}

        try:
            if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
                self.handle_config["create_site"] = []
                self.handle_config["have"] = []
                self.handle_config['area'] = []
                self.handle_config['building'] = []
                self.handle_config['floor'] = []
                for each_config in config:
                    try:
                        have = {
                            "site_name_hierarchy": self.get_site_name_hierarchy(each_config),
                            "site_params": self.get_site_params(each_config),
                            "want": each_config,
                            "site_exists": False
                        }

                        response = self.get_site(have["site_name_hierarchy"])
                        self.log("Raw response from get_site: {}".format(response), "DEBUG")

                        if not response:
                            self.log("Unexpected response received:", "ERROR")
                            self.handle_config["create_site"].append(have)
                            self.handle_config["have"].append(have)
                            continue

                        if isinstance(response, list):
                            self.log("Unexpected list returned from get_site, skipping: {}".format(response), "ERROR")
                            continue

                        if isinstance(response, dict):
                            sites = response.get("response", [])
                            if not sites:
                                self.log("No site information found for name: {0}".format(have["site_name_hierarchy"]), "WARNING")
                                continue

                            for site in sites:
                                if isinstance(site, dict):
                                    self.log("site information found: {0}".format(site), "INFO")
                                    current_site = dict(site.items())
                                    current_site['parentName'] = site.get('nameHierarchy', '').rsplit('/', 1)[0] if site.get('nameHierarchy') else None
                                    site_exists = True

                        have["site_exists"] = site_exists
                        have["current_site"] = current_site
                        have["site_id"] = current_site.get("id")
                        self.handle_config["have"].append(have)

                        if each_config.get("type") == "area":
                            self.handle_config["area"].append(have)
                        elif each_config.get("type") == "building":
                            self.handle_config["building"].append(have)
                        elif each_config.get("type") == "floor":
                            self.handle_config["floor"].append(have)

                    except Exception as e:
                        self.log("Error fetching site for name '{0}': {1}".format(have["site_name_hierarchy"], str(e)))

                self.have = self.handle_config["have"]
                self.log("All site information collected from bulk operation(create_config): {0}".
                         format(self.handle_config["create_site"]), "DEBUG")
                self.log("All site information collected (have): {0}".format(self.have), "DEBUG")

            else:
                site_exists, current_site = self.site_exists()
                self.log("Regular operation: Retrieved site existence: {}".format(site_exists), "DEBUG")

                if site_exists:
                    have["site_id"] = current_site.get("siteId")
                    self.log("SiteId for site version <= 2.3.5.3: {}".format(have["site_id"]), "DEBUG")
                    have["site_exists"] = site_exists
                    have["current_site"] = current_site

                self.have = have
                self.log("Final 'have' state updated: {}".format(self.have), "INFO")

            return self

        except Exception as e:
            self.msg = "An unexpected error occurred while retrieving site details: {}".format(e)
            self.set_operation_result("failed", False, self.msg, "ERROR")

    def get_want(self, config):
        """
        Get all site-related information from the playbook needed for creation/updation/deletion of site in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing configuration information.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            Retrieves all site-related information from playbook that is
            required for creating a site in Cisco Catalyst Center. It includes
            parameters such as 'site_params' and 'site_name_hierarchy.' The gathered
            information is stored in the 'want' attribute for later reference.
        """
        try:
            if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
                self.keymap = self.map_config_key_to_api_param({}, config)
                self.keymap.update({
                    "floor_number": "floorNumber",
                    "rf_model": "rfModel",
                    "parent_name": "parentName",
                    "units_of_measure": "unitsOfMeasure",
                    "parent_name_hierarchy": "parentNameHierarchy"
                })
                want_list = []

                for item in config:
                    site_data = item.get('site', {})
                    site_type = item.get('type')
                    self.log("Processing site of type: {0}".format(site_type), "INFO")

                    want = {}
                    if site_type in ['area', 'building', 'floor'] and site_data:
                        specific_data = site_data.get(site_type, {})
                        for key, value in specific_data.items():
                            if value is not None:
                                want[key] = value
                        want["type"] = site_type
                        want_list.append(want)

                self.want = want_list
                self.log("Desired State (want): {0}".format(self.want), "INFO")
                return self

        except Exception as e:
            self.log("An unexpected error occurred: {0}".format(e), "ERROR")

        want = dict(
            site_params=self.get_site_params(config),
            site_name_hierarchy=self.get_site_name_hierarchy(config),
        )
        self.want = want
        self.log("Desired State (want): {0}".format(self.want), "INFO")
        return self

    def validate_site_input_data(self, config, state):
        """
        Validates site-related data from the playbook configuration to ensure it meets
        the required standards for site creation or modification in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (list): A list of dictionaries, where each dictionary contains site configuration information.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center, with status
            and validation messages updated based on the validation results.
        Description:
            This method performs a series of checks on the playbook configuration data for sites,
            verifying the presence and validity of required fields such as 'name', 'parent_name', 'address',
            'latitude', 'longitude', and other site-specific details depending on the site type (area, building, or floor).
        """
        errormsg = []
        self.log("Starting validation of site input data.", "DEBUG")

        if not config:
            self.log("Config data is missing.", "ERROR")
            errormsg.append("Config data is missing.")
            return errormsg

        self.log("Config data found with {0} entries.".format(str(len(config))), "DEBUG")
        for entry in config:
            self.log("Validating entry in config: {0}".format(str(entry)), "DEBUG")
            site = entry.get("site", {})
            site_type = entry.get("type")
            name = site.get(site_type, {}).get("name")
            parent_name = site.get(site_type, {}).get("parent_name")
            if name:
                self.log("Validating 'name' field: {0}.".format(name), "DEBUG")
                param_spec = dict(type="str", length_max=40)
                validate_str(name, param_spec, "name", errormsg)
            else:
                self.log("Missing 'name' field in entry.", "ERROR")
                errormsg.append("name should not be None or empty")

            if parent_name:
                self.log("Validating 'parent_name' field:{0} ".format(parent_name), "DEBUG")
                param_spec = dict(type="str", length_max=400)
                validate_str(parent_name, param_spec, "parent_name", errormsg)
            else:
                self.log("Missing 'parent_name' field in entry.", "ERROR")
                errormsg.append("parent_name should not be None or empty")

            if state == "deleted":
                continue

            if site_type:
                if site_type not in ("area", "building", "floor"):
                    errormsg.append("site_type: Invalid value '{0}' for site_type in playbook. Must be one of: area, building, or Floor.".format(site_type))
            else:
                errormsg.append("Site_type should not be None or empty")

            if site_type == "building":
                self.log("Performing building-specific validations.", "DEBUG")
                address = site.get(site_type, {}).get("address")
                if address:
                    self.log("Validating 'address' field: " + str(address), "DEBUG")
                    param_spec = dict(type="str", length_max=255)
                    validate_str(address, param_spec, "address", errormsg)

                latitude = site.get(site_type, {}).get("latitude")
                if latitude:
                    self.log("Validating 'latitude' value: " + str(latitude), "DEBUG")
                    if not (isinstance(latitude, (float, int)) and -90 <= latitude <= 90):
                        errormsg.append("Invalid latitude, valid range is -90 to +90.")

                longitude = site.get(site_type, {}).get("longitude")
                if longitude:
                    self.log("Validating 'longitude' value: " + str(longitude), "DEBUG")
                    if not (isinstance(longitude, (float, int)) and -180 <= longitude <= 180):
                        errormsg.append("Invalid longitude. Valid range is -180 to +180.")

                if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
                    if not (latitude and longitude or address):
                        errormsg.append("Either latitude/longitude or address is required.")
                        self.log("Missing required latitude/longitude or address for building.", "ERROR")
                    elif (latitude and not longitude) or (not latitude and longitude):
                        errormsg.append("Either Latitude or longitude is missing in the given playbook")
                else:
                    if not (latitude and longitude):
                        errormsg.append("Latitude and longitude are required.")
                        self.log("Missing required latitude and longitude for building.", "ERROR")

                country = site.get(site_type, {}).get("country")
                if country:
                    self.log("Validating 'country' field: " + str(country), "DEBUG")
                    param_spec = dict(type="str", length_max=100)
                    validate_str(country, param_spec, "country", errormsg)
                else:
                    self.log("Missing 'country' field in building entry.", "ERROR")
                    errormsg.append("country should not be None or empty")

            if site_type == "floor":
                self.log("Performing floor-specific validations.", "DEBUG")
                floor_number = site.get(site_type, {}).get("floor_number")
                if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
                    if floor_number or floor_number == 0:
                        self.log("Validating 'floor_number': " + str(floor_number), "DEBUG")
                        if not (isinstance(floor_number, int) and -200 <= floor_number <= 200):
                            errormsg.append("Please enter a valid floor number (-200 to 200)")
                            self.log("'floor_number' is out of the valid range (-200 to 200).", "ERROR")
                    else:
                        errormsg.append("'floor_number' should not be None or empty.")
                        self.log("Missing 'floor_number' in floor entry.", "ERROR")
                else:
                    if floor_number:
                        self.log("Validating 'floor_number': " + str(floor_number), "DEBUG")
                        if not (isinstance(floor_number, int) and -200 <= floor_number <= 200):
                            errormsg.append("Please enter a valid floor number (-200 to 200)")
                            self.log("'floor_number' is out of the valid range (-200 to 200).", "ERROR")

                rf_model = site.get(site_type, {}).get("rf_model")
                if rf_model:
                    self.log("Validating 'rf_model': " + str(rf_model), "DEBUG")
                    rf_model_list = [
                        "Free Space",
                        "Outdoor Open Space",
                        "Cubes And Walled Offices",
                        "Indoor High Ceiling",
                        "Drywall Office Only"
                    ]
                    if rf_model not in rf_model_list:
                        errormsg.append("rf_model: Invalid value '{0}' for rf_model in playbook. Must be one of: '{1}'".
                                        format(site_type, str(rf_model)))
                        self.log("Invalid 'rf_model': " + str(rf_model), "ERROR")
                else:
                    errormsg.append("RF should not be None or empty")

                width = site.get(site_type, {}).get("width")
                if width:
                    self.log("Validating 'width': " + str(width), "DEBUG")
                    if not (isinstance(width, (float, int)) and 5.00 <= width <= 99999.00):
                        errormsg.append("Invalid width. Valid range is 5.00 to 99999.00 ft.")
                else:
                    errormsg.append("Width should not be None or empty")

                length = site.get(site_type, {}).get("length")
                if length:
                    self.log("Validating 'length': " + str(length), "DEBUG")
                    if not (isinstance(length, (float, int)) and 5.00 <= length <= 99999.00):
                        errormsg.append("Invalid length. Valid range is 5.00 to 99999.00 ft.")
                else:
                    errormsg.append("length should not be None or empty")

                height = site.get(site_type, {}).get("height")
                if height:
                    if not (isinstance(height, (float, int)) and 3.00 <= height <= 99999.00):
                        errormsg.append("Invalid height. Valid range is 3.00 to 99999.00 ft.")
                else:
                    errormsg.append("height should not be None or empty")

                if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
                    units_of_measure = site.get(site_type, {}).get("units_of_measure")
                    if units_of_measure:
                        if units_of_measure not in ("feet", "meters"):
                            errormsg.append(
                                "units_of_measure: Invalid value '{0}' for units_of_measure in playbook. Must be one of 'feet' or 'meters'.".format(
                                    units_of_measure))
                            self.log("Invalid 'units_of_measure': {0}. Expected 'feet' or 'meters'.".format(units_of_measure), "ERROR")
                    else:
                        site[site_type]["units_of_measure"] = "feet"
                        self.log("Default value assigned for units_of_measure: feet.", "INFO")

                upload_floor_image_path = site.get(site_type, {}).get("upload_floor_image_path")
                if upload_floor_image_path:
                    param_spec = dict(type="str", length_max=500)
                    validate_str(upload_floor_image_path, param_spec, "upload_floor_image_path", errormsg)
                elif upload_floor_image_path == "":
                    errormsg.append("upload_floor_image_path should not be whitespace")

                if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:
                    if upload_floor_image_path:
                        errormsg.append(
                            "upload_floor_image_path parameter not supported for 2.3.5.3 Catalyst Center and only applicable from "
                            "2.3.7.6 Catalyst version onwards"
                        )

        if len(errormsg) > 0:
            self.msg = "Missing or invalid parameters in playbook config: '{0}' ".format(", ".join(errormsg))
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.msg = "Successfully validated config params."
        self.log(self.msg, "INFO")
        self.status = "success"
        return self

    def update_floor(self, site_params, config):
        """
        Updates a floor in the site hierarchy using the provided site parameters.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_params (dict): Dictionary containing parameters required for the floor update, including the site_id.

        Returns:
            dict: The API response from the 'updates_a_floor' operation or None if an exception occurs.
        """
        response = None
        units_of_measure = ["feet", "meters"]
        rf_model = [
            "Free Space",
            "Outdoor Open Space",
            "Cubes And Walled Offices",
            "Indoor High Ceiling",
            "Drywall Office Only"
        ]
        try:
            self.log("Updating floor with parameters: {0}".format(site_params), "INFO")
            parent_name = site_params.get("site", {}).get("floor", {}).get("parentName")
            if not parent_name:
                self.log("Parent name is missing in the site parameters.", "ERROR")
                return None
            parent_id = self.get_parent_id(parent_name)
            if not parent_id:
                self.log("Failed to retrieve parent ID for parent name: '{}'".format(parent_name), "ERROR")
                return None
            site_params['site']['floor']['parentId'] = parent_id
            self.log("Retrieved parent ID: '{}' for parent name: '{}'".format(parent_id, parent_name), "DEBUG")

            units_of_measure_value = config.get("unitsOfMeasure")
            if units_of_measure_value not in units_of_measure:
                error_msg = "Given Unit of Measure: {} not in allowed units: {}".format(units_of_measure_value, units_of_measure)
                self.module.fail_json(msg=error_msg)
            else:
                site_params['site']['floor']['unitsOfMeasure'] = units_of_measure_value
                self.log("Set 'units of measure' to: {}".format(units_of_measure_value), "DEBUG")

            rf_model_value = site_params.get('site', {}).get('floor', {}).get('rfModel')
            if rf_model_value not in rf_model:
                error_msg = "Given RF Model: {} not in valid models: {}".format(rf_model_value, rf_model)
                self.module.fail_json(msg=error_msg)
            else:
                self.log("Validated 'RF Model' as: {}".format(rf_model_value), "DEBUG")

            self.log("Updated site_params with parent_id: {0}".format(site_params), "INFO")
            floor_param = site_params.get('site', {}).get('floor')
            site_params['site']['floor']['parentId'] = parent_id
            site_id = site_params.get("site_id")
            floor_param['id'] = site_id

            response = self.dnac._exec(
                family="site_design",
                function='updates_a_floor',
                op_modifies=True,
                params=floor_param
            )

            if response and isinstance(response, dict):
                self.log("Initial API response from 'updates_a_floor': {0}".format(response), "DEBUG")
                execution_id = response.get("executionId")

                if execution_id:
                    while True:
                        execution_details = self.get_execution_details(execution_id)
                        if execution_details.get("status") == "SUCCESS":
                            self.log("Floor update completed successfully.", "INFO")
                            break
                        elif execution_details.get("bapiError"):
                            self.status = "failed"
                            self.msg = "Error during floor update execution: {0}".format(execution_details.get("bapiError")), "ERROR"
                            self.result['response'] = self.msg
                            self.log(self.msg, "ERROR")
                            break

        except Exception as e:
            error_msg = "Exception occurred while updating floor with site_id '{0}' due to: {1}".format(
                site_params.get('site_id'), str(e)
            )
            self.log(error_msg, "ERROR")

        return response

    def update_building(self, site_params):
        """
        Updates a building in the site hierarchy using the provided site id.

        Args:
            site_params (dict): Dictionary containing parameters required for the building update, including the site_id.

        Returns:
            dict: The API response from the 'update_a_building' operation.
        """
        response = None
        try:
            self.log("Updating building with parameters: {0}".format(site_params), "INFO")
            parent_name = site_params.get("site", {}).get("building", {}).get("parentName")
            parent_id = self.get_parent_id(parent_name)
            site_params['site']['building']['parentId'] = parent_id
            self.log("Updated site_params with parent_id: {0}".format(site_params), "INFO")
            building_param = site_params.get('site', {}).get('building')
            site_id = site_params.get("site_id")
            building_param['id'] = site_id

            self.log("Before updating the building params:{0}".format(building_param), "INFO")
            response = self.dnac._exec(
                family="site_design",
                function='updates_a_building',
                op_modifies=True,
                params=building_param,
            )
            self.log("Building update successful. API response: {0}".format(response), "DEBUG")

            return response

        except Exception as e:
            self.msg = "Exception occurred while updating building '{0}' due to: {1}".format(site_params.get('site_name_hierarchy'), str(e))
            self.result['response'] = self.msg
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def update_area(self, site_params):
        """
        Updates an area in the site hierarchy using the provided site id.

        Args:
            site_params (dict): Dictionary containing parameters required for the area update, including the site_id.

        Returns:
            dict: The API response from the 'update_an_area' operation.
        """
        response = None
        try:
            self.log("Updating area with parameters: {0}".format(self.have), "INFO")
            parent_id = self.have.get("current_site", {}).get("parentId")
            site_params['site']['area']['parentId'] = parent_id
            area_param = site_params.get('site', {}).get('area')
            site_id = self.have.get("site_id")
            area_param['id'] = site_id
            self.log("Updating area with parameters: {0}".format(area_param), "INFO")

            response = self.dnac._exec(
                family="site_design",
                function='updates_an_area',
                op_modifies=True,
                params=area_param,
            )
            self.log("Area update successful. API response: {0}".format(
                response), "DEBUG")

            return response

        except Exception as e:
            self.msg = "Exception occurred while updating area'{0}' due to: {1}".format(site_params.get('site_name_hierarchy'), str(e))
            self.result['response'] = self.msg
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def creating_bulk_site(self, params):
        """
        Creates a site (area, building, or floor) in the site hierarchy using the provided site parameters.

        Args:
            site_params (dict): Dictionary containing parameters required for the site creation.

        Returns:
            dict: The API response from the 'create_sites' operation.
        """

        self.log("Before executing create site: {0}".format(params), "INFO")
        try:
            response = self.dnac._exec(
                family="site_design",
                function='create_sites',
                op_modifies=True,
                params={"payload": params}
            )

            if not response:
                self.log("Site creation failed: No response from the API.", "ERROR")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                return None

            self.log("Site creation successful. Response: {0}".format(response), "INFO")
            return response

        except Exception as e:
            self.msg = "Exception occurred while creating site due to: {}".format(str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def change_payload_data(self, config):
        """
        Modify payload data to match the new API version format.

        Parameters:
            self (object): An instance of the class calling this function.
            config (dict): A configuration dictionary containing site data and type information.

        Returns:
            dict: A dictionary with formatted payload data, ready for submission to Cisco Catalyst Center.

        Description:
            This function prepares and maps configuration data for creating or updating a site in Cisco Catalyst Center.
            It extracts the site-specific data based on the `type` value ('area', 'building', or 'floor') from the
            input configuration. Each key in the site-specific data is mapped to a standardized key using `self.keymap`.
        """
        payload_data = {}
        try:
            self.log("Starting to process payload data.", "DEBUG")
            if config:
                self.log("Config data found, proceeding with processing.", "DEBUG")
                site_data = config.get('site', {})
                site_type = config.get('type')

                if site_type in ['area', 'building', 'floor'] and site_data:
                    self.log("Site type identified as: " + str(site_type), "DEBUG")
                    specific_data = site_data.get(site_type, {})

                    for key, value in specific_data.items():
                        if value is not None:
                            self.log("Mapping key: " + str(key) + " to value: " + str(value), "DEBUG")
                            mapped_key = self.keymap.get(key, key)
                            payload_data[mapped_key] = value
                            payload_data["type"] = site_type
                            self.log("Payload data created successfully.", "DEBUG")
                        else:
                            self.log("Skipping key: " + str(key) + " as value is None.", "DEBUG")
                else:
                    self.log("Invalid site type or missing site data in the configuration.", "ERROR")
            else:
                self.log("No configuration data provided.", "ERROR")

            return payload_data
        except Exception as e:
            self.msg = "Unable to process the payload data : {}".format(str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def is_site_exist(self, site_name):
        """
        Checks if a site exists in Cisco Catalyst Center by retrieving site information based on the provided site name.

        Args:
            site_name (str): The name or hierarchy of the site to be retrieved.

        Returns:
                A boolean indicating whether the site exists (True if found, False otherwise).

        Details:
            - Calls `get_site()` to retrieve site details from Cisco Catalyst Center.
            - If the site does not exist, it returns (False).
            - Logs detailed debug information about the retrieval attempt and any errors that occur.

        """
        site_exists = False
        try:
            response = self.get_site(site_name)

            if response is None:
                self.log("No site details retrieved for site name: {0}".format(site_name), "DEBUG")
                return site_exists

            self.log("Site details retrieved for site {0}: {1}".format(site_name, str(response)), "DEBUG")
            site_exists = True

        except Exception as e:
            self.log(
                "An exception occurred while retrieving Site details for Site '{0}' "
                "does not exist in the Cisco Catalyst Center. Error: {1}".format(site_name, e),
                "INFO"
            )

        return site_exists

    def process_bulk_site(self, process_config):
        """
         Processes the bulk creation of sites in Cisco Catalyst Center and uploads floor maps for floor sites if specified.

        Args:
            process_config (list): A list of dictionaries, where each dictionary contains details for creating a site.

        Returns:
            bool: True if all sites were created successfully and floor maps (if applicable) were uploaded.
                  Returns False if the bulk site creation failed.

        Details:
            - Calls `creating_bulk_site` to initiate the creation of multiple sites in Cisco Catalyst Center.
            - Logs detailed debug information about the creation process.
            - If the creation is successful, logs the task ID and monitors the task status.
            - For floor sites, attempts to upload the floor map if an upload path is provided.
            - If a floor map upload fails, logs an error message. If no upload path is provided, logs that no floor map was uploaded.
        """
        self.log("Initiating bulk site creation for {0} sites.".format(
            len(process_config)), "INFO")
        response = self.creating_bulk_site(process_config)
        self.log("Response from creating_bulk_site for {0}: {1}".
                 format(process_config, response), "DEBUG")

        if not response or not isinstance(response, dict):
            self.log("Invalid response received from creating_bulk_site.", "ERROR")
            return False

        task_id = response.get("response", {}).get("taskId")
        if not task_id:
            self.log("Failed to retrieve task ID for site creation.", "ERROR")
            return False

        self.log("Task Id for the 'site_creation' task: {0}".format(task_id), "INFO")

        task_name = "create_sites"
        success_msg = "Site created successfully."
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        for site in process_config:
            site_name = site.get("name")
            if site_name:
                self.created_site_list.append("{0}: {1}".format(site, site_name))

        self.log("List of successfully created sites: {0}".format(self.created_site_list), "DEBUG")

        if len(self.created_site_list) != len(process_config):
            self.log("Bulk site creation failed. Expected {0} sites, but only {1} were created.".
                     format(len(process_config), len(self.created_site_list)), "WARNING")
            return False

        self.log("All sites have been successfully created. Proceeding with floor site processing.",
                 "INFO")

        # Process floor sites if all sites were successfully created
        for site in process_config:
            if site.get("type") == "floor":
                floor_name = site.get("name")
                self.log("Processing floor site '{0}'.".format(floor_name), "INFO")

                upload_path = site.get("upload_floor_image_path", None)
                if upload_path:
                    self.log("Uploading floor map for '{0}' from '{1}'.".
                             format(floor_name, upload_path), "INFO")
                    self.log("Upload path found for floor '{0}'. Starting upload floor map from '{1}.'".
                             format(floor_name, upload_path), "INFO")
                    map_details, map_status, success_message = self.upload_floor_image(site)
                    if map_details:
                        self.log("Floor map for '{0}' uploaded successfully: {1}".format(
                            floor_name, success_message), "INFO")
                    else:
                        self.log("Floor map upload failed for '{0}'. Please check the upload path and retry.".
                                 format(floor_name), "ERROR")
                else:
                    self.log("No upload path provided for '{0}'. Floor created without floor map.".
                             format(floor_name), "INFO")
        self.log("Bulk site creation process completed successfully.", "INFO")
        return True

    def get_diff_merged(self, config):
        """
        Update/Create site information in Cisco Catalyst Center with fields
        provided in the playbook.
        Parameters:
          self (object): An instance of a class used for interacting with Cisco Catalyst Center.
          config (dict): A dictionary containing configuration information.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method determines whether to update or create a site in Cisco Catalyst Center based on the provided
            configuration information. If the specified site exists, the method checks if it requires an update
            by calling the 'site_requires_update' method. If an update is required, it calls the 'update_site'
            function from the 'sites' family of the Cisco Catalyst Center API. If the site does not require an update,
            the method exits, indicating that the site is up to date.
        """
        site_updated = False
        site_created = False

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
            self.handle_config['area'] = []
            self.handle_config['building'] = []
            self.handle_config['floor'] = []
            try:
                create_site = copy.deepcopy(self.handle_config["create_site"])
                if len(create_site) > 0:
                    self.log("Starting site creation process.", "DEBUG")
                    for each_config in create_site:
                        payload_data = self.change_payload_data(each_config.get("want"))
                        if payload_data:
                            payload_data[self.keymap["parent_name_hierarchy"]] = \
                                payload_data.get(self.keymap["parent_name"])
                            del payload_data[self.keymap["parent_name"]]
                            self.log("Payload data prepared for site creation: {0}".format(payload_data), "DEBUG")

                        if payload_data.get("type") == "area":
                            self.handle_config["area"].append(payload_data)
                            self.log("Added to area: {0}".format(payload_data), "DEBUG")
                        elif payload_data.get("type") == "building":
                            self.handle_config["building"].append(payload_data)
                            self.log("Added to building: {0}".format(payload_data), "DEBUG")
                        elif payload_data.get("type") == "floor":
                            self.handle_config["floor"].append(payload_data)
                            self.log("Added to floor: {0}".format(payload_data), "DEBUG")
                        else:
                            self.msg = "Site not available in payload '{0}'.".format(payload_data)
                            self.fail_and_exit(self.msg)

                    combined_config = []
                    for each_type in ("area", "building", "floor"):
                        if self.handle_config[each_type]:
                            combined_config.extend(self.handle_config[each_type])

                    if not self.process_bulk_site(combined_config):
                        site_name = payload_data.get(self.keymap["parent_name_hierarchy"])
                        self.msg = "Unable to proceed to create bulk site '{0}'.".format(site_name)
                        self.fail_and_exit(self.msg)

                task_detail_list = []
                for each_config in self.have:
                    site_name_hierarchy = each_config.get("site_name_hierarchy")
                    if each_config.get("site_exists"):
                        self.log("Processing site: {}".format(site_name_hierarchy), "DEBUG")
                        new_site_config = self.change_payload_data(each_config.get("want"))
                        if new_site_config.get("type") == "area":
                            self.msg = "Site - {0} does not need any update".format(site_name_hierarchy)
                            self.log(self.msg, "INFO")
                            self.update_not_needed_sites.append(new_site_config.get("type") + ": " + site_name_hierarchy)
                        elif new_site_config.get("type") in ("building", "floor"):
                            site_params = each_config.get("site_params")
                            site_params["site_id"] = each_config.get("site_id")
                            site_type = site_params.get("type")
                            force_upload_image_state = False

                            if (
                                site_type == "floor"
                                and site_params["site_id"]
                                and new_site_config.get("force_upload_floor_image")
                                and new_site_config.get("upload_floor_image_path")
                            ):
                                map_details, map_status, success_message = self.upload_floor_image(new_site_config)

                                if map_details:
                                    self.log("Floor map for '{0}' uploaded successfully: {1}".
                                             format(new_site_config.get("name"), success_message), "INFO")
                                    force_upload_image_state = True
                                else:
                                    self.log("Floor map upload failed for '{0}'. Please check the upload path and retry.".
                                             format(new_site_config.get("name")), "ERROR")

                            if self.site_requires_update(each_config):

                                self.log("Site requires update, starting update for type: {}".format(site_type), "DEBUG")
                                response = (self.update_floor(site_params, new_site_config) if site_type == "floor"
                                            else self.update_area(site_params) if site_type == "area"
                                            else self.update_building(site_params) if site_type == "building"
                                            else self.log("Unknown site type: {0}".format(site_type), "ERROR"))

                                self.log("Received API response from 'update_site': {0}".
                                         format(str(response)), "DEBUG")

                                if response and isinstance(response, dict):
                                    taskid = response["response"]["taskId"]

                                    while True:
                                        task_details = self.get_task_details(taskid)
                                        if site_type != "floor":
                                            if task_details.get("progress") == "Group is updated successfully":
                                                task_detail_list.append(task_details)
                                                self.updated_site_list.append(site_type + ": " + site_name_hierarchy)
                                                self.log("Site '{}' updated successfully.".format(site_name_hierarchy), "INFO")
                                                break
                                        else:
                                            if task_details.get("progress") == "Service domain is updated successfully.":
                                                task_detail_list.append(task_details)
                                                self.updated_site_list.append(site_type + ": " + site_name_hierarchy)
                                                break

                                        if task_details.get("bapiError"):
                                            msg = task_details.get("bapiError")
                                            self.set_operation_result("failed", False, msg, "ERROR",
                                                                      task_details).check_return_status()
                                            break
                                else:
                                    self.msg = "Unable to execute the update the site: {0} ".format(site_name_hierarchy)
                                    self.log(self.msg, "INFO")
                                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                            else:
                                self.msg = "Site - {0} does not need any update".format(site_name_hierarchy)
                                if force_upload_image_state:
                                    self.msg = "Floor image updated for the Site : {0}".format(site_name_hierarchy)
                                    self.updated_site_list.append(site_type + ": " + site_name_hierarchy)
                                    self.log(self.msg, "INFO")
                                else:
                                    self.log(self.msg, "INFO")
                                    self.update_not_needed_sites.append(new_site_config.get("type") + ": " + site_name_hierarchy)
            except Exception as e:
                self.log("Yaml is not available for bulk: {}".format(str(e)), "ERROR")

            return self

        else:
            site_params = self.want.get("site_params")
            site_type = site_params.get("type")
            if self.have.get("site_exists"):
                site_name_hierarchy = self.want.get("site_name_hierarchy")
                if not self.site_requires_update():
                    self.update_not_needed_sites.append(site_type + ": " + site_name_hierarchy)
                    self.msg = "Site - {0} does not need any update".format(site_name_hierarchy)
                    self.log(self.msg, "INFO")
                else:
                    try:
                        site_params["site_id"] = self.have.get("site_id")
                        self.log("Site parameters prepared for update: {}".format(site_params))
                        self.log("Site update process started.", "INFO")

                        if site_params['site'].get('building'):
                            building_details = {}
                            for key, value in site_params['site']['building'].items():
                                if value is not None:
                                    building_details[key] = value

                            site_params['site']['building'] = building_details

                        response = self.dnac._exec(
                            family="sites",
                            function='update_site',
                            op_modifies=True,
                            params=site_params,
                        )
                        self.log("Received API response from 'update_site': {0}".format(str(response)), "DEBUG")

                        if response and isinstance(response, dict):
                            execution_id = response.get("executionId")
                            while True:
                                execution_details = self.get_execution_details(execution_id)
                                if execution_details.get("status") == "SUCCESS":
                                    self.result['changed'] = True
                                    site_updated = True
                                    self.updated_site_list.append(str(site_type) + ": " + str(site_name_hierarchy))
                                    self.log("Site - {0} Updated Successfully".format(site_name_hierarchy), "INFO")
                                    break
                                elif execution_details.get("bapiError"):
                                    self.msg = "Unable to Update: " + execution_details.get("bapiError")
                                    self.set_operation_result("failed", False, self.msg, "ERROR",
                                                              execution_details).check_return_status()

                    except Exception as e:
                        self.msg = "Unexpected error occurred while update: {0}".format(str(e))
                        self.log(self.msg, "ERROR")
                        self.set_operation_result("failed", False, self.msg, "ERROR",
                                                  site_name_hierarchy).check_return_status()

            else:
                try:
                    try:
                        if site_params['site'].get('building'):
                            building_details = {}
                            for key, value in site_params['site']['building'].items():
                                if value is not None:
                                    building_details[key] = value

                            site_params['site']['building'] = building_details

                    except Exception as e:
                        site_type = site_params['type']
                        name = site_params['site'][site_type]['name']
                        self.log("The site '{0}' is not categorized as a building; no need to filter 'None' values.".
                                 format(name), "INFO")

                    site_type = site_params['type']
                    parent_name = site_params.get('site').get(site_type).get('parentName')
                    try:
                        response = self.get_site_v1(parent_name)
                        if not response:
                            self.msg = "Parent name '{0}' does not exist in the Cisco Catalyst Center.".format(parent_name)
                            self.log(self.msg, "DEBUG")
                            self.site_absent_list.append(str(parent_name) + " does not exist ")
                            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    except Exception as e:
                        self.log("No response received from 'get_site_v1' API for site: {0}".format(parent_name + str(e)), "ERROR")

                    response = self.dnac._exec(
                        family="sites",
                        function='create_site',
                        op_modifies=True,
                        params=site_params,
                    )
                    self.log("Received API response from 'create_site': {0}".format(str(response)), "DEBUG")

                    if response and isinstance(response, dict):
                        executionid = response.get("executionId")
                        while True:
                            execution_details = self.get_execution_details(executionid)
                            if execution_details.get("status") == "SUCCESS":
                                self.result['changed'] = True
                                break
                            elif execution_details.get("bapiError"):
                                self.msg = "Unable to Create: " + str(execution_details.get("bapiError"))
                                self.set_operation_result("failed", False, self.msg, "ERROR",
                                                          execution_details).check_return_status()
                                break

                    site_exists, current_site = self.site_exists()
                    if site_exists:
                        site_name_hierarchy = self.want.get("site_name_hierarchy")
                        self.created_site_list.append(str(site_type) + ": " + str(site_name_hierarchy))
                        self.log("Site '{0}' created successfully".format(site_name_hierarchy), "INFO")
                    return self

                except Exception as e:
                    self.msg = "Unexpected error occurred while create: {0}".format(str(e))
                    self.log(self.msg, "ERROR")
                    self.set_operation_result("failed", False, self.msg, "ERROR",
                                              site_name_hierarchy).check_return_status()

        return self

    def delete_single_site(self, site_id, site_name_hierarchy):
        """"
        Delete a single site in the Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_id (str): The ID of the site to be deleted.
           site_name_hierarchy  (str): The name of the site to be deleted.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This function initiates the deletion of a site in the Cisco Catalyst Center by calling the delete API.
            If the deletion is successful, the result is marked as changed, and the status is set to "success."
            If an error occurs during the deletion process, the status is set to "failed," and the log contains
            details about the error.
        """
        try:
            response = self.dnac._exec(
                family="sites",
                function="delete_site",
                op_modifies=True,
                params={"site_id": site_id},
            )
            if response and isinstance(response, dict):
                self.log("Received API response from 'delete_site': {0}".format(str(response)), "DEBUG")
                executionid = response.get("executionId")

                while True:
                    execution_details = self.get_execution_details(executionid)
                    if execution_details.get("status") == "SUCCESS":
                        self.status = "success"
                        self.deleted_site_list.append(site_name_hierarchy)
                        self.log("Site '{0}' deleted successfully".format(site_name_hierarchy), "INFO")
                        break
                    elif execution_details.get("bapiError"):
                        self.log("Error response for 'delete_site' execution: {0}".format(
                            execution_details.get("bapiError")), "ERROR")
                        self.module.fail_json(msg=execution_details.get(
                            "bapiError"), response=execution_details)
                        break

        except Exception as e:
            self.msg = "Exception occurred while deleting site '{0}' due to: {1}".format(site_name_hierarchy, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def delete_floor(self, site_name_hierarchy, site_id):
        """
        Deletes a floor site by ID.

        Parameters:
            site_id (str): The ID of the floor site to be deleted.
            site_name_hierarchy (str): The name of the floor site to be deleted.

        Returns:
            dict: The API response from the 'deletes_a_floor' operation.
        """

        if not site_id:
            self.log("No site ID found for building site: '{}'.".format(site_name_hierarchy), "ERROR")
            return None
        params = {'id': site_id}
        task_id = self.get_taskid_post_api_call("site_design", "deletes_a_floor", params)
        return task_id

    def delete_building(self, site_name_hierarchy, site_id):
        """
        Deletes a building site by ID, including all associated floors.

        Parameters:
            site_id (str): The ID of the building site to be deleted.
            site_name_hierarchy (str): The name of the building site to be deleted.

        Returns:
            dict: The API response from the 'deletes_a_building' operation.
        """

        if not site_id:
            self.log("No site ID found for building site: '{}'.".format(site_name_hierarchy), "ERROR")
            return None

        try:
            self.log("Fetching child sites for building: '{}'".format(site_name_hierarchy), "DEBUG")
            get_sites_params = {"name_hierarchy": site_name_hierarchy + ".*", "type": "floor"}
            response = self.execute_get_request("site_design", "get_sites", get_sites_params)

            if response and isinstance(response, dict):
                self.log("Received response from get_sites: {}".format(response), "DEBUG")

                child_sites = response.get("response", [])
                for child in child_sites:
                    child_site_id = child.get("id")
                    child_site_name_hierarchy = child.get("nameHierarchy")

                    if child_site_id:
                        self.log("Deleting floor: {0} with ID: {1}".format(child_site_name_hierarchy, child_site_id), "INFO")
                        del_task_id = self.delete_floor(child_site_name_hierarchy, child_site_id)
                        if del_task_id:
                            success_msg = "Deleted floor: {0}. Task Id: {1}".format(
                                child_site_name_hierarchy, del_task_id)
                            self.get_task_status_from_tasks_by_id(
                                del_task_id, "delete_floor", success_msg).check_return_status()
                            self.log("Deleted child floor: {0} with ID: {1}".format(
                                child_site_name_hierarchy, child_site_id), "INFO")
                            self.deleted_site_list.append("floor: {0}".format(str(child_site_name_hierarchy)))
                        else:
                            self.msg = "Unable to delete child site: {0}".format(child_site_name_hierarchy)
                            self.set_operation_result("failed", False,
                                                      self.msg, "ERROR").check_return_status()

            self.log("Deleting building site: '{0}' with ID: '{1}'".format(
                site_name_hierarchy, site_id), "INFO")
            response = self.dnac._exec(
                family="site_design",
                function="deletes_a_building",
                op_modifies=True,
                params={'id': site_id},
            )
            self.log("Successfully deleted building site: {0}. API response: {1}".format(site_name_hierarchy, response), "DEBUG")
            return response

        except Exception as e:
            self.msg = "Exception occurred while deleting building site '{0}' with site_id '{1}' due to: {2}".format(site_name_hierarchy, site_id, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def delete_area(self, site_name_hierarchy, site_id):
        """
        Deletes an area site by ID.

        Parameters:
            site_id (str): The ID of the site to be deleted.
            site_name_hierarchy (str): The name of the site to be deleted.

        Returns:
            self: An instance of the class used for interacting with Cisco Catalyst Center.
        """

        self.log("Initiating delete_area for site: '{}' with ID: '{}'".format(site_name_hierarchy, site_id), "DEBUG")
        if not site_id:
            self.log("No site ID found for area site: '{}'.".format(site_name_hierarchy), "ERROR")
            return None

        try:
            self.log("Fetching child sites for area: '{}'".format(site_name_hierarchy), "DEBUG")

            for delete_type in ("floor", "building"):
                get_sites_params = {"name_hierarchy": site_name_hierarchy + ".*",
                                    "type": delete_type}
                self.log("Parameters for get_sites request: {}".format(get_sites_params), "DEBUG")
                response = self.execute_get_request("site_design", "get_sites", get_sites_params)
                self.log("Response from get_sites request: {}".format(response), "DEBUG")

                if response and isinstance(response, dict):

                    child_sites = response.get("response", [])
                    self.log("Found {0} child sites of type '{1}' for area '{2}'".format(len(child_sites), delete_type, site_name_hierarchy), "DEBUG")
                    for child in child_sites:
                        child_site_id = child.get("id")
                        child_site_name_hierarchy = child.get("nameHierarchy")
                        self.log("Processing child site: '{0}' with ID: '{1}'".format(child_site_name_hierarchy, child_site_id), "DEBUG")

                        if child_site_id:
                            self.log("Deleting {0}: {1} with ID: {2}".format(
                                delete_type, child_site_name_hierarchy, child_site_id), "INFO")
                            delete_method = getattr(self, "delete_{}".format(delete_type))
                            del_response = delete_method(child_site_name_hierarchy, child_site_id)
                            self.log("Delete response for {0}: {1}".format(child_site_name_hierarchy, del_response), "DEBUG")
                            if del_response:
                                self.log("Successfully deleted: {0}".format(child_site_name_hierarchy), "INFO")
                                self.log("Deleted: {0} and  response: {1}".format(child_site_name_hierarchy, response), "INFO")
                            else:
                                self.msg = "Unable to delete the: {0}, {1}".format(delete_type, site_name_hierarchy)
                                self.log(self.msg, "ERROR")
                                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            self.log("Attempting to delete area site: '{0}' with ID: '{1}'".
                     format(site_name_hierarchy, site_id), "INFO")
            get_sites_params = {"name_hierarchy": site_name_hierarchy + ".*",
                                "type": "area"}
            self.log("Parameters for get_sites request: {0}".format(get_sites_params), "DEBUG")
            self.log("Fetching child sites using parameters: {0}".format(
                get_sites_params), "DEBUG")
            response = self.execute_get_request("site_design", "get_sites", get_sites_params)
            if not response or not isinstance(response, dict):
                self.log("Failed to retrieve child sites for '{0}'. Response: {1}".
                         format(site_name_hierarchy, response), "ERROR")
                return None

            self.log("Response from get_sites request: {}".format(response), "DEBUG")
            child_sites = response.get("response", [])
            self.log("Found {0} child sites for area '{1}'".format(len(child_sites),
                                                                   site_name_hierarchy), "DEBUG")
            child_sites = sorted(child_sites, key=lambda x: x["nameHierarchy"].split("/"),
                                 reverse=True)

            delete_responses = []
            for child in child_sites:
                child_site_id = child.get("id")
                child_site_name_hierarchy = child.get("nameHierarchy")
                self.log("Processing child site: '{0}' with ID: '{1}'".
                         format(child_site_name_hierarchy, child_site_id), "DEBUG")
                if child_site_id:
                    self.log("Deleting {0}: {1} with ID: {2}".format(
                        delete_type, child_site_name_hierarchy, child_site_id), "INFO")

                    delete_response = self.dnac._exec(
                        family="site_design",
                        function="deletes_an_area",
                        op_modifies=True,
                        params={'id': child_site_id},
                    )
                    self.log("Delete area site API response: {0}".format(delete_response), "DEBUG")
                    self.log("Successfully deleted area site: '{0}'. API response: {1}".format(
                        site_name_hierarchy, delete_response), "DEBUG")
                    delete_responses.append(delete_response)
            return delete_responses

        except Exception as e:
            self.msg = "Exception occurred while deleting area site" +\
                "'{0}' with site_id '{1}' due to: {2}".format(site_name_hierarchy, site_id, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def get_diff_deleted(self, config):
        """
        Call Cisco Catalyst Center API to delete sites with provided inputs.
        Parameters:
          - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
          - config (dict): Dictionary containing information for site deletion.
        Returns:
          - self: The result dictionary includes the following keys:
              - 'changed' (bool): Indicates whether changes were made
                 during the deletion process.
              - 'response' (dict): Contains details about the execution
                 and the deleted site ID.
              - 'msg' (str): A message indicating the status of the deletion operation.
        Description:
            This method initiates the deletion of a site by calling the 'delete_site' function in the 'sites' family
            of the Cisco Catalyst Center API. It uses the site ID obtained from the 'have' attribute.
        """

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:
            site_exists = self.have.get("site_exists")
            site_name_hierarchy = self.want.get("site_name_hierarchy")
            site_id = self.have.get("site_id")
            if not site_exists:
                if site_name_hierarchy not in self.deleted_site_list:
                    self.site_absent_list.append(site_name_hierarchy)
                self.log(
                    "Failed to delete site '{0}'. Reason: The site was not found in the Cisco Catalyst Center.".format(site_name_hierarchy),
                    "DEBUG"
                )
                return self
            api_response, response = self.get_device_ids_from_site(site_name_hierarchy, site_id)
            self.log(
                "Received API response from 'get_membership': {0}".format(str(api_response)), "DEBUG")

            site_response = api_response.get("site", {}).get("response", [])
            self.log(
                "Site '{0}' response along with its child sites: {1}".format(site_name_hierarchy, str(site_response)), "DEBUG")

            if not site_response:
                self.delete_single_site(site_id, site_name_hierarchy)
                return self

            sorted_site_resp = sorted(
                site_response, key=lambda x: x.get("groupHierarchy"), reverse=True)

            for item in sorted_site_resp:
                self.delete_single_site(item['id'], item['groupNameHierarchy'])

            self.delete_single_site(site_id, site_name_hierarchy)
            self.log(
                "The site '{0}' and its child sites have been deleted successfully".format(site_name_hierarchy), "INFO")

        elif self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
            final_deletion_list = []
            for each_type in ("floor", "building", "area"):
                if self.handle_config[each_type]:
                    self.log("Starting bulk site creation for type: {}".format(each_type), "DEBUG")
                    self.handle_config[each_type] = sorted(
                        self.handle_config[each_type], key=lambda x: x["site_name_hierarchy"].split("/"), reverse=True)

                    for config in self.handle_config[each_type]:
                        site_exists = config.get("site_exists")
                        if not site_exists:
                            self.log("Unable to delete site {0} as it's not found in Cisco Catalyst Center".
                                     format(config.get("site_name_hierarchy")), "INFO")
                            self.site_absent_list.append(str(each_type) + ": " + str(config.get("site_name_hierarchy")))
                        else:
                            final_deletion_list.append(config)
            self.log("Deletion list re-arranged order: {0}.".format(final_deletion_list), "INFO")

            if len(final_deletion_list) > 0:
                for config in final_deletion_list:
                    site_name_hierarchy = config.get("site_name_hierarchy")
                    site_params = config.get("site_params")
                    site_params["site_id"] = config.get("site_id")
                    site_type = site_params.get("type")
                    site_id = site_params["site_id"]
                    self.log("Site ID from 'have' for retrieval: {0}".format(site_id), "DEBUG")
                    self.log("Site TYPE from 'have' for retrieval: {0}".format(site_type), "DEBUG")
                    self.log("Site PARAMS from 'have' for retrieval: {0}".format(site_params), "DEBUG")
                    self.log("Site NAME from 'want' for retrieval: {0}".format(site_name_hierarchy), "DEBUG")

                    self.log("Initiating deletion for site '{0}' with site ID: {1} of type: {2}".format(
                        site_name_hierarchy, site_id, site_type), "DEBUG")

                    response = None
                    if site_type == "floor":
                        response = self.delete_floor(site_name_hierarchy, site_id)
                    elif site_type == "building":
                        response = self.delete_building(site_name_hierarchy, site_id)
                    elif site_type == "area":
                        response = self.delete_area(site_name_hierarchy, site_id)
                        self.log("Response for deleting area: {0}".format(str(response)), "DEBUG")

                    self.log("Checking task details for '{0}' deletion.".format(
                        site_type), "DEBUG")
                    if isinstance(response, str):
                        if response:
                            task_id = response
                            self.log("Received Task ID '{0}' for {1}.".format(
                                response, site_type), "INFO")
                            self.process_site_task_details(
                                task_id, site_type, site_name_hierarchy
                            )
                    elif isinstance(response, dict):
                        task_id = response.get("response", {}).get("taskId")
                        if task_id:
                            self.log("Received Task ID '{0}' for {1}.".format(
                                task_id, site_type), "INFO")
                            self.process_site_task_details(
                                task_id, site_type, site_name_hierarchy
                            )
                    elif isinstance(response, list):
                        self.log("Received Task list '{0}' for {1}.".format(
                            str(response), site_type), "INFO")
                        for each_response in response:
                            task_id = each_response.get("response", {}).get("taskId")
                            if task_id:
                                self.process_site_task_details(
                                    task_id, site_type, site_name_hierarchy
                                )

        return self

    def process_site_task_details(self, task_id, site_type, site_name_hierarchy):
        """
        Processes the task details based on the given task ID and updates the deleted site list.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            task_id (str): A string containing task ID to get status and details of task.
            site_type (str): A string contain site type floor, area or building
            site_name_hierarchy (str): A string contain complete path of the site

        Returns:
            self (obj): contains status message of task

        """
        if task_id:
            if site_type == "area":
                task_name = "deletes_an_area"
                progress_msg = "Group is deleted successfully"
            elif site_type == "building":
                task_name = "deletes_building"
                progress_msg = "Group is deleted successfully"
            else:
                task_name = "deletes_an_floor"
                progress_msg = "NCMP00150: Service domain is deleted successfully"

            self.log("Processing task for {0}: {1}".format(site_type,
                                                           site_name_hierarchy), "DEBUG")
            success_message = "{0} '{1}' deleted successfully.".format(site_type.title(),
                                                                       site_name_hierarchy)
            self.get_task_status_from_task_by_id(
                task_id, task_name, None, success_message, progress_msg)

            if self.status == "success":
                self.log("Adding to deleted site list: {0}: {1}".format(
                    site_type, site_name_hierarchy), "DEBUG")
                self.deleted_site_list.append(str(site_type) + ": " + str(site_name_hierarchy))

        return self

    def verify_diff_merged(self, config):
        """
        Verify the merged status (Creation/Updation) of site configuration in Cisco Catalyst Center.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.
        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the merged status of a configuration in Cisco Catalyst Center by retrieving the current state
            (have) and desired state (want) of the configuration, logs the states, and validates whether the specified
            site exists in the Catalyst Center configuration.
        """
        try:
            if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
                self.get_have(config)
                config_count = len(config)
                site_exist_list = [
                    each_site.get("site_name_hierarchy")
                    for each_site in self.handle_config.get("have", [])
                    if each_site.get("site_exists")
                ]
                self.log("COUNTS: {0}, {1}".format(config_count, str(site_exist_list)), "INFO")
                if len(site_exist_list) == config_count and len(self.update_not_needed_sites) < 1:
                    self.msg = "The requested site '{0}' is present in the Cisco Catalyst Center and its creation has been verified.".format(site_exist_list)
                    self.log(self.msg, "INFO")
                    self.set_operation_result("success", True, self.msg, "INFO", str(site_exist_list))
                elif len(self.update_not_needed_sites) > 0:
                    self.update_site_messages().check_return_status()
                else:
                    msg = """Mismatch between the playbook input for site '{0}' and the Cisco Catalyst Center indicates that
                        the deletion was not executed successfully.""".format(site_exist_list)
                    self.log(msg, "INFO")
                    self.set_operation_result("success", False, self.msg, "INFO", site_exist_list)

                return self

        except Exception as e:
            self.log("An unexpected error occurred: {0}".format(e), "ERROR")
            return self

        self.get_have(config)
        site_exist = self.have.get("site_exists")
        site_name_hierarchy = self.want.get("site_name_hierarchy")

        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        if site_exist:
            self.status = "success"
            self.msg = "The requested site '{0}' is present in the Cisco Catalyst Center and its creation has been verified.".format(site_name_hierarchy)
            self.log(self.msg, "INFO")

        require_update = self.site_requires_update()

        if not require_update:
            self.log("The update for site '{0}' has been successfully verified.".format(site_name_hierarchy), "INFO")
            self.status = "success"
            return self

        self.log("""The playbook input for site '{0}' does not align with the Cisco Catalyst Center, indicating that the merge task
                may not have executed successfully.""".format(site_name_hierarchy), "INFO")

        return self

    def verify_diff_deleted(self, config):
        """
        Verify the deletion status of site configuration in Cisco Catalyst Center.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.
        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the deletion status of a configuration in Cisco Catalyst Center.
            It validates whether the specified site exists in the Catalyst Center configuration.
        """
        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
            self.get_have(config)
            config_count = len(config)
            site_not_exist_list = [
                each_site.get("site_name_hierarchy")
                for each_site in self.handle_config.get("have", [])
                if not each_site.get("site_exists")
            ]

            if len(site_not_exist_list) == config_count:
                msg = """The requested site(s) '{0}' has already been deleted from the Cisco Catalyst Center and this has been
                    successfully verified.""".format(site_not_exist_list)
                self.log(msg, "INFO")
                self.set_operation_result("success", True, msg, "INFO", str(site_not_exist_list))
            else:
                msg = """Mismatch between the playbook input for site '{0}' and the Cisco Catalyst Center indicates that
                    the deletion was not executed successfully.""".format(site_not_exist_list)
                self.log(msg, "INFO")
                self.set_operation_result("success", False, msg, "INFO", site_not_exist_list)

            return self
        else:
            self.get_have(config)
            self.log("Current State (have): {0}".format(str(self.have)), "INFO")
            self.log("Desired State (want): {0}".format(str(self.want)), "INFO")
            site_exist = self.have.get("site_exists")

            if not site_exist:
                self.status = "success"
                msg = """The requested site '{0}' has already been deleted from the Cisco Catalyst Center and this has been
                    successfully verified.""".format(self.want.get("site_name_hierarchy"))
                self.log(msg, "INFO")
                return self

            self.log("""Mismatch between the playbook input for site '{0}' and the Cisco Catalyst Center indicates that
                    the deletion was not executed successfully.""".format(self.want.get("site_name_hierarchy")), "INFO")
            return self

    def update_site_messages(self):
        """
        Update site messages based on the status of created, updated, and deleted sites.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class representing the status of the operation, including whether it was
                successful or failed, any error messages encountered during operation.
        Description:
            This method updates the messages related to site creation, updating, and deletion in the Cisco Catalyst Center.
            It evaluates the status of created sites, updated sites, and sites that are no longer needed for update to
            determine the appropriate message to be set. The messages are then stored in the 'msg' attribute of the object.
        """
        if self.created_site_list and self.updated_site_list:
            self.result['changed'] = True
            if self.update_not_needed_sites:
                msg = """Site(s) '{0}' created successfully as well as Site(s) '{1}' updated successully and the some site(s)
                        '{2}' needs no update in Cisco Catalyst Center"""
                self.msg = msg.format(str(self.created_site_list), str(self.updated_site_list), str(self.update_not_needed_sites))
            else:
                self.msg = """Site(s) '{0}' created successfully in Cisco Catalyst Center as well as Site(s) '{1}' updated successully in
                        Cisco Catalyst Center""".format(str(self.created_site_list), str(self.updated_site_list))
            self.result['response'] = self.msg
        elif self.created_site_list:
            self.result['changed'] = True
            if self.update_not_needed_sites:
                self.msg = """Site(s) '{0}' created successfully and some site(s) '{1}' not needs any update in Cisco Catalyst
                                Center.""".format(str(self.created_site_list), str(self.update_not_needed_sites))
            else:
                self.msg = "Site(s) '{0}' created successfully in Cisco Catalyst Center.".format(
                    str(self.created_site_list))
            self.result['response'] = self.created_site_list
        elif self.updated_site_list:
            self.result['changed'] = True
            if self.update_not_needed_sites:
                self.msg = """Site(s) '{0}' updated successfully and some site(s) '{1}' not needs any update in Cisco Catalyst
                                Center.""".format(str(self.updated_site_list), str(self.update_not_needed_sites))
            else:
                self.msg = "Site(s) '{0}' updated successfully in Cisco Catalyst Center.".format(
                    str(self.updated_site_list))
            self.result['response'] = self.updated_site_list
        elif self.update_not_needed_sites:
            self.result['changed'] = False
            self.msg = "Site(s) '{0}' not needs any update in Cisco Catalyst Center.".format(
                str(self.update_not_needed_sites))
            self.result['response'] = self.update_not_needed_sites
        elif self.deleted_site_list and self.site_absent_list:
            self.result['changed'] = True
            self.msg = """Given site(s) '{0}' deleted successfully from Cisco Catalyst Center and unable to deleted some site(s) '{1}' as they
                    are not found in Cisco Catalyst Center.""".format(str(self.deleted_site_list), str(self.site_absent_list))
            self.result['response'] = self.msg
        elif self.deleted_site_list:
            self.result['changed'] = True
            self.msg = "Given site(s) '{0}' deleted successfully from Cisco Catalyst Center".format(
                str(self.deleted_site_list))
            self.result['response'] = self.deleted_site_list
        else:
            self.result['changed'] = False
            self.msg = "Requested item is not found. Nothing to delete."
            self.result['response'] = self.msg

        self.status = "success"
        self.result['msg'] = self.msg

        return self

    def upload_floor_image(self, config):
        """
        Upload a floor image to the Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing configuration details, including the file path for the floor image.

        Returns:
            tuple: A tuple containing:
                - map_details (bool): Indicates if the upload was successful.
                - map_status (dict or None): Contains the upload status if successful; otherwise None.
                - success_message (str or None): A success message if upload was successful; otherwise None.

        Description:
            This method uploads a specified floor image by validating the file path, ensuring the file exists,
            determining the content type, reading the file content, and invoking the appropriate API to upload the image.
            It logs the success or failure of the upload operation.
        """
        map_details = None
        map_status = None
        response = None
        success_message = None
        content_type = None

        try:
            self.log("Starting upload_floor_image function", "DEBUG")
            file_path = config.get('upload_floor_image_path')
            self.log("File path extracted from config: {}".format(file_path), "DEBUG")

            if not isinstance(file_path, str) or not file_path:
                msg = "Invalid file path format. It must be a non-empty string."
                self.set_operation_result("failed", False, msg, "ERROR").check_return_status()
            if not os.path.exists(file_path):
                msg = "File path does not exist: {0}".format(file_path)
                self.set_operation_result("failed", False, msg, "ERROR").check_return_status()

            self.log("File path exists: {0}".format(file_path), "DEBUG")

            valid_extensions = ['.png', '.jpg', '.jpeg', '.pdf']
            if not any(file_path.lower().endswith(ext) for ext in valid_extensions):
                msg = "Unsupported file format. Supported formats: {0}".format(", ".join(valid_extensions))
                self.set_operation_result("failed", False, msg, "ERROR").check_return_status()

            if file_path.lower().endswith('.png'):
                content_type = 'image/png'
            elif file_path.lower().endswith('.jpg') or file_path.lower().endswith('.jpeg'):
                content_type = 'image/jpeg'
            elif file_path.lower().endswith('.pdf'):
                content_type = 'application/pdf'

            self.log("Determined content type: {}".format(content_type), "DEBUG")

            try:
                with open(file_path, "rb") as image_file:
                    file_content = image_file.read()
            except IOError as e:
                msg = "Failed to read file at {0}: {1}".format(file_path, str(e))
                self.set_operation_result("failed", False, msg, "ERROR").check_return_status()

            multipart_fields = {
                'image': (os.path.basename(file_path), file_content, content_type)
            }

            site_hierarchy = config.get(self.keymap["parent_name_hierarchy"], "parent_name_hierarchy") + "/" + str(config.get('name'))
            if config.get(self.keymap["parent_name"]):
                site_hierarchy = str(config.get(self.keymap["parent_name"])) + "/" + str(config.get('name'))

            site_exists, current_site = self.site_exists(site_hierarchy)
            site_id = current_site.get("id")
            if not site_id:
                msg = "No valid Site found for the site hierarchy {0}".format(site_hierarchy)
                self.set_operation_result("failed", False, msg, "ERROR").check_return_status()

            try:
                response = self.dnac._exec(
                    family="site_design",
                    function="uploads_floor_image",
                    op_modifies=True,
                    params={
                        "id": site_id,
                        "multipart_fields": multipart_fields,
                        "multipart_monitor_callback": None
                    }
                )
                if response is None:
                    self.log("No response received from the API.", "ERROR")
                else:
                    self.log("API response: {}".format(response), "DEBUG")
            except Exception as e:
                self.msg = "An exception occurred during uploads_floor_image API execution: {0}".format(str(e))
                self.log(self.msg, "ERROR")
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        except Exception as e:
            self.msg = "An exception occurred: {}".format(str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return None, None, None

        if not response:
            self.msg = "Failed to upload floor image: No response from the API."
            self.set_operation_result("failed", False, self.msg, "ERROR")
        if isinstance(response, dict) and "id" in response:
            self.log("Received valid API response: {}".format(response), "DEBUG")
            map_details = True
            map_status = response
            success_message = "Floor image uploaded successfully."
            self.log(success_message, "INFO")
        else:
            self.log("Invalid response received from API. Response: {}".format(response), "ERROR")

        return map_details, map_status, success_message


def main():
    """ main entry point for module execution
    """
    element_spec = {'dnac_host': {'required': True, 'type': 'str'},
                    'dnac_port': {'type': 'str', 'default': '443'},
                    'dnac_username': {'type': 'str', 'default': 'admin', 'aliases': ['user']},
                    'dnac_password': {'type': 'str', 'no_log': True},
                    'dnac_verify': {'type': 'bool', 'default': 'True'},
                    'dnac_version': {'type': 'str', 'default': '2.2.3.3'},
                    'dnac_debug': {'type': 'bool', 'default': False},
                    'dnac_log_level': {'type': 'str', 'default': 'WARNING'},
                    "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
                    "dnac_log_append": {"type": 'bool', "default": True},
                    'dnac_log': {'type': 'bool', 'default': False},
                    'validate_response_schema': {'type': 'bool', 'default': True},
                    'config_verify': {'type': 'bool', "default": False},
                    'dnac_api_task_timeout': {'type': 'int', "default": 1200},
                    'dnac_task_poll_interval': {'type': 'int', "default": 2},
                    'config': {'required': True, 'type': 'list', 'elements': 'dict'},
                    'state': {'default': 'merged', 'choices': ['merged', 'deleted']}
                    }

    module = AnsibleModule(argument_spec=element_spec,
                           supports_check_mode=False)

    ccc_site = Site(module)
    state = ccc_site.params.get("state")

    if ccc_site.compare_dnac_versions(ccc_site.get_ccc_version(), "2.3.5.3") < 0:
        ccc_site.msg = (
            "The specified version '{0}' does not support the site workflow feature. Supported versions start from '2.3.5.3' onwards. "
            "Version '2.3.5.3' introduces APIs for creating, updating, and deleting sites. "
            "Version '2.3.7.6' expands support to include APIs for bulk site creating, updating, and deleting sites.".format(
                ccc_site.get_ccc_version())
        )

        ccc_site.status = "failed"
        ccc_site.check_return_status()

    if state not in ccc_site.supported_states:
        ccc_site.status = "invalid"
        ccc_site.msg = "State {0} is invalid".format(state)
        ccc_site.check_return_status()

    ccc_site.validate_input().check_return_status()
    config_verify = ccc_site.params.get("config_verify")
    ccc_site.validate_site_input_data(ccc_site.validated_config, state).check_return_status()

    if ccc_site.compare_dnac_versions(ccc_site.get_ccc_version(), "2.3.7.6") >= 0:
        ccc_site.reset_values()
        ccc_site.get_want(ccc_site.validated_config).check_return_status()
        ccc_site.get_have(ccc_site.validated_config).check_return_status()

        ccc_site.get_diff_state_apply[state](ccc_site.validated_config).check_return_status()

        if config_verify:
            ccc_site.update_site_messages().check_return_status()

    else:
        for config in ccc_site.validated_config:
            ccc_site.reset_values()

            ccc_site.get_want(config).check_return_status()
            ccc_site.get_have(config).check_return_status()

            ccc_site.get_diff_state_apply[state](config).check_return_status()
        ccc_site.update_site_messages().check_return_status()

    module.exit_json(**ccc_site.result)


if __name__ == '__main__':
    main()
