#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to manage Access Point to the planned locations
in Cisco Catalyst Center, and assign the access point to floor plans."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ["A Mohamed Rafeek, Madhan Sankaranarayanan"]

DOCUMENTATION = r"""
---
module: accesspoint_location_workflow_manager
short_description: Resource module for managing Access Point planned positions and real positions in Cisco Catalyst Center
description: >
  This module facilitates the creation, update, assignment and deletion of planned and real Access Point positions
  in Cisco Catalyst Center.
  - Supports creating, assigning and deleting planned and real Access Point positions.
  - Enables assignment of the access point to the planned positions.
version_added: "6.40.0"
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - A Mohamed Rafeek (@mabdulk2)
  - Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: >
      Set to `True` to enable configuration verification on Cisco Catalyst Center after applying the playbook configuration.
      This ensures that the system validates the configuration state after the changes are applied.
    type: bool
    default: false
  state:
    description: >
      Specifies the desired state for the configuration.
      If set to `merged`, the module will create or update the configuration by adding new settings or modifying existing ones.
      If set to `deleted`, the module will remove the specified settings.
    type: str
    choices: ["merged", "deleted"]
    default: merged
  config:
    description: >
      A list containing the details required for creating, updating or removing
      the Access Point planned and real positions.
    type: list
    elements: dict
    required: true
    suboptions:
      floor_site_hierarchy:
        description: >
          Complete floor site hierarchy for the access point position.
        type: str
        required: true
      access_points:
        description: >
          List of access points to be configured at the specified position.
        type: list
        elements: dict
        required: true
        suboptions:
          accesspoint_name:
            description: >
              Name of the access point to be assigned to the position.
            type: str
            required: true
          action:
            description: >
              The action to be performed on the access point.
              Determines how the access point will be managed within the specified position.
              This field is only required when assigning or deleting real access point to/from an existing planned position.
              It is not required when creating, updating, or deleting a planned access point position itself.
            type: str
            required: false
            choices:
              - C(assign_planned_ap)
              - C(manage_real_ap)
          mac_address:
            description: |
              The MAC address used to identify the real access point.
              This field is required when mapping a planned access point to an actual access point.
            type: str
            required: false
          accesspoint_model:
            description: Model of the access point. Model is required when creating planned access point position.
            type: str
            required: false
          position:
            description: |
              The X,Y and Z coordinates representing the access point's position on the floor plan.
            type: dict
            required: false
            suboptions:
              x_position:
                description: >
                  The X coordinate of the access point's position. allows from 0 to 100
                type: int
                required: true
              y_position:
                description: >
                  The Y coordinate of the access point's position. allows from 0 to 88
                type: int
                required: true
              z_position:
                description: >
                  The Z coordinate of the access point's position. allows from 3.0 to 10.0
                type: float
                required: true
          radios:
            description: |
              List of radio details for the access point.
            type: list
            elements: dict
            required: false
            suboptions:
              bands:
                description: |
                  Radio band supported by the access point.
                type: list
                elements: str
                required: true
                choices:
                  - C(2.4)
                  - C(5)
                  - C(6)
              channel:
                description: |
                  The channel number for the radio interface.
                  in case of dual bands, channel should be the maximum band channel.
                  - For C(2.4GHz): valid values are 1, 6 and 11.
                  - For C(5GHz): valid values are
                    36, 40, 44, 48, 52, 56, 60, 64,
                    100, 104, 108, 112, 116, 120, 124,
                    128, 132, 136, 140, 144, 149, 153,
                    157, 161, 165, 169, 173.
                  - For C(6GHz): valid values are
                    1, 5, 9, 13, 17, 21, 25, 29, 33, 37,
                    41, 45, 49, 53, 57, 61, 65, 69, 73,
                    77, 81, 85, 89, 93, 97, 101, 105,
                    109, 113, 117, 121, 125, 129, 133,
                    137, 141, 145, 149, 153, 157, 161,
                    165, 169, 173, 177, 181, 185, 189,
                    193, 197, 201, 205, 209, 213, 217,
                    221, 225, 229, 233.
                type: int
                required: true
              tx_power:
                description: |
                  The transmit power level of the access point.
                type: int
                required: true
              antenna:
                description: |
                  Antenna configuration details of the access point.
                type: dict
                required: true
                suboptions:
                  antenna_name:
                    description: |
                      Model name of the antenna.
                    type: str
                    required: true
                  azimuth:
                    description: |
                      The azimuth angle of the antenna, ranging from 1 to 360.
                    type: int
                    required: true
                  elevation:
                    description: |
                      The elevation angle of the antenna, ranging from -90 to 90.
                    type: int
                    required: true
requirements:
  - dnacentersdk >= 2.8.6
  - python >= 3.9
seealso:
  - name: Cisco Catalyst Center API Documentation
    description: Complete API reference for device management.
    link: https://developer.cisco.com/docs/dna-center/
notes:
    # Version Compatibility
  - Minimum Catalyst Center version 3.1.3.0 required for accesspoint location workflow features.

  - This module utilizes the following SDK methods
    site_design.SiteDesign.get_planned_access_points_positions
    site_design.SiteDesign.add_planned_access_points_positions
    site_design.SiteDesign.edit_planned_access_points_positions
    site_design.SiteDesign.delete_planned_access_points_position
    site_design.SiteDesign.assign_planned_access_points_to_operations_ones
    site_design.SiteDesign.edit_the_access_points_positions
    site_design.SiteDesign.get_access_points_positions
    site_design.SiteDesign.get_sites

  - The following API paths are used
    GET /dna/intent/api/v2/floors/${floorId}/plannedAccessPointPositions
    GET /dna/intent/api/v1/sites
    GET /dna/intent/api/v2/floors/${floorId}/accessPointPositions
    POST /dna/intent/api/v2/floors/${floorId}/plannedAccessPointPositions/${id}
    POST /dna/intent/api/v2/floors/${floorId}/plannedAccessPointPositions/bulk
    POST /dna/intent/api/v2/floors/${floorId}/accessPointPositions/bulkChange
    POST /dna/intent/api/v2/floors/${floorId}/plannedAccessPointPositions/bulkChange
    POST /dna/intent/api/v2/floors/${floorId}/plannedAccessPointPositions/assignAccessPointPositions

"""

EXAMPLES = r"""
---
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Create planned access point positions for the access points
      cisco.dnac.accesspoint_location_workflow_manager:
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
        config:  # Minimum 1; Maximum 100 config hierarchy
          - floor_site_hierarchy: "Global/USA/SAN JOSE/SJ_BLD23/FLOOR1"
            access_points:
              - accesspoint_name: AP687D.B402.1614-AP-location_Test6
                accesspoint_model: AP9120E
                position:
                  x_position: 30  # x-axis: from 0 to 100
                  y_position: 30  # y-axis: from 0 to 88
                  z_position: 8  # height: from 3.0 to 10
                radios:  # Minimum Items: 1; Maximum Items: 4
                  - bands: ["2.4"]  # can be 2.4, 5 and 6
                    channel: 11
                    tx_power: 5  # Decibel milliwatts (dBm)
                    antenna:
                      antenna_name: AIR-ANT2524DB-R-2.4GHz
                      azimuth: 30  # support upto 360
                      elevation: 30  # support -90 upto 90
                  - bands: ["5"]  # can be 2.4, 5 and 6
                    channel: 44
                    tx_power: 6  # Decibel milliwatts (dBm)
                    antenna:
                      antenna_name: AIR-ANT2524DB-R-5GHz
                      azimuth: 30  # support upto 360
                      elevation: 30  # support -90 upto 90
                  - bands: ["2.4", "5"]  # can be 2.4, 5 and 6
                    channel: 48
                    tx_power: 6  # Decibel milliwatts (dBm)
                    antenna:
                      antenna_name: AIR-ANT2524DB-R
                      azimuth: 30  # support upto 360
                      elevation: 30  # support -90 upto 90

    # Assign planned access point position and assign the real access points
    - name: Assign planned access point position and assign the real access points
      cisco.dnac.accesspoint_location_workflow_manager:
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
        config:  # Minimum 1; Maximum 100 config hierarchy
          - floor_site_hierarchy: "Global/USA/SAN JOSE/SJ_BLD23/FLOOR1"
            access_points:
              - accesspoint_name: AP687D.B402.1614-AP-location_Test6
                action: assign_planned_ap  # Optional assign_planned_ap, manage_real_ap
                mac_address: a4:88:73:d4:dd:80  # Required while assigning planned access point

    # Update planned access point position to the access points
    - name: Update planned access point position to the access points
      cisco.dnac.accesspoint_location_workflow_manager:
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
        config:  # Minimum 1; Maximum 100 config hierarchy
          - floor_site_hierarchy: "Global/USA/California/SAN JOSE/BLD24/Floor3"
            access_points:
              - accesspoint_name: IAC-TB4-SJ-AP1
                accesspoint_model: AP9120E
                position:
                  x_position: 30  # x-axis: from 0 to 100
                  y_position: 30  # y-axis: from 0 to 88
                  z_position: 8  # height: from 3.0 to 10
                radios:  # Minimum Items: 1; Maximum Items: 4
                  - bands: ["2.4"]  # can be 2.4, 5 and 6
                    channel: 11
                    tx_power: 5  # Decibel milliwatts (dBm)
                    antenna:
                      antenna_name: AIR-ANT2524DB-R-2.4GHz
                      azimuth: 20  # support upto 360
                      elevation: 20  # support -90 upto 90
                  - bands: ["5"]  # can be 2.4, 5 and 6
                    channel: 44
                    tx_power: 6  # Decibel milliwatts (dBm)
                    antenna:
                      antenna_name: AIR-ANT2524DB-R-5GHz
                      azimuth: 30  # support upto 360
                      elevation: 30  # support -90 upto 90
                  - bands: ["2.4", "5"]  # can be 2.4, 5 and 6
                    channel: 48
                    tx_power: 6  # Decibel milliwatts (dBm)
                    antenna:
                      antenna_name: AIR-ANT2524DB-R
                      azimuth: 30  # support upto 360
                      elevation: 30  # support -90 upto 90

    # Delete Planned Access Point from maps
    - name: Delete Planned Access Point from maps
      cisco.dnac.accesspoint_location_workflow_manager:
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
        config:  # Minimum 1; Maximum 100 config hierarchy
          - floor_site_hierarchy: "Global/USA/SAN JOSE/SJ_BLD23/FLOOR1"
            access_points:
              - accesspoint_name: AP687D.B402.1614-AP-location_Test6

    # Create the real AP position with real access point.
    - name: Create the real AP position with real access point
      cisco.dnac.accesspoint_location_workflow_manager:
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
        config:  # Minimum 1; Maximum 100 config hierarchy
          - floor_site_hierarchy: "Global/USA/SAN JOSE/SJ_BLD23/FLOOR1"
            access_points:
              - accesspoint_name: AP687D.B402.1614-AP-location_Test6
                mac_address: a4:88:73:d4:dd:80  # Required for real access point creation
                accesspoint_model: AP9120E
                position:
                  x_position: 20  # x-axis: from 0 to 100
                  y_position: 30  # y-axis: from 0 to 88
                  z_position: 8  # height: from 3.0 to 10
                radios:  # Minimum Items: 1; Maximum Items: 4
                  - bands: ["2.4"]  # can be 2.4, 5 and 6
                    channel: 11
                    tx_power: 5  # Decibel milliwatts (dBm)
                    antenna:
                      antenna_name: AIR-ANT2524DB-R-2.4GHz
                      azimuth: 20  # support upto 360
                      elevation: 30  # support -90 upto 90
                  - bands: ["5"]  # can be 2.4, 5 and 6
                    channel: 44
                    tx_power: 6  # Decibel milliwatts (dBm)
                    antenna:
                      antenna_name: AIR-ANT2524DB-R-5GHz
                      azimuth: 20  # support upto 360
                      elevation: 30  # support -90 upto 90
                  - bands: ["2.4", "5"]  # can be 2.4, 5 and 6
                    channel: 48
                    tx_power: 6  # Decibel milliwatts (dBm)
                    antenna:
                      antenna_name: AIR-ANT2524DB-R
                      azimuth: 30  # support upto 360
                      elevation: 30  # support -90 upto 90

    # Update the real AP position with real access point.
    - name: Update the real AP position with real access point.
      cisco.dnac.accesspoint_location_workflow_manager:
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
        config:  # Minimum 1; Maximum 100 config hierarchy
          - floor_site_hierarchy: "Global/USA/SAN JOSE/SJ_BLD23/FLOOR1"
            access_points:
              - accesspoint_name: AP687D.B402.1614-AP-location_Test6
                mac_address: a4:88:73:d4:dd:80  # Required for real access point creation
                accesspoint_model: AP9120E
                position:
                  x_position: 20  # x-axis: from 0 to 100
                  y_position: 30  # y-axis: from 0 to 88
                  z_position: 8  # height: from 3.0 to 10
                radios:  # Minimum Items: 1; Maximum Items: 4
                  - bands: ["2.4"]  # can be 2.4, 5 and 6
                    antenna:
                      antenna_name: AIR-ANT2524DB-R-2.4GHz
                      azimuth: 20  # support upto 360
                      elevation: 30  # support -90 upto 90
                  - bands: ["5"]  # can be 2.4, 5 and 6
                    antenna:
                      antenna_name: AIR-ANT2524DB-R-5GHz
                      azimuth: 20  # support upto 360
                      elevation: 30  # support -90 upto 90

    # Delete assigned access point from the real floor position
    - name: Delete assigned access point from the real floor position
      cisco.dnac.accesspoint_location_workflow_manager:
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
        config:  # Minimum 1; Maximum 100 config hierarchy
          - floor_site_hierarchy: "Global/USA/California/SAN JOSE/BLD24/Floor3"
            access_points:
              - accesspoint_name: IAC-TB4-SJ-AP1
                action: manage_real_ap  # Delete the access point from the real position
"""

RETURN = r"""
# Case 1: Create planned access point position for the access points
response_create:
  description: >
    A dictionary or list containing the response returned by the Cisco Catalyst Center Python SDK
    when a access point planned position is successfully created. The response confirms the successful
    creation of the planned position and provides details about the status, including its access point name
    and status.
  returned: always
  type: dict
  sample: >
    {
        "msg": "Planned/Real Access Point position created successfully for 'Global/USA/SAN JOSE/SJ_BLD23/FLOOR1'.",
        "response": [
            [
                "AP687D.B402.1614-AP-location_Test6"
            ]
        ],
        "status": "success"
    }

# Case 2: Assign planned access point position
response_assign_planned_position:
  description: >
    A dictionary or list containing the response returned by the Cisco Catalyst Center Python SDK
    when a access point planned position is successfully assigned. The response confirms
    the successful assignment of the planned position and provides details about the status,
    including its access point name and status.
  returned: always
  type: dict
  sample: >
    {
        "msg": "Planned Access Point position assigned successfully for '[['AP687D.B402.1614-AP-location_Test6']]'.
                Following real Access Point(s) assigned to planned position(s): '['AP687D.B402.1614-AP-location_Test6']'.",
        "response": [
            [
                "AP687D.B402.1614-AP-location_Test6"
            ]
        ],
        "status": "success"
    }

# Case 3: Idempotent Create planned access point position for the accesspoint
response_create_idempotent:
  description: >
    A dictionary or list containing the response returned by the Cisco Catalyst Center Python SDK.
    This response is provided when attempting to create planned access point positions in an idempotent manner.
    If the positions are already created, the response indicates that no changes were required.
  returned: always
  type: dict
  sample: >
    {
        "msg": "No Changes required, Planned/Real Access Point position(s) already exist.",
        "response": [],
        "status": "success"
    }

# Case 4: Update planned access point position for the access points
response_update_position:
  description: >
    A dictionary or list containing the response returned by the Cisco Catalyst Center Python SDK
    when a planned access point position is successfully updated. The response confirms the
    update and provides details about the updated position.
  returned: always
  type: dict
  sample: >
    {
        "msg": "Planned/Real Access Point position updated successfully for 'Global/USA/SAN JOSE/SJ_BLD23/FLOOR1'.",
        "response": [
            [
                "AP687D.B402.1614-AP-location_Test6"
            ]
        ],
        "status": "success"
    }

# Case 5: Successfully deleted the planned access point position
response_delete_planned_position:
  description: >
    A dictionary or list containing the response returned by the Cisco Catalyst Center Python SDK
    when a planned access point position is successfully deleted. The response confirms the
    deletion and provides details about the position and access point(s) affected.
  returned: always
  type: dict
  sample: >
    {
        "msg": "Planned/Real Access Point position(s) deleted and verified successfully for '['AP687D.B402.1614-AP-location_Test6']'.",
        "response": [
            "AP687D.B402.1614-AP-location_Test6"
        ],
        "status": "success"
    }

# Case 6: Idempotent delete the planned access point position
response_unassign_idempotent:
  description: >
    A dictionary or list containing the response returned by the Cisco Catalyst Center Python SDK
    when a planned access point position is successfully unassigned. The response confirms the
    unassignment and provides details about the position and the access point(s) affected.
  returned: always
  type: dict
  sample: >
    {
        "msg": "No Changes required, planned/real Access Point position(s) already deleted
                and verified successfully for '['AP687D.B402.1614-AP-location_Test6']'.",
        "response": [],
        "status": "success"
    }

# Case 7: Assign the access point to existing access points planned position.
response_create_assign_idempotent:
  description: >
    A dictionary or list containing the response returned by the Cisco Catalyst Center Python SDK
    when a access point planned position is successfully created and assigned. The response confirms
    the successful creation of the planned position and provides details about the status,
    including its access point name and status.
  returned: always
  type: dict
  sample: >
    {
        "msg": "No Changes required, planned Access Point position(s) already exist.
                Following real Access Point(s) assigned to planned position(s): '['IAC-TB4-SJ-AP1']'.
                Following Access Point position(s): 'None' already exist.",
        "response": [],
        "status": "success"
    }

# Case 8: Update the real AP position with real access point.
response_update_real_position:
  description: >
    A dictionary or list containing the response returned by the Cisco Catalyst Center Python SDK
    when a real access point position is successfully updated. The response confirms
    the successful update of the real position and provides details about the status,
    including its access point name and status.
  returned: always
  type: dict
  sample: >
    {
        "msg": "Planned/Real Access Point position updated successfully for 'Global/USA/SAN JOSE/SJ_BLD23/FLOOR1'.",
        "response": [
            [
                "AP687D.B402.1614-AP-Test6"
            ]
        ],
        "status": "success"
    }

# Case 9: Unassign the access point from existing access points real position.
response_unassign_real_position:
  description: >
    A dictionary or list containing the response returned by the Cisco Catalyst Center Python SDK
    when a access point real position is successfully unassigned. The response confirms
    the successful unassignment of the real position and provides details about the status,
    including its access point name and status.
  returned: always
  type: dict
  sample: >
    {
        "msg": "Real Access Point position(s) deleted and verified successfully for '['IAC-TB4-SJ-AP1']'.",
        "response": [
            "IAC-TB4-SJ-AP1"
        ],
        "status": "success"
    }
"""


from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_str,
)
from ansible_collections.cisco.dnac.plugins.module_utils.validation import (
    validate_list_of_dicts,
)
from ansible.module_utils.basic import AnsibleModule


class AccessPointLocation(DnacBase):
    """Class containing member attributes for access point position workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.location_created, self.location_updated, self.location_deleted = [], [], []
        self.location_not_created, self.location_not_updated, self.location_not_deleted = [], [], []
        self.location_exist, self.location_already_deleted = [], []
        self.location_assigned, self.location_not_assigned, self.location_already_assigned = [], [], []

        self.result_response = {
            "success_responses": self.location_created,
            "unprocessed": self.location_not_created,
            "already_processed": self.location_exist
        }

        self.keymap = {
            "accesspoint_name": "name",
            "mac_address": "macAddress",
            "accesspoint_model": "type",
            "position": "position",
            "radios": "radios",
            "x_position": "x",
            "y_position": "y",
            "z_position": "z",
            "bands": "bands",
            "channel": "channel",
            "tx_power": "txPower",
            "antenna": "antenna",
            "antenna_name": "name",
            "azimuth": "azimuth",
            "elevation": "elevation"
        }

    def validate_input(self):
        """
        Validate access point position configuration against predefined specifications.

        Processes playbook configuration to ensure compliance with expected structure,
        data types, coordinate ranges, and Cisco Catalyst Center requirements for access
        point positioning including site hierarchy, position coordinates, radio bands,
        channels, antenna patterns, and transmission power levels.

        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.

        Returns:
            The method updates these attributes of the instance:
                - msg: A message describing the validation result.
                - self.status: The status of the validation ('success' or 'failed').
                - self.validated_config: If successful, a validated version of the 'config' parameter.

        Description:
            - Validates configuration structure against comprehensive specification
            - Ensures required fields are present and correctly typed
            - Validates coordinate ranges (x: 0-100, y: 0-88, z: 3.0-10.0)
            - Validates radio bands (2.4GHz, 5GHz, 6GHz) and appropriate channels
            - Validates antenna configurations and transmission power levels
            - Sets self.validated_config on successful validation
        """
        self.log(
            "Starting comprehensive playbook configuration validation for access point positioning",
            "INFO"
        )

        config_size = len(self.config) if self.config else 0
        self.log(
            "Processing access point position validation with config size: {0}".format(config_size),
            "DEBUG"
        )

        temp_spec = {
            "floor_site_hierarchy": {"type": "str", "required": True},
            "access_points": {
                "type": "list",
                "elements": "dict",
                "accesspoint_name": {"type": "str", "required": True},
                "action": {"type": "str", "required": False,
                           "choices": ["assign_planned_ap", "manage_real_ap"]},
                "mac_address": {"type": "str"},
                "serial_number": {"type": "str"},
                "accesspoint_model": {"type": "str", "required": False},
                "position": {
                    "type": "dict",
                    "x_position": {"type": "int", "required": False},  # 0-100 range
                    "y_position": {"type": "int", "required": False},  # 0-88 range
                    "z_position": {"type": "int", "required": False},  # 3.0-10.0 range
                },
                "radios": {
                    "type": "list",
                    "elements": "dict",
                    "bands": {"type": "list", "elements": "str", "required": False},  # 2.4, 5, 6
                    "channel": {"type": "int", "required": False},  # Band-specific channels
                    "tx_power": {"type": "int", "required": False},  # Transmission power (dBm)
                    "antenna": {
                        "type": "dict",
                        "antenna_name": {"type": "str", "required": False},  # Model-specific antenna
                        "azimuth": {"type": "int", "required": False},  # 1-360 degrees
                        "elevation": {"type": "int", "required": False},  # -90 to 90 degrees
                    },
                },
            },
        }

        if not self.config:
            msg = "The playbook configuration is empty or missing."
            self.set_operation_result("failed", False, msg, "ERROR")
            return self

        self.log(
            "Executing configuration structure validation against access point positioning specification",
            "DEBUG"
        )
        # Validate configuration against the specification
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            msg = f"The playbook contains invalid parameters: {invalid_params}"
            self.result["response"] = msg
            self.set_operation_result("failed", False, msg, "ERROR")
            return self

        self.validated_config = valid_temp
        msg = f"Successfully validated playbook configuration parameters using 'validate_input': {self.pprint(valid_temp)}"
        self.log(msg, "INFO")

        return self

    def input_data_validation(self, config):
        """
        Perform additional validation for access point position configuration compliance.

        Validates access point configuration against Cisco Catalyst Center UI requirements
        including coordinate ranges, field formats, duplicate detection, and structural
        integrity beyond basic schema validation performed in validate_input().

        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            config (dict): Dictionary containing the Access point planned position details.

        Returns:
            list: List of invalid access point position data with details.

        Description:
            - Validates site hierarchy string format and length constraints
            - Checks access point list size limits (max 100) and duplicate names
            - Validates coordinate ranges: x(0-100), y(0-88), z(3-10)
            - Validates field lengths and formats for MAC addresses and serial numbers
            - Delegates radio configuration validation to validate_radios() method
            - Skips detailed validation for deletion state operations
        """
        self.log(
            "Starting additional input data validation for access point position "
            "configuration compliance",
            "INFO"
        )

        config_keys = list(config.keys()) if isinstance(config, dict) else []
        self.log(
            "Processing additional validation for config with sections: {0}".format(
                config_keys
            ),
            "DEBUG"
        )
        self.log(
            f"Validating input data from Playbook config: {config}", "INFO"
        )
        errormsg = []

        floor_site_hierarchy = config.get("floor_site_hierarchy", "")
        if floor_site_hierarchy:
            param_spec = dict(type="str", length_max=200)
            validate_str(floor_site_hierarchy, param_spec, "floor_site_hierarchy", errormsg)
            self.log(
                "Floor site hierarchy validation passed for: {0}".format(
                    floor_site_hierarchy
                ),
                "DEBUG"
            )
        else:
            errormsg.append("floor_site_hierarchy: Floor Site Hierarchy is missing in playbook.")

        access_points = config.get("access_points", [])
        if not access_points:
            errormsg.append("access_points: Access Points list is missing in playbook.")
            self.log(
                "Validation failed - no access points provided for positioning",
                "ERROR"
            )
            return errormsg
        elif len(access_points) > 100:
            errormsg.append("access_points: Maximum of 100 Access Points are allowed in playbook.")
            self.log(
                "Validation failed - access points list exceeds maximum limit of 100",
                "ERROR"
            )
            return errormsg

        self.log(
            "Processing {0} access points for additional validation".format(
                len(access_points)
            ),
            "DEBUG"
        )
        duplicate_name = self.find_duplicate_value(access_points, "accesspoint_name")
        if duplicate_name:
            errormsg.append(
                f"accesspoint_name: Duplicate Access Point Name(s) '{duplicate_name}' found in playbook."
            )

        for idx, each_access_point in enumerate(access_points):
            self.log(
                "Validating access point {0}/{1}: {2}".format(
                    idx + 1, len(access_points),
                    each_access_point.get("accesspoint_name", "Unknown")
                ),
                "DEBUG"
            )
            accesspoint_name = each_access_point.get("accesspoint_name")
            if accesspoint_name:
                param_spec = dict(type="str", length_max=255)
                validate_str(accesspoint_name, param_spec, "accesspoint_name", errormsg)
            else:
                errormsg.append("accesspoint_name: Access Point Name is missing in playbook.")

            if self.params.get("state") == "deleted":
                self.log(
                    "Skipping detailed field validation for deletion state operation",
                    "DEBUG"
                )
                continue

            mac_address = each_access_point.get("mac_address")
            if mac_address:
                param_spec = dict(type="str", length_max=17)
                validate_str(mac_address, param_spec, "mac_address", errormsg)

            serial_number = each_access_point.get("serial_number")
            if serial_number:
                param_spec = dict(type="str", length_max=200)
                validate_str(serial_number, param_spec, "serial_number", errormsg)

            if each_access_point.get("action") == "assign_planned_ap":
                if not mac_address:
                    errormsg.append("mac_address: MAC Address required for assign planned access point in playbook.")
                continue

            accesspoint_model = each_access_point.get("accesspoint_model")
            if accesspoint_model:
                param_spec = dict(type="str", length_max=50)
                validate_str(accesspoint_model, param_spec, "accesspoint_model", errormsg)
            else:
                errormsg.append("accesspoint_model: Access Point Model is missing in playbook.")

            position = each_access_point.get("position")
            if position and isinstance(position, dict):
                x_position = position.get("x_position")
                if x_position is None:
                    errormsg.append("x_position: X Position is missing in playbook.")
                elif x_position and isinstance(x_position, int) and not (0 < x_position < 100):
                    errormsg.append("x_position: X Position must be between 0 and 100.")

                y_position = position.get("y_position")
                if y_position is None:
                    errormsg.append("y_position: Y Position is missing in playbook.")
                elif y_position and isinstance(y_position, int) and not (0 < y_position < 88):
                    errormsg.append("y_position: Y Position must be between 0 and 88.")

                z_position = position.get("z_position")
                if z_position is None:
                    errormsg.append("z_position: Z Position is missing in playbook.")
                elif z_position and isinstance(z_position, (int, float)) and not (3 < z_position < 10):
                    errormsg.append("z_position: Z Position must be between 3 and 10.")

            radios = each_access_point.get("radios")
            if not radios:
                errormsg.append("radios: Radios is missing in playbook.")
            elif radios and isinstance(radios, list):
                self.validate_radios(radios, each_access_point, errormsg)

        if errormsg:
            self.msg = f"Invalid parameters in playbook config: {' '.join(errormsg)}"
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        msg = f"Successfully validated config params: {str(config)}"
        self.log(msg, "INFO")
        return self

    def validate_radios(self, radios_param, each_access_point, errormsg):
        """
        Validate radio configuration parameters for access point positioning.

        Validates radio band compatibility, channel assignments, transmission power
        levels, and antenna configurations against Cisco Catalyst Center requirements
        and access point model specifications.

        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            radios_param (list): A list of radio configuration dictionaries.
            each_access_point (dict): A dictionary representing an access point.
            errormsg (list): A list to collect error messages.

        Returns:
            list: List of invalid access point position radios data with details.

        Description:
            - Validates radio count limits (maximum 4 radios per access point)
            - Validates radio band specifications (2.4GHz, 5GHz, 6GHz)
            - Validates band-specific channel assignments and ranges
            - Validates transmission power levels and antenna configurations
            - Validates azimuth (1-360 degrees) and elevation (-90 to 90 degrees)
        """
        self.log("Validating radio configuration parameters.", "DEBUG")

        radio_count = len(radios_param) if radios_param else 0
        self.log(
            "Processing radio validation for {0} radio configurations".format(radio_count),
            "DEBUG"
        )

        if len(radios_param) > 4:
            errormsg.append("Maximum of 4 radio configuration parameters are allowed.")
            return errormsg

        # Define channel ranges for validation
        channel_ranges = {
            "2.4GHz": list(range(1, 15)),  # Channels 1-14
            "5GHz": (
                list(range(36, 65, 4)) +
                list(range(100, 145, 4)) +
                [149, 153, 157, 161, 165, 169, 173]
            ),
            "6GHz": list(range(1, 234, 4))  # Channels 1, 5, 9, ... 233
        }
        for radio_idx, radio in enumerate(radios_param):
            self.log(
                "Validating radio configuration {0}/{1}".format(
                    radio_idx + 1, len(radios_param)
                ),
                "DEBUG"
            )

            # Validate radio structure
            if not isinstance(radio, dict):
                errormsg.append(
                    "radios: Radio configuration must be a dictionary, got: {0}".format(
                        type(radio).__name__
                    )
                )
                continue

            bands = radio.get("bands")
            if not bands:
                errormsg.append("bands: Bands is missing in playbook.")
                continue

            self.log(
                "Validating band '{0}' configuration for radio {1}".format(
                    bands, radio_idx + 1
                ),
                "DEBUG"
            )

            if bands and isinstance(bands, list):
                for band in bands:
                    param_spec = dict(type="str", length_max=3)
                    validate_str(str(band), param_spec, "bands", errormsg)
                    if band not in ["2.4", "5", "6"]:
                        errormsg.append(
                            "bands: Bands list must be '2.4', '5', or '6'."
                        )
            else:
                errormsg.append("bands: Bands is missing in playbook.")

            channel = radio.get("channel")
            if channel is None and each_access_point.get("action") != "manage_real_ap":
                errormsg.append("channel: Channel is missing in playbook.")
            elif isinstance(channel, int):
                channel_band = radio.get("bands")
                if bands and isinstance(bands, list):
                    channel_band = max(bands, key=float)

                valid_channels = channel_ranges.get(str(channel_band) + "GHz", [])
                if channel not in valid_channels:
                    errormsg.append(
                        "channel: Channel must be one of {0} for {1} band.".format(
                            valid_channels, str(channel_band) + "GHz"
                        )
                    )
            else:
                errormsg.append(
                    "channel: Channel must be an integer, got: {0}".format(
                        type(channel).__name__
                    )
                )

            tx_power = radio.get("tx_power")
            if tx_power is None and each_access_point.get("action") != "manage_real_ap":
                errormsg.append("tx_power: Tx Power is missing in playbook.")
            elif isinstance(tx_power, int):
                if not (0 < tx_power < 101):
                    errormsg.append(
                        "tx_power: Tx Power must be between 1 and 100 dBm."
                    )
            else:
                errormsg.append(
                    "tx_power: Tx Power must be an integer, got: {0}".format(
                        type(tx_power).__name__
                    )
                )

            antenna = radio.get("antenna")
            if antenna is None:
                errormsg.append("antenna: Antenna is missing in playbook.")
                continue
            elif antenna and isinstance(antenna, dict):
                antenna_name = antenna.get("antenna_name")
                if not antenna_name:
                    errormsg.append(
                        "antenna_name: Antenna Name is missing in playbook."
                    )
                else:
                    param_spec = dict(type="str", length_max=50)
                    validate_str(antenna_name, param_spec, "antenna_name", errormsg)

                # Validate azimuth angle
                azimuth = antenna.get("azimuth")
                if azimuth is None:
                    errormsg.append("azimuth: Azimuth is missing in playbook.")
                elif isinstance(azimuth, int):
                    if not (0 < azimuth < 361):
                        errormsg.append(
                            "azimuth: Azimuth must be between 1 and 360 degrees."
                        )
                else:
                    errormsg.append(
                        "azimuth: Azimuth must be an integer, got: {0}".format(
                            type(azimuth).__name__
                        )
                    )

                # Validate elevation angle
                elevation = antenna.get("elevation")
                if elevation is None:
                    errormsg.append("elevation: Elevation is missing in playbook.")
                elif isinstance(elevation, int):
                    if not (-91 < elevation < 91):
                        errormsg.append(
                            "elevation: Elevation must be between -90 and 90 degrees."
                        )
                else:
                    errormsg.append(
                        "elevation: Elevation must be an integer, got: {0}".format(
                            type(elevation).__name__
                        )
                    )

        self.log("Radio configuration validation completed.", "DEBUG")
        error_count = len([msg for msg in errormsg if any(
            field in msg for field in ["bands", "channel", "tx_power", "antenna"]
        )])

        self.log(
            "Radio configuration validation completed - {0} radios processed, "
            "{1} errors found".format(len(radios_param), error_count),
            "DEBUG"
        )
        return errormsg

    def get_want(self, config):
        """
        Retrieve and prepare desired state configuration for access point positioning.

        Processes playbook configuration to extract access point position requirements
        including site hierarchy, access point details, position coordinates, and radio
        configurations. Validates configuration integrity and prepares desired state
        for comparison against current Catalyst Center state.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing access point position details.
        Returns:
            self: The current instance of the class with updated 'want' attributes.

        Description:
            - Validates input configuration structure and content integrity
            - Extracts access point positioning requirements from playbook configuration
            - Prepares desired state dictionary for downstream processing and comparison
            - Stores validated configuration in want['ap_location'] for module workflow
        """
        self.log(f"Validating input data and update to want for: {config}", "INFO")

        config_keys = list(config.keys()) if isinstance(config, dict) else []
        access_points_count = len(config.get("access_points", [])) if config else 0

        self.log(
            f"Processing want state collection for config sections: {config_keys} with {access_points_count} access points",
            "DEBUG"
        )

        if not config:
            error_msg = "Configuration dictionary is empty or missing for want state collection"
            self.log(error_msg, "ERROR")
            self.set_operation_result("failed", False, error_msg, "ERROR")
            self.check_return_status()

        if not isinstance(config, dict):
            error_msg = "Configuration must be a dictionary, got: {0}".format(
                type(config).__name__
            )
            self.log(error_msg, "ERROR")
            self.set_operation_result("failed", False, error_msg, "ERROR")
            self.check_return_status()

        self.input_data_validation(config).check_return_status()
        want = {}
        if config:
            want["ap_location"] = config

        self.want = want
        self.log(f"Desired State (want) prepared for access point positioning: {self.pprint(self.want)}",
                 "INFO")

        return self

    def get_have(self, config):
        """
        Collect current state of access point positions from Cisco Catalyst Center.

        Retrieves site information, validates access point models against supported
        antenna patterns, and categorizes access points for create/update/delete operations.
        Gathers comprehensive current state including device details, position information,
        and antenna compatibility for comparison with desired state.

        Parameters:
            config (dict) - Playbook details containing access point position

        Returns:
            self - The current object with site details and access point position
            information collection for create and update.

        Description:
            - Validates site hierarchy and retrieves site ID from Catalyst Center
            - Collects supported antenna patterns for access point model validation
            - Validates antenna compatibility for each access point radio configuration
            - Categorizes access points based on current vs desired state comparison
            - Prepares data structures for subsequent create/update/delete operations
        """

        self.log(
            f"Collecting access point position related information for: {config}",
            "INFO",
        )

        if not isinstance(config, dict):
            error_msg = "Configuration must be a dictionary, got: {0}".format(
                type(config).__name__
            )
            self.log(error_msg, "ERROR")
            self.fail_and_exit(error_msg)

        site_hierarchy = config.get("floor_site_hierarchy")
        access_points_count = len(config.get("access_points", []))
        self.log(
            "Collecting state for site '{0}' with {1} access points".format(
                site_hierarchy, access_points_count
            ),
            "DEBUG"
        )

        response = self.get_site(config.get("floor_site_hierarchy"))
        if not response.get("response") or not isinstance(response["response"], list):
            msg = "Invalid API response structure for site information"
            self.log(msg, "WARNING")
            self.fail_and_exit(msg)

        site = response["response"][0]
        if not site.get("id"):
            msg = f"No site information found for: {config}"
            self.log(msg, "WARNING")
            self.fail_and_exit(msg)

        self.log(
            "Site information retrieved successfully - ID: {0}".format(site["id"]),
            "DEBUG"
        )
        have = {
            "site_id": site["id"],
            "site_name": config.get("floor_site_hierarchy"),
            "selected_ap_model": [],
        }

        self.log(
            "Validating access point models and antenna compatibility",
            "DEBUG"
        )
        for access_point in config.get("access_points", []):

            if self.params.get("state") == "deleted":
                self.log("Skipping antenna validation for deletion operation: {0}".format(
                    access_point.get("accesspoint_name")), "INFO"
                )
                continue

            if access_point.get("action") == "assign_planned_ap":
                self.log(f"Access point marked for Assign Planned AP: {access_point}", "INFO")
                continue

            have["antenna_patterns"] = self.get_supported_antenna_patterns()
            selected_ap_model = self.find_dict_by_key_value(
                have["antenna_patterns"], "apType", access_point.get("accesspoint_model")
            )
            if not selected_ap_model:
                msg = f"No supported access point model found for: {access_point.get('accesspoint_model')}"
                self.log(msg, "WARNING")
                self.fail_and_exit(msg)
            self.log(f"Supported AP Model found: {self.pprint(selected_ap_model)}", "INFO")

            radios = access_point.get("radios")
            for radio in radios:
                band = radio.get("bands")
                if band and isinstance(band, list):
                    band = max(band, key=float)
                antenna_name = radio.get("antenna", {}).get("antenna_name")

                self.log(
                    f"Validating radio band '{band}' compatibility with AP model", "DEBUG"
                )
                band_exist = self.find_dict_by_key_value(
                    selected_ap_model.get("antennaPatterns"), "band", band
                )
                if not band_exist:
                    msg = f"No supported antenna pattern band found for: {radio.get('bands')} {antenna_name}"
                    self.log(msg, "WARNING")
                    self.fail_and_exit(msg)
                self.log(f"Band exist: {self.pprint(band_exist)}", "DEBUG")

                self.log(f"Finding antenna name exist on supported AP model for: {antenna_name}.", "INFO")
                if len(radio.get("bands", [])) > 1:
                    antenna_exist = any(name.startswith(antenna_name) for name in band_exist.get("names", []))
                    if not antenna_exist:
                        msg = f"No supported antenna name found for dual band: {antenna_exist}"
                        self.log(msg, "WARNING")
                        self.fail_and_exit(msg)
                elif antenna_name not in band_exist.get("names"):
                    msg = f"No supported antenna name found for: {antenna_name}"
                    self.log(msg, "WARNING")
                    self.fail_and_exit(msg)

                self.log(f"Antenna name exist: {antenna_name} in {selected_ap_model.get('name')}", "DEBUG")

            have["selected_ap_model"].append(selected_ap_model)

        accesspoint_exists, new_accesspoint, update_accesspoint = [], [], []
        assign_accesspoint, assigned_accesspoint = [], []
        access_point_devices = []
        delete_accesspoint = []
        update_real_accesspoint = []

        for access_point in config.get("access_points", []):
            ap_name = access_point.get('accesspoint_name')
            self.log(
                "Processing access point state analysis for: {0}".format(ap_name),
                "DEBUG"
            )

            # Check if access point exist in the planned position
            ap_details = self.get_access_point_posisiton(
                have["site_id"], have["site_name"], access_point
            )
            if not ap_details:
                # Check if access point exist in the real position
                ap_details = self.get_access_point_posisiton(
                    have["site_id"], have["site_name"], access_point, True
                )
                if ap_details:
                    self.log(f"Access point found in real position for analysis: {ap_name}", "INFO")
                    if self.params.get("state") == "deleted":
                        ap_details[0]["action"] = access_point.get("action")
                        delete_accesspoint.append(ap_details[0])
                    else:
                        self.log(f"Access point already assigned to real position: {ap_name}", "INFO")
                        assigned_accesspoint.append(ap_details[0])
                    continue

            if ap_details:
                if self.params.get("state") == "deleted":
                    self.log(f"Access point marked for deletion from planned position: {ap_name}", "INFO")
                    ap_details[0]["action"] = access_point.get("action")
                    delete_accesspoint.append(ap_details[0])
                    continue

                if access_point.get("action") == "assign_planned_ap":
                    self.log(f"Access point marked for Assign Planned AP: {access_point}", "INFO")
                    ap_details[0]["action"] = access_point.get("action")
                    ap_details[0]["mac_address"] = access_point.get("mac_address")
                    assign_accesspoint.append(ap_details[0])

                    self.log(f"Retrieving accesspoint details for MAC Address: {access_point.get('mac_address')}", "INFO")
                    ap_device_details = self.get_access_point_device_details(access_point.get("mac_address"))
                    if not ap_device_details:
                        msg = f"No device details found for access point: {access_point.get('mac_address')}"
                        self.log(msg, "WARNING")
                        self.fail_and_exit(msg)
                    access_point_devices.append(ap_device_details)
                    continue

                ap_status, ap_update = self.compare_access_point_configurations(
                    ap_details[0], access_point)
                if ap_status:
                    self.log(f"Access point configuration matches desired state: {ap_name}", "INFO")
                    accesspoint_exists.append(access_point)
                else:
                    if access_point.get("action") == "manage_real_ap":
                        self.log(f"Real access point position requires update: {ap_name}", "INFO")
                        update_real_accesspoint.append(access_point)
                        continue
                    else:
                        self.log(f"Planned access point position requires update: {ap_name}", "INFO")
                        update_accesspoint.append(access_point)
            else:
                self.log(
                    f"New access point position to be created: {ap_name}",
                    "INFO"
                )
                new_accesspoint.append(access_point)

        have.update({
            "accesspoint_devices": access_point_devices,
            "new_accesspoint": new_accesspoint,
            "update_accesspoint": update_accesspoint,
            "update_real_accesspoint": update_real_accesspoint,
            "existing_accesspoint": accesspoint_exists,
            "delete_accesspoint": delete_accesspoint,
            "assign_accesspoint": assign_accesspoint,
            "already_assigned_accesspoint": assigned_accesspoint,
        })
        self.have = have
        self.log(
            "Current state collection completed - new: {0}, update: {1}, "
            "delete: {2}, existing: {3}".format(
                len(new_accesspoint), len(update_accesspoint),
                len(delete_accesspoint), len(accesspoint_exists)
            ),
            "INFO"
        )

        self.log(
            "Current State (have) collected for access point positioning: {0}".format(
                self.pprint(self.have)
            ),
            "INFO"
        )

        return self

    def get_supported_antenna_patterns(self):
        """
        Retrieve supported access point antenna patterns from Cisco Catalyst Center.

        Collects comprehensive antenna pattern mappings including supported access point
        models, antenna types, frequency bands, and pattern specifications required for
        access point positioning validation and compatibility verification.

        Parameters:
            None

        Returns:
            dict: Dictionary containing antenna pattern mappings with model specifications,
                  band support, and antenna name associations for validation

        Description:
            - Retrieves antenna pattern data from Catalyst Center maps API
            - Validates API response structure and content availability
            - Provides antenna compatibility data for access point model validation
            - Supports multi-band antenna pattern verification for radio configurations
        """
        self.log("Collecting supported access point antenna patterns", "INFO")

        try:
            response = self.execute_get_request(
                "sites", "maps_supported_access_points", {}
            )
            if not response:
                msg = "No response received from API for supported access point antenna patterns."
                self.log(msg, "WARNING")
                self.fail_and_exit(msg)

            if not isinstance(response, (dict, list)):
                error_msg = (
                    "Invalid response format for antenna patterns - expected dict or list, "
                    "got: {0}".format(type(response).__name__)
                )
                self.log(error_msg, "WARNING")
                self.fail_and_exit(error_msg)

            self.log(f"Supported Access Point Antenna Patterns API Response: {self.pprint(response)}", "DEBUG")

            return response

        except Exception as e:
            self.msg = 'An error occurred during get supported AP antenna patterns. '
            self.log(self.msg + str(e), "ERROR")
            self.fail_and_exit(self.msg)

    def get_access_point_posisiton(self, floor_id, floor_name, ap_details, recheck=False):
        """
        Retrieve access point position information from Cisco Catalyst Center.

        Queries either planned or real access point positions based on operation context
        and access point configuration. Supports both planned position queries for
        creation/update operations and real position queries for management operations.

        Parameters:
            floor_id (str) - The ID of the floor where the access point is located.
            floor_name (str) - The name of the floor where the access point is located.
            ap_details (dict) - The access point details from the playbook config.
            recheck (bool) - Flag to indicate if this is a recheck for deletion.

        Returns:
            dict - Planned access point position information

        Description:
            - Determines whether to query planned or real position based on operation type
            - Constructs appropriate API payload with floor ID, name, and optional model
            - Executes position retrieval via Catalyst Center site design APIs
            - Handles both planned position queries and real position validation
        """
        self.log(
            f"Collecting planned access point position for site: {floor_name} and access point: {ap_details}",
            "INFO",
        )

        ap_name = ap_details.get("accesspoint_name", "Unknown") if ap_details else "None"
        operation_type = ap_details.get("action", "planned") if ap_details else "planned"

        self.log(
            "Retrieving position for floor '{0}', access point '{1}', operation '{2}', "
            "recheck: {3}".format(floor_name, ap_name, operation_type, recheck),
            "DEBUG"
        )

        payload = {
            "offset": 1,
            "limit": 500,
            "floor_id": floor_id,
            "name": ap_details["accesspoint_name"]
        }

        function_name = None
        if (
            ap_details.get("action") in ["manage_real_ap"]
            or recheck
        ):
            function_name = "get_access_points_positions"
            position_type = "real"
        else:
            function_name = "get_planned_access_points_positions"
            position_type = "planned"

            if ap_details.get("accesspoint_model"):
                payload["type"] = ap_details["accesspoint_model"]

        try:
            response = self.execute_get_request(
                "site_design", function_name, payload
            )
            if not response:
                msg = f"No response received from API for the planned access point position: {ap_details}"
                self.log(msg, "WARNING")
                return None

            if not isinstance(response, dict):
                warning_msg = (
                    "Invalid response format for {0} position query - expected dict, "
                    "got: {1}".format(position_type, type(response).__name__)
                )
                self.log(warning_msg, "WARNING")
                return None

            self.log(f"{position_type} Access Point Position API Response: {response}", "DEBUG")
            return response.get("response")

        except Exception as e:
            self.msg = 'An error occurred during get planned AP position. '
            self.log(self.msg + str(e), "ERROR")
            return None

    def compare_access_point_configurations(self, ap_details, access_point):
        """
        Compare planned access point configuration with existing configuration details.

        Performs comprehensive comparison between desired access point configuration
        from playbook and current access point configuration from Catalyst Center.
        Validates position coordinates, radio settings, antenna configurations, and
        basic access point attributes to determine if updates are required.

        Parameters:
            ap_details (dict) - Actual access point details.
            access_point (dict) - Planned access point details.

        Returns:
            tuple: (comparison_result, unmatched_differences)
                - comparison_result (bool): True if configurations match, False otherwise
                - unmatched_differences (list): List of tuples containing field differences

        Description:
            - Compares basic access point attributes (name, MAC, model)
            - Validates position coordinates with float precision handling
            - Performs radio-by-radio comparison based on band matching
            - Validates antenna configurations (name, azimuth, elevation)
            - Updates access point configuration with existing IDs for updates
        """
        self.log(
            f"Comparing access point details: {self.pprint(access_point)} with existing details: {self.pprint(ap_details)}",
            "INFO",
        )

        ap_name = access_point.get("accesspoint_name", "Unknown")
        existing_id = ap_details.get("id", "Unknown")

        self.log(
            f"Comparing desired configuration for AP '{ap_name}' against existing ID '{existing_id}'",
            "DEBUG"
        )

        # Initialize comparison state tracking
        configurations_match = True
        configuration_differences = []

        # Define basic access point fields for comparison
        basic_ap_fields = ["accesspoint_name", "mac_address", "accesspoint_model"]

        self.log(
            "Validating basic access point attributes for configuration consistency",
            "DEBUG"
        )

        for field_name in basic_ap_fields:
            desired_value = access_point.get(field_name)
            existing_value = ap_details.get(self.keymap[field_name])

            self.log(
                "Comparing field '{0}': desired='{1}', existing='{2}'".format(
                    field_name, desired_value, existing_value
                ),
                "DEBUG"
            )

            if desired_value != existing_value:
                self.log(
                    "Configuration mismatch detected for field '{0}'".format(field_name),
                    "INFO"
                )
                configuration_differences.append((
                    field_name, desired_value, existing_value
                ))
                configurations_match = False

        self.log(
            "Validating access point position coordinates for configuration consistency",
            "DEBUG"
        )

        desired_position = access_point.get("position", {})
        existing_position = ap_details.get("position", {})
        position_fields = ["x_position", "y_position", "z_position"]

        for position_field in position_fields:
            desired_coord = desired_position.get(position_field)
            existing_coord = existing_position.get(self.keymap[position_field])

            self.log(
                "Comparing position '{0}': desired={1}, existing={2}".format(
                    position_field, desired_coord, existing_coord
                ),
                "DEBUG"
            )

            # Validate coordinate values exist before comparison
            if (existing_coord is not None and desired_coord is not None):
                try:
                    if float(desired_coord) != float(existing_coord):
                        self.log(
                            "Position coordinate mismatch for field '{0}'".format(
                                position_field
                            ),
                            "INFO"
                        )
                        configuration_differences.append((
                            position_field, desired_coord, existing_coord
                        ))
                        configurations_match = False

                except (ValueError, TypeError) as e:
                    self.log(
                        "Invalid coordinate values for comparison: {0}".format(str(e)),
                        "WARNING"
                    )
                    configuration_differences.append((
                        position_field, "invalid_coordinate", str(e)
                    ))
                    configurations_match = False

        self.log(
            "Validating radio configurations for antenna and transmission settings",
            "DEBUG"
        )

        desired_radios = access_point.get("radios", [])
        existing_radios = ap_details.get("radios", [])

        self.log(
            "Processing {0} desired radios against {1} existing radio configurations".format(
                len(desired_radios), len(existing_radios)
            ),
            "DEBUG"
        )

        for radio_config in desired_radios:
            matching_radio_found = False

            # Convert band values to float for comparison
            try:
                desired_bands = [float(band) for band in radio_config.get("bands", [])]

            except (ValueError, TypeError):
                self.log(
                    "Invalid band values in desired radio configuration: {0}".format(
                        radio_config.get("bands")
                    ),
                    "WARNING"
                )
                continue

            # Find matching radio by band configuration
            for existing_radio in existing_radios:
                try:
                    existing_bands = [
                        float(band) for band in existing_radio.get("bands", [])
                    ]

                except (ValueError, TypeError):
                    continue

                self.log(
                    "Comparing radio bands - desired: {0}, existing: {1}".format(
                        desired_bands, existing_bands
                    ),
                    "DEBUG"
                )

                # Match radios by band configuration
                if desired_bands == existing_bands:
                    matching_radio_found = True
                    radio_config["id"] = existing_radio.get("id")

                    # Compare radio transmission settings
                    radio_comparison_result = self._compare_radio_settings(
                        radio_config, existing_radio, configuration_differences
                    )

                    if not radio_comparison_result:
                        configurations_match = False

                    break

            if not matching_radio_found:
                self.log(
                    "No matching existing radio found for bands: {0}".format(
                        desired_bands
                    ),
                    "WARNING"
                )
                configuration_differences.append((
                    "radio_bands", desired_bands, "no_matching_radio"
                ))
                configurations_match = False

        # Update access point configuration for potential updates
        if configuration_differences:
            access_point["planned_id"] = ap_details.get("id")

            self.log(
                "Configuration differences detected - {0} mismatches found".format(
                    len(configuration_differences)
                ),
                "WARNING"
            )

            for field, desired, existing in configuration_differences:
                self.log(
                    "Difference - field: {0}, desired: {1}, existing: {2}".format(
                        field, desired, existing
                    ),
                    "DEBUG"
                )

        comparison_status = "match" if configurations_match else "mismatch"
        self.log(
            "Access point configuration comparison completed - result: {0}, "
            "differences: {1}".format(comparison_status, len(configuration_differences)),
            "INFO"
        )

        return configurations_match, configuration_differences

    def _compare_radio_settings(self, desired_radio, existing_radio, differences_list):
        """
        Helper method to compare radio transmission and antenna settings.

        Parameters:
            desired_radio (dict): Desired radio configuration from playbook
            existing_radio (dict): Current radio configuration from API
            differences_list (list): List to append differences to

        Returns:
            bool: True if radio settings match, False otherwise
        """

        radio_settings_match = True
        radio_fields = ["channel", "tx_power"]

        # Compare basic radio settings
        for field_name in radio_fields:
            desired_value = desired_radio.get(field_name)
            existing_value = existing_radio.get(self.keymap[field_name])

            if desired_value != existing_value:
                self.log(
                    "Radio setting mismatch for field '{0}': {1} != {2}".format(
                        field_name, desired_value, existing_value
                    ),
                    "INFO"
                )
                differences_list.append(("radio_" + field_name, desired_value, existing_value))
                radio_settings_match = False

        # Compare antenna configuration
        desired_antenna = desired_radio.get("antenna", {})
        existing_antenna = existing_radio.get(self.keymap["antenna"], {})

        if desired_antenna and existing_antenna:
            antenna_match = self._compare_antenna_configuration(
                desired_antenna, existing_antenna, differences_list
            )

            if not antenna_match:
                desired_radio["id"] = existing_radio.get("id")
                radio_settings_match = False

        return radio_settings_match

    def _compare_antenna_configuration(self, desired_antenna, existing_antenna, differences_list):
        """
        Helper method to compare antenna configuration parameters.

        Parameters:
            desired_antenna (dict): Desired antenna configuration
            existing_antenna (dict): Current antenna configuration
            differences_list (list): List to append differences to

        Returns:
            bool: True if antenna configurations match, False otherwise
        """

        antenna_config_match = True
        antenna_fields = ["antenna_name", "azimuth", "elevation"]

        for field_name in antenna_fields:
            desired_value = desired_antenna.get(field_name)
            existing_value = existing_antenna.get(self.keymap[field_name])

            # Handle numeric fields with type conversion
            if field_name in ["azimuth", "elevation"]:
                try:
                    if (desired_value is not None and
                       existing_value is not None and
                       int(desired_value) != int(existing_value)):

                        self.log(
                            "Antenna {0} mismatch: {1} != {2}".format(
                                field_name, desired_value, existing_value
                            ),
                            "INFO"
                        )
                        differences_list.append((
                            "antenna_" + field_name, desired_value, existing_value
                        ))
                        antenna_config_match = False

                except (ValueError, TypeError) as e:
                    self.log(
                        "Invalid {0} values for comparison: {1}".format(field_name, str(e)),
                        "WARNING"
                    )
                    antenna_config_match = False

            # Handle string fields
            elif desired_value != existing_value:
                self.log(
                    "Antenna {0} mismatch: '{1}' != '{2}'".format(
                        field_name, desired_value, existing_value
                    ),
                    "INFO"
                )
                differences_list.append((
                    "antenna_" + field_name, desired_value, existing_value
                ))
                antenna_config_match = False

        return antenna_config_match

    def get_access_point_device_details(self, mac_address):
        """
        Retrieve device details for access point from Cisco Catalyst Center.

        Queries device information using MAC address to obtain comprehensive device
        details including configuration, status, and identification information
        required for access point position management operations.

        Parameters:
            self (object): An instance of the class containing the method.
            mac_address (str): The MAC address of the access point to retrieve details for.

        Returns:
            dict: A dictionary containing the current details of the access point, or an error message.

        Description:
            - Validates MAC address format and availability
            - Executes device list query via Catalyst Center devices API
            - Retrieves first matching device from response for position operations
            - Handles device not found scenarios with appropriate logging
        """
        input_param = {
            "macAddress": mac_address
        }
        self.log(
            "Starting device details retrieval for access point position management",
            "INFO"
        )

        self.log(
            "Retrieving device details for MAC address: {0}".format(mac_address),
            "DEBUG"
        )

        try:
            ap_response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                op_modifies=True,
                params=input_param,
            )

            if not ap_response:
                warning_msg = (
                    "No response received from device list API for MAC address: {0}".format(
                        mac_address
                    )
                )
                self.log(warning_msg, "WARNING")
                return None

            # Extract device data from response
            device_data_list = ap_response.get("response") if ap_response else None

            # Validate response structure and content
            if not device_data_list:
                warning_msg = (
                    "Empty response received from device query for MAC address: {0}".format(
                        mac_address
                    )
                )
                self.log(warning_msg, "WARNING")
                return None

            if not isinstance(device_data_list, list):
                warning_msg = (
                    "Invalid response format for device query - expected list, "
                    "got: {0}".format(type(device_data_list).__name__)
                )
                self.log(warning_msg, "WARNING")
                return None

            if len(device_data_list) == 0:
                warning_msg = (
                    "No device found with MAC address: {0}".format(mac_address)
                )
                self.log(warning_msg, "WARNING")
                return None

            # Extract first device from results
            device_details = device_data_list[0]

            # Validate device details structure
            if not isinstance(device_details, dict):
                warning_msg = (
                    "Invalid device details format - expected dict, got: {0}".format(
                        type(device_details).__name__
                    )
                )
                self.log(warning_msg, "WARNING")
                return None

            # Log successful device retrieval with details
            device_id = device_details.get("id", "Unknown")
            device_hostname = device_details.get("hostname", "Unknown")

            self.log(
                "Device details retrieved successfully - ID: {0}, hostname: {1}, "
                "MAC: {2}".format(device_id, device_hostname, mac_address),
                "INFO"
            )

            # Debug logging for device details analysis
            self.log(
                "Retrieved device details for position management: {0}".format(
                    self.pprint(device_details)
                ),
                "DEBUG"
            )

            return device_details

        except Exception as e:
            error_msg = (
                f"An error occurred during device details retrieval for MAC address: {mac_address}"
            )
            self.log(
                f"{error_msg}: {str(e)}",
                "WARNING"
            )

            # Set instance message for error context
            self.msg = (
                f"The provided device with MAC '{mac_address}' is either invalid or not "
                "present in the Cisco Catalyst Center")

            return None

    def transform_access_point_payload(self, accesspoint):
        """
        Transform playbook access point configuration to API payload format.

        Converts access point configuration from playbook format to Cisco Catalyst
        Center API payload structure for planned position operations including position
        coordinates, radio configurations, and antenna specifications.

        Parameters:
            accesspoint (dict) - Access point details from the playbook config.

        Returns:
            dict - Parsed planned access point position details in API payload format.

        Description:
            - Transforms field names using keymap for API compatibility
            - Converts position coordinates to API structure format
            - Processes radio configurations with band and antenna details
            - Handles both create and update operations with ID preservation
            - Validates nested structure availability before transformation
        """
        ap_name = accesspoint.get("accesspoint_name", "Unknown")
        has_planned_id = bool(accesspoint.get("planned_id"))
        radio_count = len(accesspoint.get("radios", []))

        self.log(
            "Transforming configuration for AP '{0}', has_id: {1}, radios: {2}".format(
                ap_name, has_planned_id, radio_count
            ),
            "DEBUG"
        )

        # Initialize API payload structure
        api_payload = {}

        if accesspoint.get("planned_id"):
            api_payload["id"] = accesspoint.get("planned_id")
            self.log(
                "Including planned ID '{0}' for update operation".format(
                    api_payload["id"]), "DEBUG")

        api_payload["name"] = accesspoint.get("accesspoint_name")

        if accesspoint.get("mac_address"):
            api_payload["macAddress"] = accesspoint.get("mac_address")
            self.log(
                "Including MAC address for access point identification",
                "DEBUG"
            )

        # Add access point model type
        api_payload["type"] = accesspoint.get("accesspoint_model")

        # Transform position coordinates
        position_config = accesspoint.get("position", {})
        if isinstance(position_config, dict):
            api_payload["position"] = {
                "x": position_config.get("x_position"),
                "y": position_config.get("y_position"),
                "z": position_config.get("z_position"),
            }

            self.log(
                "Transformed position coordinates - x:{0}, y:{1}, z:{2}".format(
                    position_config.get("x_position"),
                    position_config.get("y_position"),
                    position_config.get("z_position")
                ),
                "DEBUG"
            )
        else:
            self.log(
                "Position configuration not available or invalid format",
                "WARNING"
            )
            api_payload["position"] = {"x": None, "y": None, "z": None}

        # Transform radio configurations
        radio_configurations = accesspoint.get("radios", [])
        transformed_radios = []

        self.log(
            "Processing {0} radio configurations for API transformation".format(
                len(radio_configurations)
            ),
            "DEBUG"
        )

        for radio_idx, radio_config in enumerate(radio_configurations):
            if not isinstance(radio_config, dict):
                self.log(
                    "Skipping invalid radio configuration at index {0}".format(radio_idx),
                    "WARNING"
                )
                continue

            # Transform radio payload structure
            transformed_radio = {
                "bands": radio_config.get("bands"),
                "channel": radio_config.get("channel"),
                "txPower": radio_config.get("tx_power"),
            }

            # Transform antenna configuration
            antenna_config = radio_config.get("antenna", {})
            if isinstance(antenna_config, dict):
                transformed_radio["antenna"] = {
                    "name": antenna_config.get("antenna_name"),
                    "azimuth": antenna_config.get("azimuth"),
                    "elevation": antenna_config.get("elevation"),
                }
            else:
                self.log(
                    "Antenna configuration missing for radio {0}".format(radio_idx),
                    "WARNING"
                )
                transformed_radio["antenna"] = {
                    "name": None, "azimuth": None, "elevation": None
                }

            # Preserve radio ID for update operations
            if radio_config.get("id"):
                transformed_radio["id"] = radio_config.get("id")
                self.log(
                    "Preserving radio ID '{0}' for update operation".format(
                        radio_config.get("id")
                    ),
                    "DEBUG"
                )

            transformed_radios.append(transformed_radio)

        api_payload["radios"] = transformed_radios

        # Log successful transformation with payload statistics
        payload_fields = list(api_payload.keys())
        self.log(
            f"API payload transformation completed successfully - fields: {payload_fields}, radios: {len(transformed_radios)}",
            "INFO"
        )

        # Debug logging for complete payload structure
        self.log(
            f"Generated API payload for access point positioning: {self.pprint(api_payload)}",
            "DEBUG"
        )

        return api_payload

    def process_access_point_position_operations(self, function_name, floor_id, payloads, state):
        """
        Executes create, update, or assignment operations for access point positions through
        the Catalyst Center site design API with comprehensive task status monitoring and
        error handling for operation validation and completion verification.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            function_name (str): The name of the function to call for processing.
            floor_id (str): The ID of the floor where the access point is located.
            payloads (list): The list of payloads to process.
            state (str): The desired state of create/update/assign for the access point position.

        Returns:
            str: Operation result - "SUCCESS" for completed operations, "FAILURE" for
                failed operations, None for API communication errors

        Description:
            - Initiates access point position operations through Catalyst Center APIs
            - Monitors task execution status with comprehensive error handling
            - Tracks operation results in appropriate location tracking lists
            - Provides detailed logging for debugging and operational visibility
        """
        self.log(
            f"Processing access point position creation/updation for: {self.have.get('site_name')}",
            "INFO",
        )

        try:
            task_id = self.get_taskid_post_api_call(
                "site_design", function_name,
                {
                    "floor_id": floor_id, "payload": payloads
                }
            )
            if not task_id:
                msg = f"No response received from API for creating/updating/assigning Access Point Location: {self.have.get('site_name')}"
                self.log(msg, "WARNING")
                if state == "update":
                    self.location_not_updated.append(self.have.get("site_name"))
                elif state == "assign":
                    self.location_not_assigned.append(self.have.get("site_name"))
                else:
                    self.location_not_created.append(self.have.get("site_name"))

            self.log(f"{state} planned Access Point location API Response: {task_id}", "DEBUG")
            self.get_task_status_from_tasks_by_id(task_id, function_name, "SUCCESS")
            if self.msg == "SUCCESS":
                self.log(f"Task '{task_id}' completed successfully.", "INFO")
                return self.msg
            else:
                self.log(f"Task '{task_id}' failed.", "ERROR")
                return "FAILURE"

        except Exception as e:
            self.msg = 'An error occurred during get task details. '
            self.log(self.msg + str(e), "ERROR")
            return None

    def manage_access_point_positions(self):
        """
        Create or update planned access point position in Cisco Catalyst Center based on the
        playbook details.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Returns:
            self - The current object with message and response information.
        """
        self.log(
            f"Starting to create/update planned access point position for: {self.have.get('site_name')}",
            "INFO",
        )

        floor_id = self.have.get("site_id")
        if not floor_id or not isinstance(floor_id, str):
            error_msg = "Floor ID must be a non-empty string for position operations"
            self.log(error_msg, "ERROR")
            return None

        create_payload, update_payload, update_real_payload = [], [], []
        collect_ap_list = []

        if self.have.get("new_accesspoint"):
            non_created_positions = []
            for access_point in self.have.get("new_accesspoint"):
                if access_point.get("action") == "assign_planned_ap":
                    self.log(f"Skipping creation for access point marked for Assign Planned AP: {self.pprint(access_point)}",
                             "INFO")
                    non_created_positions.append(access_point.get("accesspoint_name"))
                    continue
                self.log(f"Processing new access point: {self.pprint(access_point)}", "INFO")
                parsed_ap_details = self.transform_access_point_payload(access_point)

                create_payload.append(parsed_ap_details)
                self.log(f"Parsed planned Access Point Payload: {self.pprint(parsed_ap_details)}", "DEBUG")
                collect_ap_list.append(access_point.get("accesspoint_name"))

            if non_created_positions:
                self.msg = f"Given accesspoint name not available in planned positions to assign: {non_created_positions}"
                self.log(self.msg, "WARNING")
                self.fail_and_exit(self.msg)

            self.log(
                f"Creating planned Access Point position with payload: {self.pprint(create_payload)}",
                "DEBUG",
            )

            process_response = self.process_access_point_position_operations(
                "add_planned_access_points_positions", floor_id, create_payload, "create"
            )
            if process_response == "SUCCESS":
                self.msg = f"Planned Access Point Position created successfully for: {self.have.get('site_name')}"
                self.log(self.msg , "INFO")
                self.location_created.append(collect_ap_list)
            elif process_response == "FAILURE":
                self.msg = f"Failed to create Planned Access Point position for: {self.have.get('site_name')}"
                self.log(self.msg, "ERROR")
                self.location_not_created.append(collect_ap_list)
            else:
                self.msg = f"Unable to process planned Access Point position creation for: {self.have.get('site_name')}"
                self.log(self.msg, "ERROR")
                self.location_not_created.append(collect_ap_list)

        if self.have.get("update_accesspoint"):
            self.log(f"Updating planned Access Point position with payload: {self.pprint(self.have.get('update_accesspoint'))}", "DEBUG")

            for access_point in self.have.get("update_accesspoint"):
                self.log(f"Processing update planned access point: {self.pprint(access_point)}", "INFO")
                parsed_ap_details = self.transform_access_point_payload(access_point)

                # Validate the payload before adding to update list
                is_valid, validation_errors = self.validate_update_payload(parsed_ap_details, "update")
                if not is_valid:
                    error_msg = f"Invalid update payload for AP '{access_point.get('accesspoint_name')}': {'; '.join(validation_errors)}"
                    self.log(error_msg, "ERROR")
                    self.fail_and_exit(error_msg)

                update_payload.append(parsed_ap_details)
                self.log(f"Parsed Planned Access Point Payload: {self.pprint(parsed_ap_details)}", "DEBUG")
                collect_ap_list.append(access_point.get("accesspoint_name"))

            self.log(
                f"Updating planned Access Point position with payload: {self.pprint(update_payload)}",
                "DEBUG",
            )

            process_response = self.process_access_point_position_operations(
                "edit_planned_access_points_positions", floor_id, update_payload, "update"
            )
            if process_response == "SUCCESS":
                self.msg = f"Planned Access Point position updated successfully for: {self.have.get('site_name')}"
                self.log(self.msg , "INFO")
                self.location_updated.append(collect_ap_list)

                self.log(".", "INFO")
            elif process_response == "FAILURE":
                self.msg = f"Failed to update planned Access Point position for: {self.have.get('site_name')}"
                self.log(self.msg, "ERROR")
                self.location_not_updated.append(collect_ap_list)
            else:
                self.msg = f"Unable to process planned Access Point position updation for: {self.have.get('site_name')}"
                self.log(self.msg, "ERROR")
                self.location_not_updated.append(collect_ap_list)

        if self.have.get("update_real_accesspoint"):
            self.log(f"Updating real Access Point position with payload: {self.pprint(self.have.get('update_real_accesspoint'))}", "DEBUG")

            for access_point in self.have.get("update_real_accesspoint"):
                self.log(f"Processing update real access point: {self.pprint(access_point)}", "INFO")
                parsed_ap_details = self.transform_access_point_payload(access_point)
                update_real_payload.append(parsed_ap_details)
                self.log(f"Parsed Real Access Point Payload: {self.pprint(parsed_ap_details)}", "DEBUG")
                collect_ap_list.append(access_point.get("accesspoint_name"))

            self.log(
                f"Updating real Access Point position with payload: {self.pprint(update_real_payload)}",
                "DEBUG",
            )

            process_response = self.process_access_point_position_operations(
                "edit_the_access_points_positions", floor_id, update_real_payload, "update"
            )
            if process_response == "SUCCESS":
                self.msg = f"Real Access Point position updated successfully for: {self.have.get('site_name')}"
                self.log(self.msg , "INFO")
                self.location_updated.append(collect_ap_list)

                self.log(".", "INFO")
            elif process_response == "FAILURE":
                self.msg = f"Failed to update real Access Point position for: {self.have.get('site_name')}"
                self.log(self.msg, "ERROR")
                self.location_not_updated.append(collect_ap_list)
            else:
                self.msg = f"Unable to process real Access Point position updation for: {self.have.get('site_name')}"
                self.log(self.msg, "ERROR")
                self.location_not_updated.append(collect_ap_list)

        return self

    def validate_update_payload(self, payload, operation="update"):
        """
        Performs comprehensive validation of access point configuration payload to ensure
        all required fields are present for successful API operations including ID validation
        for update operations, radio configuration completeness, and payload structure integrity.

        Parameters:
            payload (dict): The payload to validate
            operation (str): The operation type (update/create)

        Returns:
            tuple: (validation_result, error_messages)
                - validation_result (bool): True if payload is valid, False otherwise
                - error_messages (list): List of validation error descriptions

        Description:
            - Validates payload structure and required field presence
            - Ensures update operations contain necessary ID fields for existing entities
            - Validates radio configurations have proper identification for updates
            - Provides detailed error messages for troubleshooting payload issues
        """
        self.log(
            "Starting payload validation for access point API operation requirements",
            "INFO"
        )

        payload_fields = list(payload.keys()) if isinstance(payload, dict) else []
        radio_count = len(payload.get("radios", [])) if isinstance(payload, dict) else 0

        self.log(
            "Validating payload for operation '{0}' with fields: {1}, radios: {2}".format(
                operation, payload_fields, radio_count
            ),
            "DEBUG"
        )
        validation_errors = []

        if operation == "update":
            self.log(
                "Validating update operation requirements for access point payload",
                "DEBUG"
            )

            # For updates, ensure AP has an ID
            if not payload.get("id"):
                validation_errors.append("Update operation requires 'id' field")
                self.log(
                    "Missing access point ID for update operation - validation failed",
                    "WARNING"
                )
            else:
                self.log(
                    "Access point ID '{0}' validated for update operation".format(
                        payload.get("id")
                    ),
                    "DEBUG"
                )

            # Validate radio configurations for update operations
            radio_configurations = payload.get("radios", [])

            if not isinstance(radio_configurations, list):
                validation_errors.append(
                    "Radio configurations must be a list for payload validation"
                )
                self.log(
                    "Invalid radio configuration format - expected list, got: {0}".format(
                        type(radio_configurations).__name__
                    ),
                    "WARNING"
                )
            else:
                self.log(
                    "Validating {0} radio configurations for update operation".format(
                        len(radio_configurations)
                    ),
                    "DEBUG"
                )

                # Validate each radio configuration
                for radio_index, radio_config in enumerate(radio_configurations):
                    if not isinstance(radio_config, dict):
                        validation_errors.append(
                            "Radio at index {0} must be a dictionary".format(radio_index)
                        )
                        continue

                    radio_bands = radio_config.get("bands", "Unknown")

                    # Validate radio ID for update operations
                    if not radio_config.get("id"):
                        error_message = (
                            "Radio at index {0} (bands: {1}) is missing required "
                            "'id' field for update operation".format(radio_index, radio_bands)
                        )
                        validation_errors.append(error_message)

                        self.log(
                            "Radio validation failed - missing ID for radio {0} with bands {1}".format(
                                radio_index, radio_bands
                            ),
                            "WARNING"
                        )
                    else:
                        self.log(
                            "Radio ID '{0}' validated for bands '{1}' at index {2}".format(
                                radio_config.get("id"), radio_bands, radio_index
                            ),
                            "DEBUG"
                        )
        elif operation == "create":
            self.log(
                "Validating create operation requirements for access point payload",
                "DEBUG"
            )

            # Validate required fields for create operations
            required_create_fields = ["name", "type", "position", "radios"]

            for required_field in required_create_fields:
                if not payload.get(required_field):
                    validation_errors.append(
                        "Create operation requires '{0}' field".format(required_field)
                    )

            self.log(
                "Create operation field validation completed with {0} errors".format(
                    len([e for e in validation_errors if "Create operation requires" in e])
                ),
                "DEBUG"
            )

        # Determine validation result
        payload_is_valid = len(validation_errors) == 0

        validation_status = "valid" if payload_is_valid else "invalid"
        self.log(
            "Payload validation completed - result: {0}, errors: {1}".format(
                validation_status, len(validation_errors)
            ),
            "INFO"
        )

        if validation_errors:
            self.log(
                "Payload validation errors detected: {0}".format(
                    "; ".join(validation_errors)
                ),
                "DEBUG"
            )
        else:
            self.log(
                "Payload validation successful - all required fields present for '{0}' operation".format(
                    operation
                ),
                "DEBUG"
            )

        return payload_is_valid, validation_errors

    def assign_access_point_to_planned_position(self):
        """
        Processes assignment operations by matching real access point devices with their
        corresponding planned positions through device MAC addresses and planned position IDs.
        Executes assignment via Catalyst Center APIs with comprehensive validation and
        error handling for operational reliability.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Returns:
            self - The current object with message and response information.

        Description:
            - Validates access point assignment requirements and device availability
            - Matches real devices with planned positions using MAC address lookup
            - Constructs assignment payloads with device and planned position identifiers
            - Executes assignments through Catalyst Center site design APIs
            - Tracks assignment results for operational reporting and validation
        """
        self.log(f"Assigning access point to planned position for: {self.have.get('site_name')}", "INFO")
        site_name = self.have.get('site_name', 'Unknown')
        assignment_count = len(self.have.get("assign_accesspoint", []))

        self.log(
            "Processing {0} access point assignments for site '{1}'".format(
                assignment_count, site_name
            ),
            "DEBUG"
        )

        if not self.have.get("assign_accesspoint"):
            self.log(
                "No access point assignments found for processing - operation complete",
                "INFO"
            )
            return self

        access_point_devices_details = self.have.get("accesspoint_devices", [])
        assignment_payloads = []
        processed_ap_list = []
        self.log(
            "Processing access point assignment operations with {0} device details available".format(
                len(access_point_devices_details)
            ),
            "DEBUG"
        )

        for access_point_config in self.have.get("assign_accesspoint", []):
            if access_point_config.get("action") != "assign_planned_ap":
                self.log(
                    "Skipping non-assignment action for AP: {0}".format(
                        access_point_config.get("accesspoint_name", "Unknown")
                    ),
                    "DEBUG"
                )
                continue

            ap_name = access_point_config.get("name", "Unknown")
            mac_address = access_point_config.get("mac_address")

            self.log(
                "Processing assignment operation for AP '{0}' with MAC '{1}'".format(
                    ap_name, mac_address
                ),
                "DEBUG"
            )

            # Input validation for security
            if not mac_address:
                error_msg = (
                    "MAC address is required for assignment operation: {0}".format(ap_name)
                )
                self.log(error_msg, "WARNING")
                self.fail_and_exit(error_msg)

            self.log(f"Processing assign access point to planned position: {self.pprint(access_point_config)}",
                     "INFO")
            # Find matching device details using MAC address
            matching_device = self.find_dict_by_key_value(
                access_point_devices_details, "macAddress",
                access_point_config.get("mac_address", access_point_config.get("name"))
            )

            if not matching_device:
                error_msg = (
                    "No device details found for access point '{0}' with MAC '{1}'".format(
                        ap_name, mac_address
                    )
                )
                self.log(error_msg, "WARNING")
                self.fail_and_exit(error_msg)

            self.log(
                "Device details located for AP '{0}' with device ID '{1}'".format(
                    ap_name, matching_device.get("id", "Unknown")
                ),
                "DEBUG"
            )

            ap_details = self.get_access_point_posisiton(
                self.have["site_id"], self.have["site_name"], access_point_config
            )
            if not ap_details:
                msg = f"Check the assignment exist in real position: {ap_name}"
                self.log(msg, "WARNING")
                ap_details = self.get_access_point_posisiton(
                    self.have["site_id"], self.have["site_name"], access_point_config, True)
                if ap_details:
                    self.log(f"Access point real position found: {ap_name}", "INFO")
                    self.location_already_assigned.append(ap_name)
                    continue

            ap_payload = {
                "accessPointId": matching_device.get("id"),
                "plannedAccessPointId": ap_details[0].get("id")
            }
            assignment_payloads.append(ap_payload)
            processed_ap_list.append(ap_name)

        if not assignment_payloads:
            self.log(
                "No valid access point assignments found for processing - operation complete",
                "INFO"
            )
            return self

        self.log(
            "Executing {0} access point assignment operations via Catalyst Center API".format(
                len(assignment_payloads)
            ),
            "INFO"
        )

        self.log(
            "Assignment operation payload: {0}".format(self.pprint(assignment_payloads)),
            "DEBUG"
        )

        floor_id = self.have.get("site_id")
        assignment_response = self.process_access_point_position_operations(
            "assign_planned_access_points_to_operations_ones",
            floor_id, assignment_payloads, "assign_planned_ap"
        )

        self.log(
            "Assignment operation API response received: {0}".format(
                self.pprint(assignment_response)
            ),
            "DEBUG"
        )

        if assignment_response == "SUCCESS":
            success_msg = (
                "Access point assignments completed successfully for site '{0}'".format(
                    site_name
                )
            )
            self.log(success_msg, "INFO")
            self.msg = success_msg
            self.location_assigned.append(processed_ap_list)

        elif assignment_response == "FAILURE":
            failure_msg = (
                "Access point assignment operations failed for site '{0}'".format(
                    site_name
                )
            )
            self.log(failure_msg, "ERROR")
            self.msg = failure_msg
            self.location_not_assigned.append(processed_ap_list)

        else:
            error_msg = (
                "Unable to process access point assignment operations for site '{0}'".format(
                    site_name
                )
            )
            self.log(error_msg, "ERROR")
            self.msg = error_msg
            self.location_not_assigned.append(processed_ap_list)

        assigned_count = len(self.location_assigned[-1]) if self.location_assigned else 0
        failed_count = len(self.location_not_assigned[-1]) if self.location_not_assigned else 0
        already_assigned_count = len(self.location_already_assigned)

        self.log(
            "Assignment operations completed - assigned: {0}, failed: {1}, "
            "already_assigned: {2}".format(
                assigned_count, failed_count, already_assigned_count
            ),
            "INFO"
        )

        return self

    def delete_access_point_positions(self):
        """
        Remove planned and real access point positions from Cisco Catalyst Center.

        Processes deletion operations for both planned position removal and real access
        point unassignment based on operation type. Executes appropriate API calls for
        position cleanup with comprehensive task monitoring and error handling for
        operational reliability and validation.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Returns:
            self - The current object with message and response information.

        Description:
            - Processes planned position deletions using site design APIs
            - Handles real access point unassignment via device management APIs
            - Monitors task execution status with comprehensive error handling
            - Tracks deletion results for operational reporting and validation
            - Supports both individual and batch deletion operations
        """
        self.log(f"Deleting planned access point positions for: {self.have.get('site_name')}", "INFO")
        site_name = self.have.get('site_name', 'Unknown')
        deletion_count = len(self.have.get("delete_accesspoint", []))

        self.log(
            "Processing {0} access point deletions for site '{1}'".format(
                deletion_count, site_name
            ),
            "DEBUG"
        )

        # Process each access point for deletion operations
        for access_point_config in self.have.get("delete_accesspoint", []):
            ap_name = access_point_config.get("name", "Unknown")
            operation_type = access_point_config.get("action", "planned")

            self.log(
                "Processing deletion operation for AP '{0}' with type '{1}'".format(
                    ap_name, operation_type
                ),
                "DEBUG"
            )

            if not access_point_config.get("id"):
                error_msg = (
                    f"Access point ID is required for deletion operation: {ap_name}"
                )
                self.log(error_msg, "WARNING")
                self.location_not_deleted.append(ap_name)
                continue

            delete_payload = {}
            family_name = "site_design"
            function_name = "delete_planned_access_points_position"

            if access_point_config.get("action") == "manage_real_ap":
                delete_payload["deviceIds"] = [access_point_config.get("id")]
                function_name = "unassign_network_devices_from_sites"
                self.log(
                    "Configured real access point unassignment for device ID: {0}".format(
                        access_point_config.get("id")
                    ),
                    "DEBUG"
                )
            else:
                delete_payload["floor_id"] = self.have.get("site_id")
                delete_payload["id"] = access_point_config.get("id")
                self.log(
                    "Configured planned position deletion for floor ID: {0}, position ID: {1}".format(
                        self.have.get("site_id"), access_point_config.get("id")
                    ),
                    "DEBUG"
                )

            self.log(f"Deleting planned access point position Payload: {self.pprint(delete_payload)}",
                     "DEBUG")

            try:
                task_id = self.get_taskid_post_api_call(
                    family_name, function_name, delete_payload
                )
                if not task_id:
                    msg = f"No task ID received from API for deletion operation on site '{site_name}', AP '{ap_name}'"
                    self.log(msg, "WARNING")
                    self.location_not_deleted.append(ap_name)
                    continue

                self.log(
                    f"Deletion task '{task_id}' initiated successfully for AP '{ap_name}' - monitoring status",
                    "DEBUG",
                )

                self.get_task_status_from_tasks_by_id(task_id, function_name, "SUCCESS")
                if self.msg == "SUCCESS":
                    self.log(f"Task '{task_id}' completed successfully.", "INFO")
                    self.location_deleted.append(ap_name)
                else:
                    self.log(f"Task '{task_id}' failed.", "ERROR")
                    self.location_not_deleted.append(ap_name)

            except Exception as e:
                self.msg = 'An error occurred during get task details. '
                self.log(self.msg + str(e), "ERROR")
                self.location_not_deleted.append(ap_name)
                continue

        deleted_count = len(self.location_deleted)
        failed_count = len(self.location_not_deleted)

        self.log(
            "Access point deletion operations completed - deleted: {0}, failed: {1}".format(
                deleted_count, failed_count
            ),
            "INFO"
        )

        if self.location_deleted:
            self.log(
                "Successfully deleted access points: {0}".format(", ".join(self.location_deleted)),
                "INFO"
            )

        if self.location_not_deleted:
            self.log(
                "Failed to delete access points: {0}".format(
                    ", ".join(self.location_not_deleted)
                ),
                "WARNING"
            )
        return self

    def get_diff_merged(self, config):
        """
        Processes create, update, and assignment operations for access point positions
        based on current state analysis. Coordinates planned position management,
        real position updates, and assignment operations with comprehensive status
        tracking and operational validation.

        Parameters:
            config (list of dict) - Playbook details containing planned access point position information.

        Returns:
            self - The current object with message and created/updated/assigned response information.

        Description:
            - Processes existing position validation and skip logic for idempotent operations
            - Executes create/update operations for new and modified access point positions
            - Handles assignment operations for planned to real position mapping
            - Tracks operation results with detailed success/failure categorization
            - Provides comprehensive status reporting for operational visibility
        """
        self.log(
            f"Starting to create/update planned or real access point position for: {config}", "INFO"
        )

        site_hierarchy = config.get("floor_site_hierarchy", "Unknown")
        access_points_count = len(config.get("access_points", []))

        self.log(
            "Processing merge operations for site '{0}' with {1} access point configurations".format(
                site_hierarchy, access_points_count
            ),
            "DEBUG"
        )

        if not isinstance(config, dict):
            error_msg = "Configuration must be a dictionary for merge operations"
            self.log(error_msg, "ERROR")
            self.fail_and_exit(error_msg)

        if not config.get("access_points"):
            error_msg = "Access points configuration is required for merge operations"
            self.log(error_msg, "ERROR")
            self.fail_and_exit(error_msg)

        self.changed = False
        self.status = "failed"
        operations_performed = []

        # Handle existing access point positions (idempotent behavior)
        if self.have.get("existing_accesspoint"):
            existing_count = 0
            for access_point_config in self.have.get("existing_accesspoint", []):
                if isinstance(access_point_config, dict):
                    ap_name = access_point_config.get("name", "Unknown")
                    self.location_exist.append(ap_name)
                    existing_count += 1

            if existing_count > 0:
                self.log(
                    "Found {0} existing access point positions - no changes required".format(
                        existing_count
                    ),
                    "INFO"
                )

                self.msg = (
                    "No changes required - planned access point positions already exist"
                )
                self.changed = False
                self.status = "success"
                operations_performed.append("existing_validation")

        if self.have.get("already_assigned_accesspoint"):
            assigned_count = 0
            for access_point_config in self.have.get("already_assigned_accesspoint", []):
                if isinstance(access_point_config, dict):
                    ap_name = access_point_config.get("name", "Unknown")
                    self.location_exist.append(ap_name)
                    assigned_count += 1

            if assigned_count > 0:
                self.log(
                    f"Found {assigned_count} already assigned access point positions - no changes required",
                    "INFO"
                )

                self.msg = (
                    "No changes required - access point positions already assigned"
                )
                self.changed = False
                self.status = "success"
                operations_performed.append("assignment_validation")

        # Process create/update operations
        creation_update_required = (
            self.have.get("new_accesspoint") or
            self.have.get("update_accesspoint") or
            self.have.get("update_real_accesspoint")
        )
        if creation_update_required:
            new_count = len(self.have.get("new_accesspoint", []))
            update_planned_count = len(self.have.get("update_accesspoint", []))
            update_real_count = len(self.have.get("update_real_accesspoint", []))

            self.log(
                "Executing position operations - new: {0}, update_planned: {1}, "
                "update_real: {2}".format(
                    new_count, update_planned_count, update_real_count
                ),
                "INFO"
            )

            creation_update_response = self.manage_access_point_positions()

            if not creation_update_response:
                error_msg = (
                    "No response received from access point position creation/update operations"
                )
                self.log(error_msg, "ERROR")
                self.fail_and_exit(error_msg)

            operations_performed.append("create_update_operations")
            self.log(
                "Position creation/update operations completed successfully",
                "DEBUG"
            )

        # Process assignment operations
        if self.have.get("assign_accesspoint"):
            assignment_count = len(self.have.get("assign_accesspoint", []))

            self.log(
                "Executing {0} access point assignment operations".format(assignment_count),
                "INFO"
            )

            assignment_response = self.assign_access_point_to_planned_position()

            # Process assignment results
            if self.location_assigned:
                assigned_list = [str(item) for item in self.location_assigned]
                success_msg = (
                    "Access point positions assigned successfully for: {0}".format(
                        assigned_list
                    )
                )
                self.log(success_msg, "INFO")
                self.msg = success_msg
                self.changed = True
                self.status = "success"
                operations_performed.append("assignment_operations")

        # Handle operation failures and error conditions
        if self.location_not_created:
            failed_creations = [str(item) for item in self.location_not_created]
            failed_msg = (
                "Unable to process the following access point positions: {0}. "
                "They may not have been created or already exist.".format(
                    ", ".join(failed_creations)
                )
            )

            self.log(failed_msg, "WARNING")

            if hasattr(self, 'msg'):
                self.msg += " " + failed_msg
            else:
                self.msg = failed_msg

            self.changed = False
            self.status = "failed"
            operations_performed.append("creation_failures")

        # Prepare operation results for response
        processed_locations = self.location_created + self.location_updated
        location_results = [str(item) for item in processed_locations]

        self.log(
            "Merge operation completed - operations: {0}, processed: {1}, "
            "existing: {2}, failed: {3}".format(
                operations_performed,
                len(location_results),
                len(self.location_exist),
                len(self.location_not_created)
            ),
            "INFO"
        )

        if hasattr(self, 'msg'):
            self.log(self.msg, "INFO")
        else:
            self.msg = "Access point position merge operations completed"
            self.log(self.msg, "INFO")

        self.set_operation_result(
            self.status, self.changed, self.msg, "INFO", location_results
        ).check_return_status()

        return self

    def verify_diff_merged(self, config):
        """
        Validate access point position operations against Cisco Catalyst Center state.

        Performs comprehensive verification of merge operation results by comparing
        expected outcomes with actual system state. Validates creation, update, and
        assignment operations to ensure configuration consistency and operational
        reliability for access point position management.

        Parameters:
            config (dict) - Playbook details containing access point planned location
                            related information.

        Returns:
            self - The current object with message and response information.

        Description:
            - Validates successful creation operations against expected access point count
            - Verifies update operations completed successfully for modified positions
            - Confirms assignment operations for planned to real position mapping
            - Tracks verification failures and provides detailed error reporting
            - Ensures idempotent behavior for existing configurations
        """
        self.log(
            f"Starting to verify created/updated Access Point Location(s) for: {config}",
            "INFO",
        )

        site_hierarchy = config.get("floor_site_hierarchy", "Unknown")
        expected_ap_count = len(config.get("access_points", []))

        self.log(
            "Verifying merge operations for site '{0}' with {1} expected access points".format(
                site_hierarchy, expected_ap_count
            ),
            "DEBUG"
        )

        self.changed = False
        verification_operations = []

        # Collect operation statistics for verification
        created_count = len(self.location_created)
        updated_count = len(self.location_updated)
        existing_count = len(self.location_exist)
        assigned_count = len(self.location_assigned)
        failed_creation_count = len(self.location_not_created)
        failed_update_count = len(self.location_not_updated)
        failed_assignment_count = len(self.location_not_assigned)

        self.log(
            "Operation statistics - created: {0}, updated: {1}, existing: {2}, "
            "assigned: {3}, failed_creation: {4}, failed_update: {5}, "
            "failed_assignment: {6}".format(
                created_count, updated_count, existing_count, assigned_count,
                failed_creation_count, failed_update_count, failed_assignment_count
            ),
            "DEBUG"
        )

        # Verify creation operations
        if self.location_created and created_count == expected_ap_count:
            success_msg = (
                "Access point positions created successfully for site '{0}'".format(
                    site_hierarchy
                )
            )
            self.log(success_msg, "INFO")
            self.msg = success_msg
            self.changed = True
            self.status = "success"
            verification_operations.append("creation_verification")

        # Verify idempotent behavior for existing positions
        elif (self.location_exist and not self.location_created and
              not self.location_updated and existing_count == expected_ap_count):
            idempotent_msg = (
                "No changes required - access point positions already exist"
            )
            self.log(idempotent_msg, "INFO")
            self.msg = idempotent_msg
            self.changed = False
            self.status = "success"
            verification_operations.append("idempotent_verification")

        # Verify update operations
        elif self.location_updated and updated_count == expected_ap_count:
            update_msg = (
                "Access point positions updated successfully for site '{0}'".format(
                    site_hierarchy
                )
            )
            self.log(update_msg, "INFO")
            self.msg = update_msg
            self.changed = True
            self.status = "success"
            verification_operations.append("update_verification")

        # Verify mixed create/update operations
        elif (self.location_created and self.location_updated and
              (created_count + updated_count) == expected_ap_count):
            combined_operations = self.location_created + self.location_updated
            mixed_msg = (
                "Access point positions created/updated successfully for: {0}".format(
                    str(combined_operations)
                )
            )
            self.log(mixed_msg, "INFO")
            self.msg = mixed_msg
            self.changed = True
            self.status = "success"
            verification_operations.append("mixed_operations_verification")

        # Handle assignment operation results
        if self.location_assigned:
            assigned_list = [str(item) for item in self.location_assigned]
            assignment_msg = (
                " Following access points assigned to planned positions: {0}.".format(
                    ", ".join(assigned_list)
                )
            )

            if hasattr(self, 'msg'):
                self.msg += assignment_msg
            else:
                self.msg = "Assignment operations completed." + assignment_msg

            self.changed = True
            self.log(
                "Assignment verification completed successfully with {0} assignments".format(
                    assigned_count
                ),
                "DEBUG"
            )
            verification_operations.append("assignment_verification")

        # Handle assignment failures
        if self.location_not_assigned:
            not_assigned_list = [str(item) for item in self.location_not_assigned]
            assignment_failure_msg = (
                " Following access points not assigned to planned positions: {0}.".format(
                    ", ".join(not_assigned_list)
                )
            )

            if hasattr(self, 'msg'):
                self.msg += assignment_failure_msg
            else:
                self.msg = "Assignment failures detected." + assignment_failure_msg

            self.log(
                "Assignment verification detected {0} failures".format(
                    failed_assignment_count
                ),
                "DEBUG"
            )
            verification_operations.append("assignment_failure_tracking")

        # Handle update operation failures
        if self.location_not_updated:
            not_updated_list = [str(item) for item in self.location_not_updated]
            update_failure_msg = (
                " Unable to update the following access point positions: {0}.".format(
                    ", ".join(not_updated_list)
                )
            )

            if hasattr(self, 'msg'):
                self.msg += update_failure_msg
            else:
                self.msg = "Update failures detected." + update_failure_msg

            self.status = "failed"
            self.log(
                "Update verification detected {0} failures".format(failed_update_count),
                "WARNING"
            )
            verification_operations.append("update_failure_tracking")

        # Handle creation operation failures
        if self.location_not_created:
            not_created_list = [str(item) for item in self.location_not_created]
            creation_failure_msg = (
                " Unable to create the following access point positions: {0}.".format(
                    ", ".join(not_created_list)
                )
            )

            if hasattr(self, 'msg'):
                self.msg += creation_failure_msg
            else:
                self.msg = "Creation failures detected." + creation_failure_msg

            self.status = "failed"
            self.log(
                "Creation verification detected {0} failures".format(
                    failed_creation_count
                ),
                "WARNING"
            )
            verification_operations.append("creation_failure_tracking")

        self.log(self.msg, "INFO")
        successful_operations = (
            self.location_created + self.location_updated + self.location_assigned
        )
        unique_operations = [
            list(operation) for operation in set(map(tuple, successful_operations))
        ]

        verification_status = getattr(self, 'status', 'unknown')
        self.log(
            "Merge verification completed - status: {0}, operations: {1}, "
            "successful: {2}, unique_results: {3}".format(
                verification_status, verification_operations,
                len(successful_operations), len(unique_operations)
            ),
            "INFO"
        )

        if hasattr(self, 'msg'):
            self.log(self.msg, "INFO")
        else:
            self.msg = "Access point position verification completed"
            self.log(self.msg, "INFO")

        self.set_operation_result(
            self.status, self.changed, self.msg, "INFO", unique_operations
        ).check_return_status()

        return self

    def get_diff_deleted(self, config):
        """
        Execute access point position deletion workflow for Cisco Catalyst Center.

        Processes deletion operations for both planned and real access point positions
        based on current state analysis. Handles idempotent behavior for non-existent
        positions and coordinates actual deletion operations with comprehensive status
        tracking and operational validation.

        Parameters:
            config (list of dict) - Playbook configuration details

        Returns:
            self - The current object with planned Access Point position deletion message and response information.

        Description:
            - Validates deletion requirements based on current position state
            - Implements idempotent behavior for positions that don't exist
            - Executes deletion operations for existing planned/real positions
            - Tracks deletion results with detailed success/failure categorization
            - Provides comprehensive status reporting for operational visibility
        """
        self.log(f"Starting to delete planned Access Point position(s) for: {config}", "INFO")
        site_hierarchy = config.get("floor_site_hierarchy", "Unknown")
        access_points_count = len(config.get("access_points", []))

        self.log(
            "Processing deletion operations for site '{0}' with {1} access point configurations".format(
                site_hierarchy, access_points_count
            ),
            "DEBUG"
        )
        self.changed = False
        self.status = "failed"
        deletion_operations = []

        if self.have.get("new_accesspoint") and not self.have.get("delete_accesspoint"):
            non_existent_count = 0
            for access_point_config in self.have.get("new_accesspoint", []):
                if isinstance(access_point_config, dict):
                    ap_name = access_point_config.get("accesspoint_name", "Unknown")
                    self.location_already_deleted.append(ap_name)
                    non_existent_count += 1

            if non_existent_count > 0:
                self.log(
                    "Found {0} non-existent access point positions - no deletion required".format(
                        non_existent_count
                    ),
                    "INFO"
                )

                idempotent_msg = (
                    "No changes required - access point positions do not exist for deletion"
                )
                self.log(idempotent_msg, "INFO")
                self.msg = idempotent_msg
                self.changed = False
                self.status = "success"
                deletion_operations.append("idempotent_validation")

        # Process actual deletion operations for existing positions
        if self.have.get("delete_accesspoint"):
            deletion_targets_count = len(self.have.get("delete_accesspoint", []))

            self.log(
                "Executing {0} access point position deletion operations".format(
                    deletion_targets_count
                ),
                "INFO"
            )

            deletion_response = self.delete_access_point_positions()

            # Initialize deletion processing status
            self.changed = False
            self.status = "failed"

            # Validate deletion operation response
            if not deletion_response:
                error_msg = (
                    "No response received from access point position deletion operations"
                )
                self.log(error_msg, "ERROR")
                self.fail_and_exit(error_msg)

            deletion_operations.append("deletion_execution")

            # Process successful deletions
            if self.location_deleted:
                deleted_count = len(self.location_deleted)
                success_msg = (
                    "Access point positions deleted successfully: {0}".format(
                        self.location_deleted
                    )
                )
                self.log(success_msg, "INFO")
                self.msg = success_msg
                self.changed = True
                self.status = "success"
                deletion_operations.append("successful_deletions")

            # Handle deletion failures
            if self.location_not_deleted:
                failed_deletions = [str(item) for item in self.location_not_deleted]
                failure_msg = (
                    " Unable to delete the following access point positions: {0}.".format(
                        ", ".join(failed_deletions)
                    )
                )

                if hasattr(self, 'msg'):
                    self.msg += failure_msg
                else:
                    self.msg = "Deletion failures detected." + failure_msg

                self.log(
                    "Deletion operation failed for {0} positions".format(
                        len(failed_deletions)
                    ),
                    "DEBUG"
                )
                self.changed = False
                self.status = "failed"
                deletion_operations.append("deletion_failures")

            # Handle already deleted positions
            if self.location_already_deleted:
                already_deleted_list = [str(item) for item in self.location_already_deleted]
                already_deleted_msg = (
                    " Access point positions already deleted: {0}.".format(
                        ", ".join(already_deleted_list)
                    )
                )

                if hasattr(self, 'msg'):
                    self.msg += already_deleted_msg
                else:
                    self.msg = "Previously deleted positions found." + already_deleted_msg

                # Don't change status to failed if some positions were already deleted
                if not self.location_not_deleted:
                    self.changed = False
                    self.status = "success"

                deletion_operations.append("already_deleted_tracking")

        deleted_count = len(self.location_deleted)
        failed_count = len(self.location_not_deleted)
        already_deleted_count = len(self.location_already_deleted)

        self.log(
            "Deletion workflow completed - operations: {0}, deleted: {1}, "
            "failed: {2}, already_deleted: {3}".format(
                deletion_operations, deleted_count, failed_count, already_deleted_count
            ),
            "INFO"
        )

        if hasattr(self, 'msg'):
            self.log(self.msg, "INFO")
        else:
            self.msg = "Access point position deletion workflow completed"
            self.log(self.msg, "INFO")

        self.set_operation_result(
            self.status, self.changed, self.msg, "INFO"
        ).check_return_status()

        return self

    def verify_diff_deleted(self, config):
        """
        Performs comprehensive verification of deletion operation results by confirming
        the removal of access point positions from the system. Validates both planned
        and real position deletions to ensure configuration consistency and operational
        reliability for access point position cleanup.

        Parameters:
            config (dict) - Playbook details containing Access Point position information.

        Returns:
            self - The current object with message and response.

        Description:
            - Validates successful deletion operations against expected access point count
            - Confirms idempotent behavior for positions that don't exist for deletion
            - Tracks deletion failures and provides detailed error reporting
            - Ensures complete removal of access point positions from system state
        """
        self.log(
            f"Starting to verify the deleted planned or real Access Point position(s) for: {config}",
            "INFO",
        )

        site_hierarchy = config.get("floor_site_hierarchy", "Unknown")
        expected_deletion_count = len(config.get("access_points", []))

        self.log(
            "Verifying deletion operations for site '{0}' with {1} expected deletions".format(
                site_hierarchy, expected_deletion_count
            ),
            "DEBUG"
        )

        # Initialize message attribute if not present
        if not hasattr(self, 'msg'):
            self.msg = ""

        # Collect deletion operation statistics for verification
        deleted_count = len(self.location_deleted)
        failed_deletion_count = len(self.location_not_deleted)
        already_deleted_count = len(self.location_already_deleted)

        self.log(
            "Deletion statistics - deleted: {0}, failed: {1}, already_deleted: {2}".format(
                deleted_count, failed_deletion_count, already_deleted_count
            ),
            "DEBUG"
        )

        # Handle deletion failures
        if failed_deletion_count > 0:
            failed_list = [str(item) for item in self.location_not_deleted]
            failure_msg = (
                "Unable to delete the following access point positions: {0}".format(
                    ", ".join(failed_list)
                )
            )

            if self.msg:
                self.msg += " " + failure_msg
            else:
                self.msg = failure_msg

            self.changed = False
            self.status = "failed"

            self.log(
                "Deletion verification failed - {0} positions could not be deleted".format(
                    failed_deletion_count
                ),
                "WARNING"
            )

        # Verify idempotent behavior for non-existent positions
        elif already_deleted_count == expected_deletion_count:
            already_deleted_list = [str(item) for item in self.location_already_deleted]
            idempotent_msg = (
                "No changes required - access point positions already deleted and "
                "verified successfully: {0}".format(", ".join(already_deleted_list))
            )

            self.log(
                "Deletion verification confirmed idempotent behavior for {0} positions".format(
                    already_deleted_count
                ),
                "INFO"
            )

            self.msg = idempotent_msg
            self.changed = False
            self.status = "success"

        # Verify successful deletion operations
        elif deleted_count == expected_deletion_count:
            deleted_list = [str(item) for item in self.location_deleted]
            success_msg = (
                "Access point positions deleted and verified successfully: {0}".format(
                    ", ".join(deleted_list)
                )
            )

            self.log(
                "Deletion verification confirmed successful removal of {0} positions".format(
                    deleted_count
                ),
                "INFO"
            )

            self.msg = success_msg
            self.changed = True
            self.status = "success"

        else:
            # Handle partial deletion scenarios
            partial_msg = (
                "Partial deletion verification completed - deleted: {0}, "
                "already_deleted: {1}, expected: {2}".format(
                    deleted_count, already_deleted_count, expected_deletion_count
                )
            )

            self.log(partial_msg, "WARNING")

            self.msg = (
                "Deletion verification completed with mixed results - some positions "
                "may require additional cleanup operations"
            )
            self.status = "failed"

        self.log(self.msg, "INFO")
        verification_status = getattr(self, 'status', 'unknown')
        self.log(
            "Deletion verification completed - status: {0}, deleted: {1}, "
            "failed: {2}, already_deleted: {3}".format(
                verification_status, deleted_count, failed_deletion_count,
                already_deleted_count
            ),
            "INFO"
        )

        if self.msg:
            self.log(self.msg, "INFO")
        else:
            self.msg = "Access point position deletion verification completed"
            self.log(self.msg, "INFO")

        # Set verification results and validate return status
        self.set_operation_result(
            self.status, self.changed, self.msg, "INFO", self.location_deleted
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
    ccc_ap_location = AccessPointLocation(module)
    state = ccc_ap_location.params.get("state")

    if (
        ccc_ap_location.compare_dnac_versions(
            ccc_ap_location.get_ccc_version(), "3.1.3.0"
        )
        < 0
    ):
        ccc_ap_location.status = "failed"
        ccc_ap_location.msg = (
            f"The specified version '{ccc_ap_location.get_ccc_version()}' does not support Accesspoint location workflow feature."
            f"Supported version(s) start from '3.1.3.0' onwards."
        )
        ccc_ap_location.log(ccc_ap_location.msg, "ERROR")
        ccc_ap_location.check_return_status()

    if state not in ccc_ap_location.supported_states:
        ccc_ap_location.status = "invalid"
        ccc_ap_location.msg = f"State {state} is invalid"
        ccc_ap_location.check_return_status()

    ccc_ap_location.validate_input().check_return_status()
    config_verify = ccc_ap_location.params.get("config_verify")

    for config in ccc_ap_location.validated_config:
        ccc_ap_location.reset_values()
        ccc_ap_location.get_want(config).check_return_status()
        ccc_ap_location.get_have(config).check_return_status()
        ccc_ap_location.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_ap_location.verify_diff_state_apply[state](
                config
            ).check_return_status()

    module.exit_json(**ccc_ap_location.result)


if __name__ == "__main__":
    main()
