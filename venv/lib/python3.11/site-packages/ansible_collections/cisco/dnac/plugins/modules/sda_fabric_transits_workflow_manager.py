#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to perform operations on SDA fabric transits in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ["Muthu Rakesh, Madhan Sankaranarayanan"]
DOCUMENTATION = r"""
---
module: sda_fabric_transits_workflow_manager
short_description: Resource module for SDA fabric transits
description:
  - Manage operations on SDA fabric transits.
  - API to create transit networks.
  - API to update transit networks.
  - API to delete transit networks.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Muthu Rakesh (@MUTHU-RAKESH-27) Madhan Sankaranarayanan
  (@madhansansel)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst
      Center after applying the playbook config.
    type: bool
    default: false
  state:
    description: The state of Cisco Catalyst Center
      after module completion.
    type: str
    choices: [merged, deleted]
    default: merged
  config:
    description:
      - A list of SDA fabric transit configurations.
      - Each entry in the list represents a transit
        network configuration.
    type: list
    elements: dict
    required: true
    suboptions:
      sda_fabric_transits:
        description: SDA fabric transit configurations.
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - The name of the SDA fabric transit.
              - It facilitates seamless communication
                between different network segments.
              - Required for the operations in the SDA
                fabric transits.
            type: str
          transit_site_hierarchy:
            description: |
                - The site name hierarchy for the SDA fabric transit configuration.
                - Specifies the hierarchical location of the fabric transit within the organizational network topology.
                - The transit transit_site_hierarchy would be higher then fabric site hierarchy to have multiple fabric
                  sites part of same transit.
                - Used to identify and associate the fabric transit with a specific site context in Cisco Catalyst Center.
                - Must follow the format 'Global/Area/Building/Floor' as configured in the site hierarchy within Cisco Catalyst Center.
                - The specified site hierarchy must exist in Cisco Catalyst Center before fabric transit creation or update.
                - This parameter enables site-aware fabric transit management and location-based network segmentation.
                - When provided during fabric transit creation, the transit will be associated with the specified site.
                - For existing fabric transits, changing the site hierarchy will update the site association if different from current assignment.
                - If not specified for existing transits, the current site association will be maintained.
                - Supported from Cisco Catalyst Center release version 3.1.3.0 onwards.
                - For versions prior to 3.1.3.0, this parameter will be ignored with a warning message.
                - Also if this is not assigned the default value is Global in catalyst center which allows this transit to be used
                  across any site in Catalyst center.
            type: str
            required: false
          transit_type:
            description: Type of the fabric tranist.
              IP_BASED_TRANSIT - Responsible for managing
              IP routing and ensures data flow between
              various segments of the network. SDA_LISP_PUB_SUB_TRANSIT
              - Facilitates the decoupling of location
              and identity information for devices,
              enabling dynamic routing. SDA_LISP_BGP_TRANSIT
              - Integrates LISP with BGP to manage and
              optimize routing decisions between different
              network segments.
            default: IP_BASED_TRANSIT
            choices: [IP_BASED_TRANSIT, SDA_LISP_PUB_SUB_TRANSIT,
              SDA_LISP_BGP_TRANSIT]
            type: str
          ip_transit_settings:
            description:
              - The configuration settings for IP based
                transit.
              - Required when the type is set to IP_BASED_TRANSIT.
              - IP_BASED_TRANSIT cannot be updated.
            type: dict
            suboptions:
              routing_protocol_name:
                description: Defines the protocol for
                  determining the best paths for data
                  transmission between networks.
                type: str
                default: BGP
                choices: [BGP]
              autonomous_system_number:
                description:
                  - Used by routing protocols like BGP
                    to manage routing between different
                    autonomous systems.
                  - Autonomous System Number (ANS) should
                    be from 1 to 4294967295.
                  - The ASN should be unique for every
                    IP-based transits.
                  - Required when the transit_type is
                    set to IP_BASED_TRANSIT.
                type: str
          sda_transit_settings:
            description:
              - The configuration settings for SDA-based
                transit.
              - Required when the transit_type is set
                to SDA_LISP_PUB_SUB_TRANSIT or SDA_LISP_BGP_TRANSIT.
            type: dict
            suboptions:
              is_multicast_over_transit_enabled:
                description:
                  - Determines whether multicast traffic
                    is permitted to traverse the transit
                    network.
                  - Enabling this option allows the
                    distribution of data to multiple
                    recipients across different network
                    segments.
                  - Available only when the transit
                    type is set to SDA_LISP_PUB_SUB_TRANSIT.
                type: bool
              control_plane_network_device_ips:
                description:
                  - Specifies the IP addresses of the
                    network devices that form the control
                    plane.
                  - Required when the transit_type is
                    set to either SDA_LISP_BGP_TRANSIT
                    or SDA_LISP_PUB_SUB_TRANSIT.
                  - Atleast one control plane network
                    device is required.
                  - A maximum of 2 control plane network
                    devices are allowed when the transit_type
                    is SDA_LISP_BGP_TRANSIT.
                  - A maximum of 4 control plane network
                    devices are allowed when the transit_type
                    is SDA_LISP_PUB_SUB_TRANSIT.
                  - SDA_LISP_PUB_SUB_TRANSIT supports
                    only devices with IOS XE 17.6 or
                    later.
                  - The devices must be present in the
                    Fabric site or zone.
                type: list
                elements: str
requirements:
  - dnacentersdk >= 2.9.2
  - python >= 3.9
notes:
  - SDK Method used are
    devices.Devices.get_device_list,
    sda.Sda.get_transit_networks,
    sda.Sda.add_transit_networks,
    sda.Sda.update_transit_networks,
    sda.Sda.delete_transit_network_by_id,
    task.Task.get_tasks_by_id,
    task.Task.get_task_details_by_id,
  - Paths used are
    get /dna/intent/api/v1/network-device,
    get /dna/intent/api/v1/sda/transitNetworks,
    post
    /dna/intent/api/v1/sda/transitNetworks,
    put /dna/intent/api/v1/sda/transitNetworks,
    delete /dna/intent/api/v1/sda/transitNetworks/${id},
    get /dna/intent/api/v1/tasks/${id} get /dna/intent/api/v1/tasks/${id}/detail
  - New parameter added 'transit_site_hierarchy' for creating/updating the transit network
    start supporting from Catalyst Center version 3.1.3.0 onwards.
"""
EXAMPLES = r"""
---
- name: Create SDA fabric transit of transit_type IP_BASED_TRANSIT
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: sample_transit
        transit_type: IP_BASED_TRANSIT
        ip_transit_settings:
          routing_protocol_name: BGP
          autonomous_system_number: 1234

- name: Create SDA fabric transit of transit_type IP_BASED_TRANSIT with newly added
    parameter 'transit_site_hierarchy'
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: sample_transit
        transit_site_hierarchy: Global/USA
        transit_type: IP_BASED_TRANSIT
        ip_transit_settings:
          routing_protocol_name: BGP
          autonomous_system_number: 134

- name: Create SDA fabric transit of transit_type SDA_LISP_BGP_TRANSIT
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: sample_transit
        transit_type: SDA_LISP_BGP_TRANSIT
        sda_transit_settings:
          control_plane_network_device_ips:
            - 10.0.0.1
            - 10.0.0.2

- name: Create SDA fabric transit of transit_type SDA_LISP_PUB_SUB_TRANSIT
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: sample_transit
        transit_type: SDA_LISP_PUB_SUB_TRANSIT
        sda_transit_settings:
          is_multicast_over_transit_enabled: false
          control_plane_network_device_ips:
            - 10.0.0.1
            - 10.0.0.2
            - 10.0.0.3
            - 10.0.0.4

- name: Update SDA fabric transit of transit_type IP_BASED_TRANSIT with newly added
    parameter 'transit_site_hierarchy'
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: sample_transit
        transit_site_hierarchy: Global/India
        transit_type: IP_BASED_TRANSIT
        ip_transit_settings:
          routing_protocol_name: BGP
          autonomous_system_number: 134

# Basic fabric transit creation with site hierarchy
- name: Create SDA fabric transit with site hierarchy
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: enterprise_transit_ny
            transit_type: SDA_LISP_BGP_TRANSIT
            transit_site_hierarchy: "Global/USA/NewYork/Building_A/Floor_1"
            sda_transit_settings:
              control_plane_network_device_ips:
                - 10.1.1.10
                - 10.1.1.11

# Multi-site fabric transit deployment
- name: Create multiple fabric transits across different sites
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: corporate_hq_transit
            transit_type: SDA_LISP_PUB_SUB_TRANSIT
            transit_site_hierarchy: "Global/Corporate/Headquarters/Building_Main"
            sda_transit_settings:
              is_multicast_over_transit_enabled: true
              control_plane_network_device_ips:
                - 192.168.10.1
                - 192.168.10.2
                - 192.168.10.3
          - name: branch_office_transit
            transit_type: SDA_LISP_BGP_TRANSIT
            transit_site_hierarchy: "Global/Branch_Offices/West_Coast/San_Francisco"
            sda_transit_settings:
              control_plane_network_device_ips:
                - 172.16.20.1
                - 172.16.20.2

# Update fabric transit with site hierarchy change
- name: Update fabric transit site association
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: enterprise_transit_ny
            transit_type: SDA_LISP_BGP_TRANSIT
            transit_site_hierarchy: "Global/USA/NewYork/Building_A/Floor_2"
            sda_transit_settings:
              control_plane_network_device_ips:
                - 10.1.1.10
                - 10.1.1.11

# Campus deployment with multiple buildings
- name: Deploy fabric transits across campus buildings
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: engineering_building_transit
            transit_type: SDA_LISP_PUB_SUB_TRANSIT
            transit_site_hierarchy: "Global/University/Campus/Engineering_Building"
            sda_transit_settings:
              is_multicast_over_transit_enabled: false
              control_plane_network_device_ips:
                - 10.100.1.1
                - 10.100.1.2
          - name: admin_building_transit
            transit_type: SDA_LISP_BGP_TRANSIT
            transit_site_hierarchy: "Global/University/Campus/Administration_Building"
            sda_transit_settings:
              control_plane_network_device_ips:
                - 10.200.1.1
                - 10.200.1.2

# Fabric transit without site hierarchy (legacy compatibility)
- name: Create fabric transit without site hierarchy
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: legacy_transit
            transit_type: SDA_LISP_BGP_TRANSIT
            # No transit_site_hierarchy specified - will work with all versions
            sda_transit_settings:
              control_plane_network_device_ips:
                - 10.50.1.1
                - 10.50.1.2

- name: Update SDA fabric transit of transit_type SDA_LISP_BGP_TRANSIT
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: sample_transit
        transit_type: SDA_LISP_BGP_TRANSIT
        sda_transit_settings:
          control_plane_network_device_ips:
            - 10.0.0.1
            - 10.0.0.2

- name: Update the multicast over transit
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: sample_transit
        transit_type: SDA_LISP_PUB_SUB_TRANSIT
        sda_transit_settings:
          is_multicast_over_transit_enabled: true

- name: Update the control plane network devices
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: sample_transit
        transit_type: SDA_LISP_PUB_SUB_TRANSIT
        sda_transit_settings:
          control_plane_network_device_ips:
            - 10.0.0.1
            - 10.0.0.2
            - 10.0.0.3

- name: Delete SDA fabric transit
  cisco.dnac.sda_fabric_transits_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: deleted
    config_verify: true
    config:
      - sda_fabric_transits:
          - name: sample_transit1
          - name: sample_transit2
"""
RETURN = r"""
# Case_1: Successful creation of SDA fabric transit
response_1:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_2: Successful updation of SDA fabric transit
response_2:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_3: Successful deletion of SDA fabric transit
response_3:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
    dnac_compare_equality,
)


class FabricTransit(DnacBase):
    """Class containing member attributes for sda_fabric_transits_workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.response = [{"fabric_transits": {"response": {}, "msg": {}}}]
        self.fabric_transits_obj_params = self.get_obj_params("fabricTransits")
        self.max_timeout = self.params.get("dnac_api_task_timeout")

    def validate_input(self):
        """
        Checks if the configuration parameters provided in the playbook
        meet the expected structure and data types,
        as defined in the 'temp_spec' dictionary.

        Parameters:
            self (object): The current object details.
        Returns:
            self (object): The current object with updated desired Fabric Transits information.
        Example:
            If the validation succeeds, 'self.status' will be 'success' and
            'self.validated_config' will contain the validated configuration.
            If it fails, 'self.status' will be 'failed', and
            'self.msg' will describe the validation issues.
        """

        if not self.config:
            self.msg = "config not available in playbook for validation."
            self.status = "success"
            return self

        # temp_spec is the specification for the expected structure of configuration parameters
        temp_spec = {
            "sda_fabric_transits": {
                "type": "list",
                "elements": "dict",
                "name": {"type": "str"},
                "transit_site_hierarchy": {"type": "str"},
                "transit_type": {
                    "type": "str",
                    "choices": [
                        "IP_BASED_TRANSIT",
                        "SDA_LISP_PUB_SUB_TRANSIT",
                        "SDA_LISP_BGP_TRANSIT",
                    ],
                },
                "ip_transit_settings": {
                    "type": "dict",
                    "routing_protocol_name": {"type": "str", "choices": ["BGP"]},
                    "autonomous_system_number": {"type": "int"},
                },
                "sda_transit_settings": {
                    "type": "dict",
                    "is_multicast_over_transit_enabled": {"type": "bool"},
                    "control_plane_network_device_ips": {
                        "type": "list",
                        "elements": "str",
                    },
                },
            }
        }

        # Validate playbook params against the specification (temp_spec)
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)
        if invalid_params:
            self.msg = "Invalid parameters in playbook: {invalid_params}".format(
                invalid_params="\n".join(invalid_params)
            )
            self.status = "failed"
            return self

        self.validated_config = valid_temp
        self.log(
            "Successfully validated playbook config params: {valid_temp}".format(
                valid_temp=valid_temp
            ),
            "INFO",
        )
        self.msg = "Successfully validated input from the playbook."
        self.status = "success"
        return self

    def requires_update(self, have, want, obj_params):
        """
        Check if the config given requires update by comparing
        current information with the requested information.

        This method compares the current fabric transits from Cisco Catalyst Center
        with the user-provided details from the playbook,
        using a specified schema for comparison.

        Parameters:
            have (dict): Current information from the Cisco Catalyst Center
                          of SDA fabric transits.
            want (dict): Users provided information from the playbook
            obj_params (list of tuples) - A list of parameter mappings specifying which
                                          Cisco Catalyst Center parameters (dnac_param) correspond to
                                          the user-provided parameters (ansible_param).
        Returns:
            bool - True if any parameter specified in obj_params differs between
            current_obj and requested_obj, indicating that an update is required.
            False if all specified parameters are equal.
        Description:
            This function checks both the information provided by the user and
            the information available in the Cisco Catalyst Center.
            Based on the object_params the comparison will be taken place.
            If there is a difference in those information, it will return True.
            Else False.
        """

        current_obj = have
        requested_obj = want
        self.log(
            "Current State (have): {current_obj}".format(current_obj=current_obj),
            "DEBUG",
        )
        self.log(
            "Desired State (want): {requested_obj}".format(requested_obj=requested_obj),
            "DEBUG",
        )

        return any(
            not dnac_compare_equality(
                current_obj.get(dnac_param), requested_obj.get(ansible_param)
            )
            for (dnac_param, ansible_param) in obj_params
        )

    def get_obj_params(self, get_object):
        """
        Get the required comparison obj_params value

        Parameters:
            get_object (str): identifier for the required obj_params
        Returns:
            obj_params (list): obj_params value for comparison.
        Description:
            This function gets the object for the requires_update function.
            The obj_params will have the pattern to be compared.
        """

        try:
            if get_object == "fabricTransits":
                obj_params = [
                    ("isMulticastOverTransitEnabled", "isMulticastOverTransitEnabled"),
                    ("controlPlaneNetworkDeviceIds", "controlPlaneNetworkDeviceIds"),
                ]
            else:
                raise ValueError(
                    "Received an unexpected value for 'get_object': {object_name}".format(
                        object_name=get_object
                    )
                )
        except Exception as msg:
            self.log("Received exception: {msg}".format(msg=msg), "CRITICAL")

        return obj_params

    def get_device_details_by_ip(self, device_ip):
        """
        Get the network device details from the IP address.

        Parameters:
            device_ip (str): Playbook fabric transits details containing name,
            type, IP transits and SDA transits details.
        Returns:
            device_details (dict or None): The network device details with the given IP address.
        Description:
            This function calls the API to get the devices list based on the IP address.
            Returns the network device details.
        """

        response = self.dnac._exec(
            family="devices",
            function="get_device_list",
            op_modifies=True,
            params={"management_ip_address": device_ip},
        )
        if not isinstance(response, dict):
            self.log(
                "Failed to retrieve the Authentication and Policy Server details - "
                "Response is not a dictionary",
                "CRITICAL",
            )
            return None

        device_details = response.get("response")
        if device_details:
            self.log(
                "Successfully retrieved device details for IP " + str(device_ip), "INFO"
            )
        else:
            self.log("No device details found for IP " + str(device_ip), "WARNING")

        return device_details

    def format_fabric_transit_params(self, fabric_transit_details):
        """
        Process the fabric transit parameters retrieved from the Cisco Catalyst Center

        Parameters:
            fabric_transit_details (dict): The fabric transit details from the Cisco Catalyst Center
        Returns:
            fabric_transit_info (dict): Processed fabric transit data in a format
            suitable for Cisco Catalyst Center configuration.
        Description:
            Formats the information with respect to the API payload.
        """

        fabric_transit_info = {
            "name": fabric_transit_details.get("name"),
            "type": fabric_transit_details.get("type"),
            "siteId": fabric_transit_details.get("siteId"),
        }
        ip_transit_settings = fabric_transit_details.get("ipTransitSettings")
        if ip_transit_settings:
            self.log("IP Transit settings found and processed.", "INFO")
            fabric_transit_info.update({"ipTransitSettings": ip_transit_settings})
            return fabric_transit_info

        sda_transit_settings = fabric_transit_details.get("sdaTransitSettings")
        fabric_transit_info.update({"sdaTransitSettings": sda_transit_settings})
        control_plane_devices = fabric_transit_info.get("sdaTransitSettings").get(
            "controlPlaneNetworkDeviceIds"
        )
        if control_plane_devices:
            sorted(control_plane_devices)

        return fabric_transit_info

    def fabric_transit_exists(self, name):
        """
        Check if the SDA fabric transit with the given name exists

        Parameters:
            name (str): The name of the fabric transit to check for existence.
        Returns:
            dict - A dictionary containing information about the
                   SDA fabric transit's existence:
                - 'exists' (bool): True if the fabric transit exists, False otherwise.
                - 'id' (str or None): The ID of the fabric transit if it exists or None if it doesn't.
                - 'details' (dict or None): Details of the fabric transit if it exists else None.
        Description:
            Sets the existance, details and the id of the fabric tranist as None.
            Calls the API 'get_transit_networks' until the transit is found or there are
            no more transits available in the Cisco Catalyst Center.
            If the transit is not found, the offset is incremented by 500, as the API returns
            a maximum of 500 entries at a time.
        """

        transit_info = {"exists": False, "details": None, "id": None}
        offset = 1
        while True:
            response = self.dnac._exec(
                family="sda",
                function="get_transit_networks",
                op_modifies=True,
                params={
                    "name": name,
                    "offset": offset
                },
            )
            if not isinstance(response, dict):
                self.msg = (
                    "Error in getting fabric transits - Response is not a dictionary"
                )
                self.log(self.msg, "ERROR")
                self.status = "exited"
                return self.check_return_status()

            all_fabric_transit_details = response.get("response")
            if not all_fabric_transit_details:
                self.log(
                    "Fabric transit {name} does not exist.".format(name=name), "DEBUG"
                )
                return transit_info

            fabric_transit_details = get_dict_result(
                all_fabric_transit_details, "name", name
            )
            if fabric_transit_details:
                self.log(
                    "Fabric transit found with name '{name}': {details}".format(
                        name=name, details=fabric_transit_details
                    ),
                    "INFO",
                )
                transit_info.update(
                    {
                        "exists": True,
                        "id": fabric_transit_details.get("id"),
                        "details": self.format_fabric_transit_params(
                            fabric_transit_details
                        ),
                    }
                )
                break

            offset += 500

        self.log(
            "SDA fabric transit details: {details}".format(
                details=transit_info.get("details")
            ),
            "DEBUG",
        )
        self.log(
            "SDA fabric transit id: {id}".format(id=transit_info.get("id")), "DEBUG"
        )
        return transit_info

    def get_have_fabric_transits(self, fabric_transits):
        """
        Get the SDA fabric transits related information from Cisco
        Catalyst Center based on the provided playbook details.

        Parameters:
            fabric_transits (dict): Playbook details containing fabric transits details.
        Returns:
            self: The current object with updated current Fabric Transits information.
        Description:
            Sets the existance, details and the id of the fabric tranist as None.
            If the name is not available, return with a msg by setting the
            self.status as 'failed' and return self.
            Call a function which checks the existence of the fabric transit.
        """

        fabric_transits_details = []
        for item in fabric_transits:
            transit_info = {"exists": False, "details": None, "id": None}
            name = item.get("name")
            if not name:
                self.msg = (
                    "The required parameter 'name' in 'sda_fabric_transits' is missing."
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            transit_info = self.fabric_transit_exists(name)
            self.log(
                "SDA transit transit exists for '{name}': {exists}".format(
                    name=name, exists=transit_info.get("exists")
                ),
                "DEBUG",
            )
            self.log(
                "SDA transit transit details for '{name}': {details}".format(
                    name=name, details=transit_info.get("details")
                ),
                "DEBUG",
            )
            self.log(
                "SDA transit transit Id for '{name}': {id}".format(
                    name=name, id=transit_info.get("id")
                ),
                "DEBUG",
            )
            fabric_transits_details.append(transit_info)

        self.have.update({"fabric_transits": fabric_transits_details})
        self.msg = (
            "Collecting the SDA fabric transits details from the Cisco Catalyst Center."
        )
        self.status = "success"
        return self

    def get_have(self, config):
        """
        Get the SDA fabric transits related information from Cisco Catalyst Center

        Parameters:
            config (dict): Playbook details containing fabric transits details.
        Returns:
            self: The current object with updated fabric transits details.
        Description:
            Check the fabric_transits. If the name is not available, return with a msg by setting the
            self.status as 'failed' and return self.
            Call the 'get_have_fabric_transits' function to collect the information
            about the fabric transit in the Cisco Catalyst Center.
        """

        fabric_transits = config.get("sda_fabric_transits")
        if not fabric_transits:
            self.msg = (
                "The parameter 'sda_fabric_transits' is missing under the 'config'."
            )
            self.status = "failed"
            return self

        self.get_have_fabric_transits(fabric_transits).check_return_status()

        self.log(
            "Current State (have): {current_state}".format(current_state=self.have),
            "INFO",
        )
        self.msg = "Successfully retrieved the SDA fabric transits details from the Cisco Catalyst Center."
        self.status = "success"
        return self

    def handle_ip_transit_settings(
        self, item, fabric_transits_values, fabric_transit_index
    ):
        """
        Handle the IP transit setting details.

        Parameters:
            item (dict): Playbook details containing fabric transits details.
            fabric_transits_values (dict): Partially stored fabric transit details.
            fabric_transit_index (int): Index which point the item in the fabric transit item in the config.
        Returns:
            fabric_transits_values (dict): Complete fabric transit details.
        Description:
            Check the basic cases and limits for all the parameters present in the SDA Fabric Transits.
        """

        fabric_transits_values.update({"ipTransitSettings": {}})
        ip_transit_settings = fabric_transits_values.get("ipTransitSettings")
        want_ip_transit_settings = item.get("ip_transit_settings")
        if not want_ip_transit_settings:
            self.msg = "The 'ip_transit_settings' is mandatory when the 'transit_type' is set to 'IP_BASED_TRANSIT'."
            self.status = "failed"
            return self.check_return_status()

        routing_protocol_name = item.get("ip_transit_settings").get(
            "routing_protocol_name"
        )
        routing_protocol_name_set = "BGP"
        if not routing_protocol_name:
            routing_protocol_name = "BGP"

        if routing_protocol_name not in routing_protocol_name_set:
            self.msg = "The 'routing_protocol_name' under 'ip_transit_settings' should be in the list: {routing_protocol_name_set}".format(
                routing_protocol_name_set=routing_protocol_name_set
            )
            self.status = "failed"
            return self.check_return_status()

        ip_transit_settings.update({"routingProtocolName": routing_protocol_name})
        have_fabric_transit_details = self.have.get("fabric_transits")[
            fabric_transit_index
        ].get("details")
        have_ip_transit_settings = None
        if have_fabric_transit_details:
            have_ip_transit_settings = (
                self.have.get("fabric_transits")[fabric_transit_index]
                .get("details")
                .get("ipTransitSettings")
            )

        autonomous_system_number = item.get("ip_transit_settings").get(
            "autonomous_system_number"
        )
        if autonomous_system_number is None:
            self.msg = "The required parameter 'autonomous_system_number' in 'ip_transit_settings' is missing."
            self.status = "failed"
            return self.check_return_status()

        try:
            autonomous_system_number_int = int(autonomous_system_number)
            if not 1 <= autonomous_system_number_int <= 4294967295:
                self.msg = (
                    "The 'autonomous_system_number' should be from 1 to 4294967295."
                )
                self.status = "failed"
                return self.check_return_status()
        except ValueError:
            self.msg = "The 'autonomous_system_number' should contain only digits 0-9."
            self.status = "failed"
            return self.check_return_status()

        if have_ip_transit_settings:
            have_autonomous_system_number = (
                self.have.get("fabric_transits")[fabric_transit_index]
                .get("details")
                .get("ipTransitSettings")
                .get("autonomousSystemNumber")
            )
            if not autonomous_system_number:
                autonomous_system_number = have_autonomous_system_number
            elif have_autonomous_system_number != str(autonomous_system_number):
                self.msg = "The 'autonomous_system_number' in 'ip_transit_settings' cannot be updated."
                self.status = "failed"
                return self.check_return_status()

        ip_transit_settings.update(
            {"autonomousSystemNumber": str(autonomous_system_number)}
        )

        return fabric_transits_values

    def remove_duplicate_ips(self, control_plane_ips):
        """
        Remove the duplicates from the given list.

        Parameters:
            control_plane_ips (list): List of elements which may contain duplicates.
        Returns:
            final_control_plane_ips (list): List of elements with out duplicates.
        Description:
            Return empty list if the list is empty or it is a NoneType. Check whether any
            duplicates is present in the list or not. If yes, remove them and return the list.
        """

        self.log(
            "The list of control plane ips before removing the duplicates {list_of_ips}".format(
                list_of_ips=control_plane_ips
            ),
            "DEBUG",
        )
        final_control_plane_ips = []

        # No need to proceed when there is no elements in the list
        if not control_plane_ips:
            self.log(
                "Received an empty or None list. Returning an empty list.", "DEBUG"
            )
            return final_control_plane_ips

        control_plane_ips = sorted(control_plane_ips)
        self.log("Control plane IPs sorted: {0}".format(control_plane_ips), "DEBUG")
        length_control_plane_ips = len(control_plane_ips)

        # No need to check for the duplicates when there is only one element in the list
        if length_control_plane_ips == 1:
            self.log("Only one IP found, no duplicates to remove.", "DEBUG")
            return control_plane_ips

        final_control_plane_ips.append(control_plane_ips[0])
        for i in range(1, length_control_plane_ips):
            if control_plane_ips[i] != control_plane_ips[i - 1]:
                final_control_plane_ips.append(control_plane_ips[i])

        self.log(
            "The list of control plane IPs after removing the duplicates '{list_of_ips}'".format(
                list_of_ips=final_control_plane_ips
            ),
            "DEBUG",
        )

        return final_control_plane_ips

    def handle_sda_transit_settings(
        self, item, fabric_transits_values, transit_type, fabric_transit_index
    ):
        """
        Handle the SDA transit settings details.

        Parameters:
            item (dict): Playbook details containing fabric transits details.
            fabric_transits_values (dict): Partially stored fabric transit details.
            transit_type (str): Type of the fabric transit.
            fabric_transit_index (int): Index which point the item in the fabric transit item in the config.
        Returns:
            fabric_transits_values (dict): Complete fabric transit details.
        Description:
            Check the basic cases and limits for all the parameters present in the SDA Fabric Transits.
        """

        fabric_transits_values.update({"sdaTransitSettings": {}})
        have_sda_transit_settings = None
        have_fabric_details = self.have.get("fabric_transits")[
            fabric_transit_index
        ].get("details")
        if have_fabric_details:
            have_sda_transit_settings = have_fabric_details.get("sdaTransitSettings")

        sda_transit_settings = fabric_transits_values.get("sdaTransitSettings")
        want_sda_transit_settings = item.get("sda_transit_settings")
        if want_sda_transit_settings:
            if transit_type == "SDA_LISP_PUB_SUB_TRANSIT":
                is_multicast_over_transit_enabled = item.get(
                    "sda_transit_settings"
                ).get("is_multicast_over_transit_enabled")
                if is_multicast_over_transit_enabled is not None:
                    sda_transit_settings.update(
                        {
                            "isMulticastOverTransitEnabled": is_multicast_over_transit_enabled
                        }
                    )
                elif have_sda_transit_settings:
                    sda_transit_settings.update(
                        {
                            "isMulticastOverTransitEnabled": have_sda_transit_settings.get(
                                "isMulticastOverTransitEnabled"
                            )
                        }
                    )
                else:
                    sda_transit_settings.update(
                        {"isMulticastOverTransitEnabled": False}
                    )

            control_plane_network_device_ips = self.remove_duplicate_ips(
                want_sda_transit_settings.get("control_plane_network_device_ips")
            )
            if have_sda_transit_settings and not control_plane_network_device_ips:
                sda_transit_settings.update(
                    {
                        "controlPlaneNetworkDeviceIds": sorted(
                            have_sda_transit_settings.get(
                                "controlPlaneNetworkDeviceIds"
                            )
                        )
                    }
                )
            elif control_plane_network_device_ips:
                length_of_control_plane_network_device_ips = len(
                    control_plane_network_device_ips
                )
                if transit_type == "SDA_LISP_BGP_TRANSIT":
                    max_ips = 2
                else:
                    max_ips = 4
                if (
                    transit_type == "SDA_LISP_BGP_TRANSIT"
                    and length_of_control_plane_network_device_ips > max_ips
                ):
                    self.msg = "The 'control_plane_network_device_ips' should have a maximum of 2 IPs when the 'transit_type' is 'SDA_LISP_BGP_TRANSIT'."
                    self.status = "failed"
                    return self.check_return_status()
                elif (
                    transit_type == "SDA_LISP_PUB_SUB_TRANSIT"
                    and length_of_control_plane_network_device_ips > max_ips
                ):
                    self.msg = "The 'control_plane_network_device_ips' should have a maximum of 4 IPs when the 'transit_type' is 'SDA_LISP_PUB_SUB_TRANSIT'."
                    self.status = "failed"
                    return self.check_return_status()

                control_plane_network_device_ids = []
                for network_device_ip in control_plane_network_device_ips:
                    network_device_details = self.get_device_details_by_ip(
                        network_device_ip
                    )
                    if not network_device_details:
                        self.msg = "There is no network device in the Cisco Catalyst Center with the IP '{device_ip}'.".format(
                            device_ip=network_device_ip
                        )
                        self.status = "failed"
                        return self.check_return_status()

                    network_device_id = network_device_details[0].get("instanceUuid")
                    control_plane_network_device_ids.append(network_device_id)
                sda_transit_settings.update(
                    {
                        "controlPlaneNetworkDeviceIds": sorted(
                            control_plane_network_device_ids
                        )
                    }
                )
            else:
                self.msg = "The parameter 'control_plane_network_device_ips' in 'sda_transit_settings' should not be empty."
                self.status = "failed"
                return self.check_return_status()

        elif have_sda_transit_settings and not want_sda_transit_settings:
            fabric_transits_values.update(
                {"sdaTransitSettings": have_sda_transit_settings}
            )
            sorted(
                fabric_transits_values.get("sdaTransitSettings").get(
                    "controlPlaneNetworkDeviceIds"
                )
            )
        else:
            self.msg = "The parameter 'sda_transit_settings' should not be empty."
            self.status = "failed"
            return self.check_return_status()

        return fabric_transits_values

    def get_want_fabric_transits(self, fabric_transits):
        """
        Get all the SDA fabric transits information from playbook
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            fabric_transits (dict): Playbook fabric transits details containing name,
            transit_type, IP transits and SDA transits details.
        Returns:
            self: The current object with updated desired Fabric Transits information.
        Description:
            Do all the validation which is done in the GUI and format the payload
            in such a way that we can pass it to the API.
            If any of the validation fails, return with a msg by setting the
            self.status as 'failed' and return self.
        """

        want_fabric_transits = []
        fabric_transit_index = 0
        for item in fabric_transits:
            fabric_transits_values = {}
            name = item.get("name")
            if not name:
                self.msg = (
                    "The required parameter 'name' in 'sda_fabric_transits' is missing."
                )
                self.status = "failed"
                return self

            if len(name) > 32:
                self.msg = "The length of the 'name' in 'sda_fabric_transits' should be less or equal to 32."
                self.status = "failed"
                return self

            fabric_transits_values.update({"name": name})
            state = self.params.get("state")
            if state == "deleted":
                want_fabric_transits.append(fabric_transits_values)
                fabric_transit_index += 1
                continue

            transit_type = item.get("transit_type")
            transit_type_set = (
                "IP_BASED_TRANSIT",
                "SDA_LISP_PUB_SUB_TRANSIT",
                "SDA_LISP_BGP_TRANSIT",
            )
            have_type = None
            fabric_transit_details = self.have.get("fabric_transits")[
                fabric_transit_index
            ].get("details")
            if fabric_transit_details:
                have_type = fabric_transit_details.get("type")

            if not transit_type:
                if have_type:
                    transit_type = have_type
                else:
                    transit_type = "IP_BASED_TRANSIT"

            if transit_type not in transit_type_set:
                self.msg = "The 'transit_type' under 'sda_fabric_transits' should be in the list: {transit_types}".format(
                    transit_types=transit_type_set
                )
                self.status = "failed"
                return self

            if have_type and transit_type != have_type:
                self.msg = "The parameter 'transit_type' under the SDA fabric transit '{name}' cannot be updated.".format(
                    name=name
                )
                self.status = "failed"
                return self

            fabric_transits_values.update({"type": transit_type})
            if transit_type == "IP_BASED_TRANSIT":
                fabric_transits_values = copy.deepcopy(
                    self.handle_ip_transit_settings(
                        item, fabric_transits_values, fabric_transit_index
                    )
                )
            else:
                fabric_transits_values = copy.deepcopy(
                    self.handle_sda_transit_settings(
                        item, fabric_transits_values, transit_type, fabric_transit_index
                    )
                )

            want_fabric_transits.append(fabric_transits_values)
            fabric_transit_index += 1

        self.log(
            "SDA fabric transits playbook details: {requested_state}".format(
                requested_state=want_fabric_transits
            ),
            "DEBUG",
        )
        self.want.update({"fabric_transits": want_fabric_transits})
        self.msg = "Collecting the SDA fabric transits details from the playbook"
        self.status = "success"
        return self

    def get_want(self, config):
        """
        Get the SDA fabric transits related information from playbook.

        Parameters:
            config (list of dict): Playbook details
        Returns:
            self: The current object with updated fabric transits details.
        Description:
            Check the fabric_transits. If the name is not available, return with a msg by setting the
            self.status as 'failed' and return self.
            Call the 'get_want_fabric_transits' function to collect the information
            about the fabric transit passed by the user.
        """

        fabric_transits = config.get("sda_fabric_transits")
        if not fabric_transits:
            self.msg = (
                "The parameter 'sda_fabric_transits' is missing under the 'config'."
            )
            self.status = "failed"
            return self

        self.get_want_fabric_transits(fabric_transits).check_return_status()

        self.log(
            "Desired State (want): {requested_state}".format(requested_state=self.want),
            "INFO",
        )
        self.msg = "Successfully retrieved details from the playbook"
        self.status = "success"
        return self

    def fabric_transit_need_update(self, want_fabric_transit, have_fabric_transit):
        """
        Check if the SDA fabric transit requires an update.
        Parameters:
            want_fabric_transit (dict): Desired fabric transit details from the playbook.
            have_fabric_transit (dict): Current fabric transit details from Cisco Catalyst Center.
        Returns:
            bool: True if the fabric transit requires an update, False otherwise.
        Description:
            This function checks if the fabric transit requires an update by comparing
            the current details with the desired details.
            IP_BASED_TRANSIT types are not updatable,
            so the function returns False for these transit types. For SDA transit types,
            it compares the sdaTransitSettings using the requires_update method with
            predefined object parameters for fabric transits.
        """

        self.log("Initiating fabric transit update requirement evaluation", "DEBUG")
        name = want_fabric_transit.get("name")
        if not name:
            self.log("Fabric transit name is missing from desired configuration - cannot evaluate update requirement", "ERROR")
            return False

        transit_type = want_fabric_transit.get("type")
        current_details = have_fabric_transit.get("details")

        self.log("Evaluating update requirement for fabric transit '{0}' with type '{1}'".format(name, transit_type), "DEBUG")
        if not current_details:
            self.log("No current fabric transit details found for '{0}' - update evaluation not possible".format(name), "WARNING")
            return False

        # IP_BASED_TRANSIT cannot be updated
        if transit_type == "IP_BASED_TRANSIT":
            self.log("Fabric transit '{0}' is of type 'IP_BASED_TRANSIT' - updates are not supported for this transit type".format(name), "INFO")
            return False

        # For SDA transit types, compare sdaTransitSettings
        current_sda_settings = current_details.get("sdaTransitSettings")
        desired_sda_settings = want_fabric_transit.get("sdaTransitSettings")

        if not current_sda_settings and not desired_sda_settings:
            self.log("Both current and desired SDA transit settings are empty for '{0}' - no update required".format(name), "DEBUG")
            return False

        if not current_sda_settings:
            self.log("Current SDA transit settings are missing for '{0}' but desired settings exist - update required".format(name), "INFO")
            return True

        if not desired_sda_settings:
            self.log(
                "Desired SDA transit settings are missing for '{0}' but current settings exist"
                " - using current settings, no update required".format(name),
                "DEBUG"
            )
            return False

        self.log("Comparing current SDA transit settings with desired settings for '{0}'".format(name), "DEBUG")
        self.log("Current SDA settings: {0}".format(self.pprint(current_sda_settings)), "DEBUG")
        self.log("Desired SDA settings: {0}".format(self.pprint(desired_sda_settings)), "DEBUG")

        update_required = self.requires_update(
            current_sda_settings,
            desired_sda_settings,
            self.fabric_transits_obj_params
        )

        if update_required:
            self.log("Fabric transit '{0}' requires an update - differences found between current and desired SDA transit settings".format(name), "INFO")
            return True

        self.log("Fabric transit '{0}' does not require an update - current and desired SDA transit settings are equivalent".format(name), "INFO")

        return False

    def update_fabric_transits(self, fabric_transits):
        """
        Create/Update fabric transit in Cisco Catalyst Center with fields provided in playbook.

        Parameters:
            fabric_transits (list of dict): SDA fabric transit playbook details.
        Returns:
            self (object): The current object with updated desired Fabric Transits information.
        Description:
            This function processes SDA fabric transit configurations for creation or update operations.
            It checks fabric transit existence in Cisco Catalyst Center and performs appropriate actions.
            For new transits, it creates them using 'add_transit_networks' API. For existing transits,
            it evaluates update requirements including site hierarchy changes (supported from version 3.1.3.0)
            and applies updates using 'update_transit_networks' API. The function handles version-specific
            features like site hierarchy assignment and ensures proper error handling throughout the workflow.
        """

        fabric_transit_index = -1
        for item in fabric_transits:
            fabric_transit_index += 1
            name = item.get("name")
            result_fabric_transit = self.response[0].get("fabric_transits")
            have_fabric_transit = self.have.get("fabric_transits")[fabric_transit_index]
            want_fabric_transit = self.want.get("fabric_transits")[fabric_transit_index]
            self.log(
                "Current SDA fabric transit '{name}' details in Catalyst Center: {current_details}".format(
                    name=name, current_details=have_fabric_transit.get("details")
                ),
                "DEBUG",
            )
            self.log(
                "Desired SDA fabric transit '{name}' details for Catalyst Center: {requested_details}".format(
                    name=name, requested_details=want_fabric_transit
                ),
                "DEBUG",
            )

            # Check transit exists, if not create and continue
            if not have_fabric_transit.get("exists"):
                self.log(
                    "Desired fabric transit '{name}' details (want): {requested_state}".format(
                        name=name, requested_state=want_fabric_transit
                    ),
                    "DEBUG",
                )
                self.log("Initiating SDA fabric transit creation and update workflow processing", "DEBUG")
                current_version = self.get_ccc_version()
                if self.compare_dnac_versions(current_version, "3.1.3.0") >= 0:
                    transit_site_hierarchy = item.get("transit_site_hierarchy")
                    if transit_site_hierarchy:
                        self.log("Processing site name hierarchy '{0}' for fabric transit '{1}'".format(transit_site_hierarchy, name), "DEBUG")
                        site_exists, site_id = self.get_site_id(transit_site_hierarchy)
                        if site_exists:
                            self.log(
                                "Successfully resolved site ID '{0}' for site hierarchy '{1}' in fabric transit '{2}'"
                                .format(
                                    site_id, transit_site_hierarchy, name
                                ),
                                "INFO"
                            )
                            want_fabric_transit["siteId"] = site_id
                        else:
                            self.log("No site with name '{0}' found in the Cisco Catalyst Center.".format(transit_site_hierarchy), "ERROR")

                self.log("Creating new SDA fabric transit '{0}' with configuration: {1}".format(name, want_fabric_transit), "DEBUG")
                payload = {"payload": [want_fabric_transit]}
                task_name = "add_transit_networks"
                task_id = self.get_taskid_post_api_call("sda", task_name, payload)
                if not task_id:
                    self.msg = "Unable to retrive the task_id for the task '{task_name}'.".format(
                        task_name=task_name
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "Successfully created the SDA Transit with the details '{transit_details}'.".format(
                    transit_details=want_fabric_transit
                )
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()
                self.log(
                    "Successfully created SDA fabric transit '{name}'.".format(
                        name=name
                    ),
                    "INFO",
                )
                result_fabric_transit.get("response").update(
                    {name: want_fabric_transit}
                )
                result_fabric_transit.get("msg").update(
                    {name: "SDA fabric transit created successfully"}
                )
                continue

            # Handle fabric transit update evaluation
            self.log("SDA fabric transit '{0}' exists - evaluating update requirements".format(name), "DEBUG")
            transit_need_update = self.fabric_transit_need_update(want_fabric_transit, have_fabric_transit)
            site_id = None
            if not transit_need_update:
                current_version = self.get_ccc_version()
                if self.compare_dnac_versions(current_version, "3.1.3.0") >= 0:
                    self.log(
                        "Evaluating site hierarchy changes for fabric transit '{0}' (version {1} supports"
                        " site hierarchy)".format(name, current_version), "DEBUG"
                    )
                    transit_site_hierarchy = item.get("transit_site_hierarchy")
                    if not transit_site_hierarchy:
                        self.log(
                            "SDA fabric transit '{name}' doesn't require a update".format(
                                name=name
                            ),
                            "INFO",
                        )
                        result_fabric_transit.get("msg").update(
                            {name: f"SDA fabric transit '{name}' doesn't require an update."}
                        )
                        continue

                    self.log("Processing site hierarchy '{0}' for existing fabric transit '{1}'".format(transit_site_hierarchy, name), "DEBUG")
                    site_exists, site_id = self.get_site_id(transit_site_hierarchy)
                    if not site_exists:
                        self.msg = (
                            "Failed to resolve site ID for site hierarchy '{0}' in fabric transit '{1}'. "
                            "Verify site exists in Cisco Catalyst Center."
                            .format(transit_site_hierarchy, name)
                        )
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()

                    self.log(
                        "Site ID '{0}' retrieved for site name '{1}'.".format(
                            site_id, transit_site_hierarchy
                        ),
                        "DEBUG",
                    )
                    current_site_id = have_fabric_transit.get("details").get("siteId")
                    if current_site_id and current_site_id == site_id:
                        self.log(
                            "Site ID '{0}' for fabric transit '{1}' matches current assignment - no site "
                            "change required".format(site_id, name),
                            "DEBUG"
                        )
                        self.log(
                            "SDA fabric transit '{name}' doesn't require a update".format(
                                name=name
                            ),
                            "INFO",
                        )
                        result_fabric_transit.get("msg").update(
                            {name: f"SDA fabric transit '{name}' doesn't require an update."}
                        )
                        continue
                    else:
                        self.log(
                            "Site ID change detected for fabric transit '{0}': current='{1}', desired='{2}' "
                            "- update required".format(name, current_site_id, site_id),
                            "INFO"
                        )
                else:
                    self.log(
                        "SDA fabric transit '{name}' doesn't require a update".format(
                            name=name
                        ),
                        "INFO",
                    )
                    result_fabric_transit.get("msg").update(
                        {name: f"SDA fabric transit '{name}' doesn't require an update."}
                    )
                    continue

            payload_site_id = site_id or have_fabric_transit.get("details").get("siteId")
            if payload_site_id:
                want_fabric_transit.update({"siteId": payload_site_id})

            # Tranist Exists
            self.log(
                "Current SDA fabric transit '{name}' details in Catalyst Center: {current_state}".format(
                    name=name, current_state=have_fabric_transit
                ),
                "DEBUG",
            )
            self.log(
                "Desired SDA fabric transit '{name}' details: {requested_state}".format(
                    name=name, requested_state=want_fabric_transit
                ),
                "DEBUG",
            )
            want_fabric_transit.update({"id": have_fabric_transit.get("id")})
            payload = {"payload": [want_fabric_transit]}
            task_name = "update_transit_networks"
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)
            if not task_id:
                self.msg = (
                    "Unable to retrive the task_id for the task '{task_name}'.".format(
                        task_name=task_name
                    )
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Successfully updated the SDA Transit with the details '{transit_details}'.".format(
                transit_details=want_fabric_transit
            )
            self.get_task_status_from_tasks_by_id(
                task_id, task_name, success_msg
            ).check_return_status()
            self.log(
                "SDA fabric transit '{name}' updated successfully.".format(name=name),
                "INFO",
            )
            result_fabric_transit.get("response").update({name: want_fabric_transit})
            result_fabric_transit.get("msg").update(
                {name: "SDA fabric transit updated successfully."}
            )

        self.log("Updated the SDA fabric transits successfully", "INFO")
        return self

    def get_diff_merged(self, config):
        """
        Create or Update the SDA fabric transits in Cisco Catalyst Center based on the playbook details.

        Parameters:
            config (list of dict): Playbook details containing SDA fabric transits information.
        Returns:
            self (object): The current object with updated desired Fabric Transits information.
        Description:
            If the 'sda_fabric_transits' is available in the playbook, call the function 'update_fabric_transits'.
            Else return self.
        """

        fabric_transits = config.get("sda_fabric_transits")
        if fabric_transits is not None:
            self.update_fabric_transits(fabric_transits)

        self.result.update({"response": self.response})
        return self

    def delete_fabric_transits(self, fabric_transits):
        """
        Delete fabric transit in Cisco Catalyst Center with fields provided in playbook.

        Parameters:
            fabric_transits (list of dict): SDA fabric transit playbook details.
        Returns:
            self (object): The current object with updated desired Fabric Transits information.
        Description:
            Check if the fabric transit is present in the Cisco Catalys Center or not.
            If not, set the result and return self.
            Or Call the API 'delete_transit_network_by_id' to delete the transit.
            Update the result and return self.
        """

        fabric_transit_index = -1
        for item in fabric_transits:
            fabric_transit_index += 1
            name = item.get("name")
            have_fabric_transit = self.have.get("fabric_transits")[fabric_transit_index]
            result_fabric_transit = self.response[0].get("fabric_transits")

            if not have_fabric_transit.get("exists"):
                result_fabric_transit.get("msg").update(
                    {name: "SDA fabric transit not found."}
                )
                self.log(
                    "SDA fabric transit '{name}' not found".format(name=name), "INFO"
                )
                continue

            self.log(
                "SDA fabric transit scheduled for deletion with the name '{name}'.".format(
                    name=name
                ),
                "INFO",
            )
            transit_id = have_fabric_transit.get("id")
            self.log(
                "SDA fabric transit '{name}' id: {id}".format(name=name, id=transit_id),
                "DEBUG",
            )
            payload = {"id": transit_id}
            task_name = "delete_transit_network_by_id"
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)
            if not task_id:
                self.msg = (
                    "Unable to retrive the task_id for the task '{task_name}'.".format(
                        task_name=task_name
                    )
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Successfully deleted the SDA Transit with id '{id}'.".format(
                id=transit_id
            )
            self.get_task_status_from_tasks_by_id(
                task_id, task_name, success_msg
            ).check_return_status()
            result_fabric_transit.get("response").update({name: {}})
            result_fabric_transit.get("response").get(name).update({"Task Id": task_id})
            result_fabric_transit.get("msg").update(
                {name: "SDA fabric transit deleted successfully"}
            )

        self.msg = "SDA fabric transit(s) deleted successfully."
        self.status = "success"
        return self

    def get_diff_deleted(self, config):
        """
        Delete the SDA fabric transits in Cisco Catalyst Center based on the playbook details.

        Parameters:
            config (list of dict): Playbook details containing SDA fabric transits information.
        Returns:
            self (object): The current object with updated desired Fabric Transits information.
        Description:
            If the 'sda_fabric_transits' is available in the playbook, call the function 'delete_fabric_transits'.
            Else return self.
        """

        fabric_transits = config.get("sda_fabric_transits")
        if fabric_transits is not None:
            self.delete_fabric_transits(fabric_transits)

        self.result.update({"response": self.response})
        return self

    def verify_diff_merged(self, config):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is merged (Create/Update).

        Parameters:
            config (dict): Playbook details containing fabric transit configuration.
        Returns:
            self (object): The current object with updated desired Fabric Transits information.
        Description:
            If the 'sda_fabric_transits' is available in the playbook, collect the fabric transit information
            from the Cisco Catalyst Center.
            Check if there is any differece between the config passed by the user and the informaion
            collected by the user.
            If there is any differece set the msg by settings the self.status as 'failed' and return self.
        """

        self.get_have(config)
        self.log(
            "Current State (have): {current_state}".format(current_state=self.have),
            "INFO",
        )
        self.log(
            "Requested State (want): {requested_state}".format(
                requested_state=self.want
            ),
            "INFO",
        )
        if config.get("sda_fabric_transits") is not None:
            want_fabric_transits = self.want.get("fabric_transits")
            have_fabric_transits = self.have.get("fabric_transits")
            self.log(
                "Current State of SDA fabric transits (have): {current_details}".format(
                    current_details=have_fabric_transits
                ),
                "DEBUG",
            )
            self.log(
                "Desired State of SDA fabric transits (want): {requested_details}".format(
                    requested_details=want_fabric_transits
                ),
                "DEBUG",
            )
            fabric_transit_index = 0
            for item in want_fabric_transits:
                fabric_transit_details = have_fabric_transits[fabric_transit_index].get(
                    "details"
                )
                if not fabric_transit_details:
                    self.msg = "The SDA fabric transit config is not created with the config: {config}".format(
                        config=item
                    )
                    self.status = "failed"
                    return self

                if fabric_transit_details.get("type") == "IP_BASED_TRANSIT":
                    fabric_transit_index += 1
                    continue

                self.log(
                    "Current SDA Transit Settings: "
                    + str(fabric_transit_details.get("sdaTransitSettings"))
                )
                self.log(
                    "Desired SDA Transit Settings: "
                    + str(item.get("sdaTransitSettings"))
                )
                if self.requires_update(
                    fabric_transit_details.get("sdaTransitSettings"),
                    item.get("sdaTransitSettings"),
                    self.fabric_transits_obj_params,
                ):
                    self.msg = "The SDA fabric transit config is not applied to the Cisco Catalyst Center."
                    self.status = "failed"
                    return self

                fabric_transit_index += 1

            self.log("Successfully validated SDA fabric transit(s).", "INFO")
            self.response[0].get("fabric_transits").update({"Validation": "Success"})

        self.result.update({"response": self.response})
        self.msg = "Successfully validated the SDA fabric transit(s)."
        self.status = "success"
        return self

    def verify_diff_deleted(self, config):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is deleted (delete).

        Parameters:
            config (dict): Playbook details containing fabric transit configuration.
        Returns:
            self (object): The current object with updated desired Fabric Transits information.
        Description:
            If the 'sda_fabric_transits' is available in the playbook, collect the fabric transit information
            from the Cisco Catalyst Center.
            Check if there is any transit with the name given in the playbook, set the msg by settings the
            self.status as 'failed' and return self.
        """

        self.get_have(config)
        self.log(
            "Current State (have): {current_state}".format(current_state=self.have),
            "INFO",
        )
        self.log(
            "Desired State (want): {requested_state}".format(requested_state=self.want),
            "INFO",
        )
        fabric_transits = config.get("sda_fabric_transits")
        if fabric_transits is not None:
            fabric_transit_index = 0
            fabric_transit_details = self.have.get("fabric_transits")
            for item in fabric_transit_details:
                fabric_transit_exists = item.get("exists")
                name = config.get("sda_fabric_transits")[fabric_transit_index].get(
                    "name"
                )
                if fabric_transit_exists:
                    self.msg = (
                        "The SDA fabric transit config '{name}' is still present in "
                        "the Cisco Catalyst Center.".format(name=name)
                    )
                    self.status = "failed"
                    return self

                self.log(
                    "Successfully validated absence of transit '{name}'.".format(
                        name=name
                    ),
                    "INFO",
                )
                fabric_transit_index += 1
            self.response[0].get("fabric_transits").update({"Validation": "Success"})

        self.result.update({"response": self.response})
        self.msg = "Successfully validated the absence of SDA fabric transit(s)."
        self.status = "success"
        return self

    def reset_values(self):
        """
        Reset all neccessary attributes to default values

        Parameters:
            self (object): The current object details.
        Returns:
            None
        """

        self.have.clear()
        self.want.clear()
        return


def main():
    """main entry point for module execution"""

    # Define the specification for module arguments
    element_spec = {
        "dnac_host": {"type": "str", "required": True},
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
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"type": "list", "required": True, "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
        "validate_response_schema": {"type": "bool", "default": True},
    }

    # Create an AnsibleModule object with argument specifications
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    ccc_sda_transit = FabricTransit(module)
    if (
        ccc_sda_transit.compare_dnac_versions(
            ccc_sda_transit.get_ccc_version(), "2.3.7.6"
        )
        < 0
    ):
        ccc_sda_transit.msg = (
            "The specified version '{0}' does not support the SDA fabric devices feature. Supported versions start from '2.3.7.6' onwards. "
            "Version '2.3.7.6' introduces APIs for creating, updating and deleting the IP and SDA Transits.".format(
                ccc_sda_transit.get_ccc_version()
            )
        )
        ccc_sda_transit.status = "failed"
        ccc_sda_transit.check_return_status()

    state = ccc_sda_transit.params.get("state")
    config_verify = ccc_sda_transit.params.get("config_verify")
    if state not in ccc_sda_transit.supported_states:
        ccc_sda_transit.status = "invalid"
        ccc_sda_transit.msg = "State '{state}' is invalid".format(state=state)
        ccc_sda_transit.check_return_status()

    ccc_sda_transit.validate_input().check_return_status()

    for config in ccc_sda_transit.config:
        ccc_sda_transit.reset_values()
        ccc_sda_transit.get_have(config).check_return_status()
        if state != "deleted":
            ccc_sda_transit.get_want(config).check_return_status()
        ccc_sda_transit.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_sda_transit.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_sda_transit.result)


if __name__ == "__main__":
    main()
