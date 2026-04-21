#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_firmware_upgrades_staged_groups
short_description: Resource module for networks _firmware _upgrades _staged _groups
description:
  - Manage operations create, update and delete of the resource networks _firmware _upgrades _staged _groups.
  - Create a Staged Upgrade Group for a network.
  - Delete a Staged Upgrade Group.
  - Update a Staged Upgrade Group for a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  assignedDevices:
    description: The devices and Switch Stacks assigned to the Group.
    suboptions:
      devices:
        description: Data Array of Devices containing the name and serial.
        elements: dict
        suboptions:
          name:
            description: Name of the device.
            type: str
          serial:
            description: Serial of the device.
            type: str
        type: list
      switchStacks:
        description: Data Array of Switch Stacks containing the name and id.
        elements: dict
        suboptions:
          id:
            description: ID of the Switch Stack.
            type: str
          name:
            description: Name of the Switch Stack.
            type: str
        type: list
    type: dict
  description:
    description: Description of the Staged Upgrade Group. Length must be 1 to 255 characters.
    type: str
  groupId:
    description: GroupId path parameter. Group ID.
    type: str
  isDefault:
    description: Boolean indicating the default Group. Any device that does not have a group explicitly assigned will upgrade with this group.
    type: bool
  name:
    description: Name of the Staged Upgrade Group. Length must be 1 to 255 characters.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks createNetworkFirmwareUpgradesStagedGroup
    description: Complete reference of the createNetworkFirmwareUpgradesStagedGroup API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-firmware-upgrades-staged-group
  - name: Cisco Meraki documentation for networks deleteNetworkFirmwareUpgradesStagedGroup
    description: Complete reference of the deleteNetworkFirmwareUpgradesStagedGroup API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-firmware-upgrades-staged-group
  - name: Cisco Meraki documentation for networks updateNetworkFirmwareUpgradesStagedGroup
    description: Complete reference of the updateNetworkFirmwareUpgradesStagedGroup API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-firmware-upgrades-staged-group
notes:
  - SDK Method used are
    networks.Networks.create_network_firmware_upgrades_staged_group,
    networks.Networks.delete_network_firmware_upgrades_staged_group,
    networks.Networks.update_network_firmware_upgrades_staged_group,
  - Paths used are
    post /networks/{networkId}/firmwareUpgrades/staged/groups,
    delete /networks/{networkId}/firmwareUpgrades/staged/groups/{groupId},
    put /networks/{networkId}/firmwareUpgrades/staged/groups/{groupId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_firmware_upgrades_staged_groups:
    meraki_api_key: "{{ meraki_api_key }}"
    meraki_base_url: "{{ meraki_base_url }}"
    meraki_single_request_timeout: "{{ meraki_single_request_timeout }}"
    meraki_certificate_path: "{{ meraki_certificate_path }}"
    meraki_requests_proxy: "{{ meraki_requests_proxy }}"
    meraki_wait_on_rate_limit: "{{ meraki_wait_on_rate_limit }}"
    meraki_nginx_429_retry_wait_time: "{{ meraki_nginx_429_retry_wait_time }}"
    meraki_action_batch_retry_wait_time: "{{ meraki_action_batch_retry_wait_time }}"
    meraki_retry_4xx_error: "{{ meraki_retry_4xx_error }}"
    meraki_retry_4xx_error_wait_time: "{{ meraki_retry_4xx_error_wait_time }}"
    meraki_maximum_retries: "{{ meraki_maximum_retries }}"
    meraki_output_log: "{{ meraki_output_log }}"
    meraki_log_file_prefix: "{{ meraki_log_file_prefix }}"
    meraki_log_path: "{{ meraki_log_path }}"
    meraki_print_console: "{{ meraki_print_console }}"
    meraki_suppress_logging: "{{ meraki_suppress_logging }}"
    meraki_simulate: "{{ meraki_simulate }}"
    meraki_be_geo_id: "{{ meraki_be_geo_id }}"
    meraki_caller: "{{ meraki_caller }}"
    meraki_use_iterator_for_get_pages: "{{ meraki_use_iterator_for_get_pages }}"
    meraki_inherit_logging_config: "{{ meraki_inherit_logging_config }}"
    state: present
    assignedDevices:
      devices:
        - name: Device Name
          serial: Q234-ABCD-5678
      switchStacks:
        - id: '1234'
          name: Stack Name
    description: The description of the group
    isDefault: false
    name: My Staged Upgrade Group
    networkId: string
- name: Delete by id
  cisco.meraki.networks_firmware_upgrades_staged_groups:
    meraki_api_key: "{{ meraki_api_key }}"
    meraki_base_url: "{{ meraki_base_url }}"
    meraki_single_request_timeout: "{{ meraki_single_request_timeout }}"
    meraki_certificate_path: "{{ meraki_certificate_path }}"
    meraki_requests_proxy: "{{ meraki_requests_proxy }}"
    meraki_wait_on_rate_limit: "{{ meraki_wait_on_rate_limit }}"
    meraki_nginx_429_retry_wait_time: "{{ meraki_nginx_429_retry_wait_time }}"
    meraki_action_batch_retry_wait_time: "{{ meraki_action_batch_retry_wait_time }}"
    meraki_retry_4xx_error: "{{ meraki_retry_4xx_error }}"
    meraki_retry_4xx_error_wait_time: "{{ meraki_retry_4xx_error_wait_time }}"
    meraki_maximum_retries: "{{ meraki_maximum_retries }}"
    meraki_output_log: "{{ meraki_output_log }}"
    meraki_log_file_prefix: "{{ meraki_log_file_prefix }}"
    meraki_log_path: "{{ meraki_log_path }}"
    meraki_print_console: "{{ meraki_print_console }}"
    meraki_suppress_logging: "{{ meraki_suppress_logging }}"
    meraki_simulate: "{{ meraki_simulate }}"
    meraki_be_geo_id: "{{ meraki_be_geo_id }}"
    meraki_caller: "{{ meraki_caller }}"
    meraki_use_iterator_for_get_pages: "{{ meraki_use_iterator_for_get_pages }}"
    meraki_inherit_logging_config: "{{ meraki_inherit_logging_config }}"
    state: absent
    groupId: string
    networkId: string
- name: Update by id
  cisco.meraki.networks_firmware_upgrades_staged_groups:
    meraki_api_key: "{{ meraki_api_key }}"
    meraki_base_url: "{{ meraki_base_url }}"
    meraki_single_request_timeout: "{{ meraki_single_request_timeout }}"
    meraki_certificate_path: "{{ meraki_certificate_path }}"
    meraki_requests_proxy: "{{ meraki_requests_proxy }}"
    meraki_wait_on_rate_limit: "{{ meraki_wait_on_rate_limit }}"
    meraki_nginx_429_retry_wait_time: "{{ meraki_nginx_429_retry_wait_time }}"
    meraki_action_batch_retry_wait_time: "{{ meraki_action_batch_retry_wait_time }}"
    meraki_retry_4xx_error: "{{ meraki_retry_4xx_error }}"
    meraki_retry_4xx_error_wait_time: "{{ meraki_retry_4xx_error_wait_time }}"
    meraki_maximum_retries: "{{ meraki_maximum_retries }}"
    meraki_output_log: "{{ meraki_output_log }}"
    meraki_log_file_prefix: "{{ meraki_log_file_prefix }}"
    meraki_log_path: "{{ meraki_log_path }}"
    meraki_print_console: "{{ meraki_print_console }}"
    meraki_suppress_logging: "{{ meraki_suppress_logging }}"
    meraki_simulate: "{{ meraki_simulate }}"
    meraki_be_geo_id: "{{ meraki_be_geo_id }}"
    meraki_caller: "{{ meraki_caller }}"
    meraki_use_iterator_for_get_pages: "{{ meraki_use_iterator_for_get_pages }}"
    meraki_inherit_logging_config: "{{ meraki_inherit_logging_config }}"
    state: present
    assignedDevices:
      devices:
        - name: Device Name
          serial: Q234-ABCD-5678
      switchStacks:
        - id: '1234'
          name: Stack Name
    description: The description of the group
    groupId: string
    isDefault: false
    name: My Staged Upgrade Group
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "assignedDevices": {
        "devices": [
          {
            "name": "string",
            "serial": "string"
          }
        ],
        "switchStacks": [
          {
            "id": "string",
            "name": "string"
          }
        ]
      },
      "description": "string",
      "groupId": "string",
      "isDefault": true,
      "name": "string"
    }
"""
