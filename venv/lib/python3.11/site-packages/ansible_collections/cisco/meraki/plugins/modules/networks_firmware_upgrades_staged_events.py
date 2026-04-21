#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_firmware_upgrades_staged_events
short_description: Resource module for networks _firmware _upgrades _staged _events
description:
  - Manage operations create and update of the resource networks _firmware _upgrades _staged _events.
  - Create a Staged Upgrade Event for a network.
  - Update the Staged Upgrade Event for a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  products:
    description: Contains firmware upgrade version information.
    suboptions:
      switch:
        description: Version information for the switch network being upgraded.
        suboptions:
          nextUpgrade:
            description: The next upgrade version for the switch network.
            suboptions:
              toVersion:
                description: The version to be updated to for switch devices.
                suboptions:
                  id:
                    description: The version ID.
                    type: str
                type: dict
            type: dict
        type: dict
      switchCatalyst:
        description: Version information for the switch network being upgraded.
        suboptions:
          nextUpgrade:
            description: The next upgrade version for the switch network.
            suboptions:
              toVersion:
                description: The version to be updated to for switch Catalyst devices.
                suboptions:
                  id:
                    description: The version ID.
                    type: str
                type: dict
            type: dict
        type: dict
    type: dict
  stages:
    description: All firmware upgrade stages in the network with their start time.
    elements: dict
    suboptions:
      group:
        description: The Staged Upgrade Group containing the name and ID.
        suboptions:
          id:
            description: ID of the Staged Upgrade Group.
            type: str
        type: dict
      milestones:
        description: The Staged Upgrade Milestones for the specific stage.
        suboptions:
          scheduledFor:
            description: The start time of the staged upgrade stage. (In ISO-8601 format, in the time zone of the network.).
            type: str
        type: dict
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks createNetworkFirmwareUpgradesStagedEvent
    description: Complete reference of the createNetworkFirmwareUpgradesStagedEvent API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-firmware-upgrades-staged-event
  - name: Cisco Meraki documentation for networks updateNetworkFirmwareUpgradesStagedEvents
    description: Complete reference of the updateNetworkFirmwareUpgradesStagedEvents API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-firmware-upgrades-staged-events
notes:
  - SDK Method used are
    networks.Networks.create_network_firmware_upgrades_staged_event,
    networks.Networks.update_network_firmware_upgrades_staged_events,
  - Paths used are
    post /networks/{networkId}/firmwareUpgrades/staged/events,
    put /networks/{networkId}/firmwareUpgrades/staged/events,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_firmware_upgrades_staged_events:
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
    networkId: string
    products:
      switch:
        nextUpgrade:
          toVersion:
            id: '1234'
      switchCatalyst:
        nextUpgrade:
          toVersion:
            id: '4321'
    stages:
      - group:
          id: '1234'
        milestones:
          scheduledFor: '2018-02-11T00:00:00Z'
- name: Update all
  cisco.meraki.networks_firmware_upgrades_staged_events:
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
    networkId: string
    stages:
      - group:
          id: '1234'
        milestones:
          scheduledFor: '2018-02-11T00:00:00Z'
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "products": {
        "switch": {
          "nextUpgrade": {
            "toVersion": {
              "id": "string",
              "shortName": "string"
            }
          }
        }
      },
      "reasons": [
        {
          "category": "string",
          "comment": "string"
        }
      ],
      "stages": [
        {
          "group": {
            "description": "string",
            "id": "string",
            "name": "string"
          },
          "milestones": {
            "canceledAt": "string",
            "completedAt": "string",
            "scheduledFor": "string",
            "startedAt": "string"
          },
          "status": "string"
        }
      ]
    }
"""
