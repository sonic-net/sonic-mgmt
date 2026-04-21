#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_firmware_upgrades_staged_events_rollbacks
short_description: Resource module for networks _firmware _upgrades _staged _events _rollbacks
description:
  - Manage operation create of the resource networks _firmware _upgrades _staged _events _rollbacks.
  - Rollback a Staged Upgrade Event for a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  reasons:
    description: The reason for rolling back the staged upgrade.
    elements: dict
    suboptions:
      category:
        description: Reason for the rollback.
        type: str
      comment:
        description: Additional comment about the rollback.
        type: str
    type: list
  stages:
    description: All completed or in-progress stages in the network with their new start times. All pending stages will be canceled.
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
  - name: Cisco Meraki documentation for networks rollbacksNetworkFirmwareUpgradesStagedEvents
    description: Complete reference of the rollbacksNetworkFirmwareUpgradesStagedEvents API.
    link: https://developer.cisco.com/meraki/api-v1/#!rollbacks-network-firmware-upgrades-staged-events
notes:
  - SDK Method used are
    networks.Networks.rollbacks_network_firmware_upgrades_staged_events,
  - Paths used are
    post /networks/{networkId}/firmwareUpgrades/staged/events/rollbacks,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_firmware_upgrades_staged_events_rollbacks:
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
    networkId: string
    reasons:
      - category: performance
        comment: Network was slower with the upgrade
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
