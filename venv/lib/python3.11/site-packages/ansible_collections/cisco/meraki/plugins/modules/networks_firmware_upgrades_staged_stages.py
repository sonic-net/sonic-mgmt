#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_firmware_upgrades_staged_stages
short_description: Resource module for networks _firmware _upgrades _staged _stages
description:
  - Manage operation update of the resource networks _firmware _upgrades _staged _stages.
  - Assign Staged Upgrade Group order in the sequence.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  _json:
    description: Array of Staged Upgrade Groups.
    elements: dict
    suboptions:
      group:
        description: The Staged Upgrade Group.
        suboptions:
          id:
            description: ID of the Staged Upgrade Group.
            type: str
        type: dict
    type: list
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks updateNetworkFirmwareUpgradesStagedStages
    description: Complete reference of the updateNetworkFirmwareUpgradesStagedStages API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-firmware-upgrades-staged-stages
notes:
  - SDK Method used are
    networks.Networks.update_network_firmware_upgrades_staged_stages,
  - Paths used are
    put /networks/{networkId}/firmwareUpgrades/staged/stages,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_firmware_upgrades_staged_stages:
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
    _json:
      - group:
          id: '1234'
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: list
  sample: >
    [
      {
        "group": {
          "description": "string",
          "id": "string",
          "name": "string"
        }
      }
    ]
"""
