#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_firmware_upgrades_rollbacks
short_description: Resource module for networks _firmware _upgrades _rollbacks
description:
  - Manage operation create of the resource networks _firmware _upgrades _rollbacks.
  - Rollback a Firmware Upgrade For A Network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  product:
    description: Product type to rollback (if the network is a combined network).
    type: str
  reasons:
    description: Reasons for the rollback.
    elements: dict
    suboptions:
      category:
        description: Reason for the rollback.
        type: str
      comment:
        description: Additional comment about the rollback.
        type: str
    type: list
  time:
    description: Scheduled time for the rollback.
    type: str
  toVersion:
    description: Version to downgrade to (if the network has firmware flexibility).
    suboptions:
      id:
        description: The version ID.
        type: str
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks createNetworkFirmwareUpgradesRollback
    description: Complete reference of the createNetworkFirmwareUpgradesRollback API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-firmware-upgrades-rollback
notes:
  - SDK Method used are
    networks.Networks.create_network_firmware_upgrades_rollback,
  - Paths used are
    post /networks/{networkId}/firmwareUpgrades/rollbacks,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_firmware_upgrades_rollbacks:
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
    product: switch
    reasons:
      - category: performance
        comment: Network was slower with the upgrade
    time: '2020-10-21T02:00:00Z'
    toVersion:
      id: '7857'
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "product": "string",
      "reasons": [
        {
          "category": "string",
          "comment": "string"
        }
      ],
      "status": "string",
      "time": "string",
      "toVersion": {
        "firmware": "string",
        "id": "string",
        "releaseDate": "string",
        "releaseType": "string",
        "shortName": "string"
      },
      "upgradeBatchId": "string"
    }
"""
