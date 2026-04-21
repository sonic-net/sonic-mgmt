#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_firmware_upgrades_by_device_info
short_description: Information module for organizations _firmware _upgrades _by _device
description:
  - Get all organizations _firmware _upgrades _by _device.
  - Get firmware upgrade status for the filtered devices. This endpoint currently only supports Meraki switches.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
  - cisco.meraki.module_info_pagination
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  organizationId:
    description:
      - OrganizationId path parameter. Organization ID.
    type: str
  perPage:
    description:
      - PerPage query parameter. The number of entries per page returned. Acceptable range is 3 - 1000. Default is 50.
    type: int
  startingAfter:
    description:
      - >
        StartingAfter query parameter. A token used by the server to indicate the start of the page. Often this is a timestamp or an ID but it
        is not limited to those. This parameter should not be defined by client applications. The link for the first, last, prev, or next page
        in the HTTP Link header should define it.
    type: str
  endingBefore:
    description:
      - >
        EndingBefore query parameter. A token used by the server to indicate the end of the page. Often this is a timestamp or an ID but it is
        not limited to those. This parameter should not be defined by client applications. The link for the first, last, prev, or next page in
        the HTTP Link header should define it.
    type: str
  networkIds:
    description:
      - NetworkIds query parameter. Optional parameter to filter by network.
    elements: str
    type: list
  serials:
    description:
      - >
        Serials query parameter. Optional parameter to filter by serial number. All returned devices will have a serial number that is an exact
        match.
    elements: str
    type: list
  macs:
    description:
      - >
        Macs query parameter. Optional parameter to filter by one or more MAC addresses belonging to devices. All devices returned belong to MAC
        addresses that are an exact match.
    elements: str
    type: list
  firmwareUpgradeBatchIds:
    description:
      - FirmwareUpgradeBatchIds query parameter. Optional parameter to filter by firmware upgrade batch ids.
    elements: str
    type: list
  upgradeStatuses:
    description:
      - UpgradeStatuses query parameter. Optional parameter to filter by firmware upgrade statuses.
    elements: str
    type: list
  currentUpgradesOnly:
    description:
      - CurrentUpgradesOnly query parameter. Optional parameter to filter to only current or pending upgrade statuses.
    type: bool
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations getOrganizationFirmwareUpgradesByDevice
    description: Complete reference of the getOrganizationFirmwareUpgradesByDevice API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-firmware-upgrades-by-device
notes:
  - SDK Method used are
    organizations.Organizations.get_organization_firmware_upgrades_by_device,
  - Paths used are
    get /organizations/{organizationId}/firmware/upgrades/byDevice,
"""

EXAMPLES = r"""
- name: Get all organizations _firmware _upgrades _by _device
  cisco.meraki.organizations_firmware_upgrades_by_device_info:
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
    perPage: 0
    startingAfter: string
    endingBefore: string
    networkIds: []
    serials: []
    macs: []
    firmwareUpgradeBatchIds: []
    upgradeStatuses: []
    currentUpgradesOnly: true
    organizationId: string
    total_pages: -1
    direction: next
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "deviceStatus": "string",
        "name": "string",
        "serial": "string",
        "upgrade": {
          "fromVersion": {
            "id": "string",
            "releaseDate": "string",
            "releaseType": "string",
            "shortName": "string"
          },
          "id": "string",
          "staged": {
            "group": {
              "id": "string"
            }
          },
          "status": "string",
          "time": "string",
          "toVersion": {
            "id": "string",
            "releaseDate": "string",
            "releaseType": "string",
            "shortName": "string"
          },
          "upgradeBatchId": "string"
        }
      }
    ]
"""
