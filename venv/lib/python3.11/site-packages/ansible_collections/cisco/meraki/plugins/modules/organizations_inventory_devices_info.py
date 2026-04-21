#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_inventory_devices_info
short_description: Information module for organizations _inventory _devices
description:
  - Get all organizations _inventory _devices.
  - Get organizations _inventory _devices by id.
  - Return a single device from the inventory of an organization.
  - Return the device inventory for an organization.
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
      - PerPage query parameter. The number of entries per page returned. Acceptable range is 3 - 1000. Default is 1000.
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
  usedState:
    description:
      - UsedState query parameter. Filter results by used or unused inventory. Accepted values are 'used' or 'unused'.
    type: str
  search:
    description:
      - Search query parameter. Search for devices in inventory based on serial number, mac address, or model.
    type: str
  macs:
    description:
      - Macs query parameter. Search for devices in inventory based on mac addresses.
    elements: str
    type: list
  networkIds:
    description:
      - >
        NetworkIds query parameter. Search for devices in inventory based on network ids. Use explicit 'null' value to get available devices only.
    elements: str
    type: list
  serials:
    description:
      - Serials query parameter. Search for devices in inventory based on serials.
    elements: str
    type: list
  models:
    description:
      - Models query parameter. Search for devices in inventory based on model.
    elements: str
    type: list
  orderNumbers:
    description:
      - OrderNumbers query parameter. Search for devices in inventory based on order numbers.
    elements: str
    type: list
  tags:
    description:
      - >
        Tags query parameter. Filter devices by tags. The filtering is case-sensitive. If tags are included, 'tagsFilterType' should also be included
        (see below).
    elements: str
    type: list
  tagsFilterType:
    description:
      - >
        TagsFilterType query parameter. To use with 'tags' parameter, to filter devices which contain ANY or ALL given tags. Accepted values are
        'withAnyTags' or 'withAllTags', default is 'withAnyTags'.
    type: str
  productTypes:
    description:
      - >
        ProductTypes query parameter. Filter devices by product type. Accepted values are appliance, camera, cellularGateway, secureConnect, sensor,
        switch, systemsManager, wireless, and wirelessController.
    elements: str
    type: list
  serial:
    description:
      - Serial path parameter.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations getOrganizationInventoryDevice
    description: Complete reference of the getOrganizationInventoryDevice API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-inventory-device
  - name: Cisco Meraki documentation for organizations getOrganizationInventoryDevices
    description: Complete reference of the getOrganizationInventoryDevices API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-inventory-devices
notes:
  - SDK Method used are
    organizations.Organizations.get_organization_inventory_device,
    organizations.Organizations.get_organization_inventory_devices,
  - Paths used are
    get /organizations/{organizationId}/inventory/devices,
    get /organizations/{organizationId}/inventory/devices/{serial},
"""

EXAMPLES = r"""
- name: Get all organizations _inventory _devices
  cisco.meraki.organizations_inventory_devices_info:
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
    usedState: string
    search: string
    macs: []
    networkIds: []
    serials: []
    models: []
    orderNumbers: []
    tags: []
    tagsFilterType: string
    productTypes: []
    organizationId: string
    total_pages: -1
    direction: next
  register: result
- name: Get organizations _inventory _devices by id
  cisco.meraki.organizations_inventory_devices_info:
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
    organizationId: string
    serial: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "claimedAt": "string",
      "countryCode": "string",
      "details": [
        {
          "name": "string",
          "value": "string"
        }
      ],
      "licenseExpirationDate": "string",
      "mac": "string",
      "model": "string",
      "name": "string",
      "networkId": "string",
      "orderNumber": "string",
      "productType": "string",
      "serial": "string",
      "tags": [
        "string"
      ]
    }
"""
