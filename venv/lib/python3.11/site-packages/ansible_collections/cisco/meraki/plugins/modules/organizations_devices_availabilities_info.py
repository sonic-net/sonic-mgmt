#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_devices_availabilities_info
short_description: Information module for organizations _devices _availabilities
description:
  - Get all organizations _devices _availabilities. - > List the availability information for devices in an organization. The data returned by
    this endpoint is updated every 5 minutes.
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
  networkIds:
    description:
      - >
        NetworkIds query parameter. Optional parameter to filter device availabilities by network ID. This filter uses multiple exact matches.
    elements: str
    type: list
  productTypes:
    description:
      - >
        ProductTypes query parameter. Optional parameter to filter device availabilities by device product types. This filter uses multiple exact
        matches. Valid types are wireless, appliance, switch, camera, cellularGateway, sensor, wirelessController, and campusGateway.
    elements: str
    type: list
  serials:
    description:
      - >
        Serials query parameter. Optional parameter to filter device availabilities by device serial numbers. This filter uses multiple exact
        matches.
    elements: str
    type: list
  tags:
    description:
      - >
        Tags query parameter. An optional parameter to filter devices by tags. The filtering is case-sensitive. If tags are included, 'tagsFilterType'
        should also be included (see below). This filter uses multiple exact matches.
    elements: str
    type: list
  tagsFilterType:
    description:
      - >
        TagsFilterType query parameter. An optional parameter of value 'withAnyTags' or 'withAllTags' to indicate whether to return devices which
        contain ANY or ALL of the included tags. If no type is included, 'withAnyTags' will be selected.
    type: str
  statuses:
    description:
      - >
        Statuses query parameter. Optional parameter to filter device availabilities by device status. This filter uses multiple exact matches.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations getOrganizationDevicesAvailabilities
    description: Complete reference of the getOrganizationDevicesAvailabilities API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-devices-availabilities
notes:
  - SDK Method used are
    organizations.Organizations.get_organization_devices_availabilities,
  - Paths used are
    get /organizations/{organizationId}/devices/availabilities,
"""

EXAMPLES = r"""
- name: Get all organizations _devices _availabilities
  cisco.meraki.organizations_devices_availabilities_info:
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
    productTypes: []
    serials: []
    tags: []
    tagsFilterType: string
    statuses: []
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
        "mac": "string",
        "name": "string",
        "network": {
          "id": "string"
        },
        "productType": "string",
        "serial": "string",
        "status": "string",
        "tags": [
          "string"
        ]
      }
    ]
"""
