#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_assurance_alerts_info
short_description: Information module for organizations _assurance _alerts
description:
  - Get all organizations _assurance _alerts.
  - Return all health alerts for an organization.
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
      - PerPage query parameter. The number of entries per page returned. Acceptable range is 4 - 300. Default is 30.
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
  sortOrder:
    description:
      - >
        SortOrder query parameter. Sorted order of entries. Order options are 'ascending' and 'descending'. Default is 'ascending'.
    type: str
  networkId:
    description:
      - NetworkId query parameter. Optional parameter to filter alerts by network ids.
    type: str
  severity:
    description:
      - Severity query parameter. Optional parameter to filter by severity type.
    type: str
  types:
    description:
      - Types query parameter. Optional parameter to filter by alert type.
    elements: str
    type: list
  tsStart:
    description:
      - TsStart query parameter. Optional parameter to filter by starting timestamp.
    type: str
  tsEnd:
    description:
      - TsEnd query parameter. Optional parameter to filter by end timestamp.
    type: str
  category:
    description:
      - Category query parameter. Optional parameter to filter by category.
    type: str
  sortBy:
    description:
      - SortBy query parameter. Optional parameter to set column to sort by.
    type: str
  serials:
    description:
      - Serials query parameter. Optional parameter to filter by primary device serial.
    elements: str
    type: list
  deviceTypes:
    description:
      - DeviceTypes query parameter. Optional parameter to filter by device types.
    elements: str
    type: list
  deviceTags:
    description:
      - DeviceTags query parameter. Optional parameter to filter by device tags.
    elements: str
    type: list
  active:
    description:
      - Active query parameter. Optional parameter to filter by active alerts defaults to true.
    type: bool
  dismissed:
    description:
      - Dismissed query parameter. Optional parameter to filter by dismissed alerts defaults to false.
    type: bool
  resolved:
    description:
      - Resolved query parameter. Optional parameter to filter by resolved alerts defaults to false.
    type: bool
  suppressAlertsForOfflineNodes:
    description:
      - >
        SuppressAlertsForOfflineNodes query parameter. When set to true the api will only return connectivity alerts for a given device if that
        device is in an offline state. This only applies to devices. This is ignored when resolved is true. Example If a Switch has a VLan Mismatch
        and is Unreachable. Only the Unreachable alert will be returned. Defaults to false.
    type: bool
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations getOrganizationAssuranceAlerts
    description: Complete reference of the getOrganizationAssuranceAlerts API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-assurance-alerts
notes:
  - SDK Method used are
    organizations.Organizations.get_organization_assurance_alerts,
  - Paths used are
    get /organizations/{organizationId}/assurance/alerts,
"""

EXAMPLES = r"""
- name: Get all organizations _assurance _alerts
  cisco.meraki.organizations_assurance_alerts_info:
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
    sortOrder: string
    networkId: string
    severity: string
    types: []
    tsStart: string
    tsEnd: string
    category: string
    sortBy: string
    serials: []
    deviceTypes: []
    deviceTags: []
    active: true
    dismissed: true
    resolved: true
    suppressAlertsForOfflineNodes: true
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
        "categoryType": "string",
        "description": "string",
        "deviceType": "string",
        "dismissedAt": "string",
        "id": "string",
        "network": {
          "id": "string",
          "name": "string"
        },
        "resolvedAt": "string",
        "scope": {
          "applications": [
            {}
          ],
          "devices": [
            {
              "imei": "string",
              "lldp": {
                "port": "string"
              },
              "mac": "string",
              "name": "string",
              "order": 0,
              "productType": "string",
              "serial": "string",
              "url": "string"
            }
          ],
          "peers": [
            {}
          ]
        },
        "severity": "string",
        "startedAt": "string",
        "title": "string",
        "type": "string"
      }
    ]
"""
