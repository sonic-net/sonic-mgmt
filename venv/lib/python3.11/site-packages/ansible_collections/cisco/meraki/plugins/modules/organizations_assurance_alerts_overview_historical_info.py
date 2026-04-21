#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_assurance_alerts_overview_historical_info
short_description: Information module for organizations _assurance _alerts _overview _historical
description:
  - Get all organizations _assurance _alerts _overview _historical.
  - Returns historical health alert overviews.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  organizationId:
    description:
      - OrganizationId path parameter. Organization ID.
    type: str
  segmentDuration:
    description:
      - SegmentDuration query parameter. Amount of time in seconds for each segment in the returned dataset.
    type: int
  networkId:
    description:
      - NetworkId query parameter. Optional parameter to filter alerts overview by network ids.
    type: str
  severity:
    description:
      - Severity query parameter. Optional parameter to filter alerts overview by severity type.
    type: str
  types:
    description:
      - Types query parameter. Optional parameter to filter by alert type.
    elements: str
    type: list
  tsStart:
    description:
      - TsStart query parameter. Parameter to define starting timestamp of historical totals.
    type: str
  tsEnd:
    description:
      - TsEnd query parameter. Optional parameter to filter by end timestamp defaults to the current time.
    type: str
  category:
    description:
      - Category query parameter. Optional parameter to filter by category.
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
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations getOrganizationAssuranceAlertsOverviewHistorical
    description: Complete reference of the getOrganizationAssuranceAlertsOverviewHistorical API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-assurance-alerts-overview-historical
notes:
  - SDK Method used are
    organizations.Organizations.get_organization_assurance_alerts_overview_historical,
  - Paths used are
    get /organizations/{organizationId}/assurance/alerts/overview/historical,
"""

EXAMPLES = r"""
- name: Get all organizations _assurance _alerts _overview _historical
  cisco.meraki.organizations_assurance_alerts_overview_historical_info:
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
    segmentDuration: 0
    networkId: string
    severity: string
    types: []
    tsStart: string
    tsEnd: string
    category: string
    serials: []
    deviceTypes: []
    organizationId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "items": [
        {
          "byAlertType": [
            {
              "critical": 0,
              "informational": 0,
              "type": "string",
              "warning": 0
            }
          ],
          "segmentStart": "string",
          "totals": {
            "critical": 0,
            "informational": 0,
            "warning": 0
          }
        }
      ],
      "meta": {
        "counts": {
          "items": 0
        }
      }
    }
"""
