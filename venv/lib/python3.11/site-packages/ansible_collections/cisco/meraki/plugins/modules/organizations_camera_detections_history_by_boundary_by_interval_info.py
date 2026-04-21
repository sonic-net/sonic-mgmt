#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_camera_detections_history_by_boundary_by_interval_info
short_description: Information module for organizations _camera _detections _history _by _boundary _by _interval
description:
  - Get all organizations _camera _detections _history _by _boundary _by _interval.
  - Returns analytics data for timespans.
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
  boundaryIds:
    description:
      - >
        BoundaryIds query parameter. A list of boundary ids. The returned cameras will be filtered to only include these ids.
    elements: str
    type: list
  ranges:
    description:
      - Ranges query parameter. A list of time ranges with intervals.
    elements: dict
    type: list
  duration:
    description:
      - >
        Duration query parameter. The minimum time, in seconds, that the person or car remains in the area to be counted. Defaults to boundary
        configuration or 60.
    type: int
  perPage:
    description:
      - PerPage query parameter. The number of entries per page returned. Acceptable range is 1 - 1000. Defaults to 1000.
    type: int
  boundaryTypes:
    description:
      - BoundaryTypes query parameter. The detection types. Defaults to 'person'.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for camera getOrganizationCameraDetectionsHistoryByBoundaryByInterval
    description: Complete reference of the getOrganizationCameraDetectionsHistoryByBoundaryByInterval API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-camera-detections-history-by-boundary-by-interval
notes:
  - SDK Method used are
    camera.Camera.get_organization_camera_detections_history_by_boundary_by_interval,
  - Paths used are
    get /organizations/{organizationId}/camera/detections/history/byBoundary/byInterval,
"""

EXAMPLES = r"""
- name: Get all organizations _camera _detections _history _by _boundary _by _interval
  cisco.meraki.organizations_camera_detections_history_by_boundary_by_interval_info:
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
    boundaryIds: []
    ranges: []
    duration: 0
    perPage: 0
    boundaryTypes: []
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
        "boundaryId": "string",
        "results": {
          "endTime": "string",
          "in": 0,
          "objectType": "string",
          "out": 0,
          "startTime": "string"
        },
        "type": "string"
      }
    ]
"""
