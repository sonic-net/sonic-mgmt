#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_camera_boundaries_areas_by_device_info
short_description: Information module for organizations _camera _boundaries _areas _by _device
description:
  - Get all organizations _camera _boundaries _areas _by _device.
  - Returns all configured area boundaries of cameras.
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
  serials:
    description:
      - >
        Serials query parameter. A list of serial numbers. The returned cameras will be filtered to only include these serials.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for camera getOrganizationCameraBoundariesAreasByDevice
    description: Complete reference of the getOrganizationCameraBoundariesAreasByDevice API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-camera-boundaries-areas-by-device
notes:
  - SDK Method used are
    camera.Camera.get_organization_camera_boundaries_areas_by_device,
  - Paths used are
    get /organizations/{organizationId}/camera/boundaries/areas/byDevice,
"""

EXAMPLES = r"""
- name: Get all organizations _camera _boundaries _areas _by _device
  cisco.meraki.organizations_camera_boundaries_areas_by_device_info:
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
    serials: []
    organizationId: string
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
        "boundaries": {
          "id": "string",
          "name": "string",
          "type": "string",
          "vertices": [
            {
              "x": 0,
              "y": 0
            }
          ]
        },
        "networkId": "string",
        "serial": "string"
      }
    ]
"""
