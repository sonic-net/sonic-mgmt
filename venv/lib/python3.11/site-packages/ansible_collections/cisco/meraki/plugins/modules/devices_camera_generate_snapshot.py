#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_camera_generate_snapshot
short_description: Resource module for devices _camera _generate _snapshot
description:
  - Manage operation create of the resource devices _camera _generate _snapshot.
  - Generate a snapshot of what the camera sees at the specified time and return a link to that image.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  fullframe:
    description: Optional If set to "true" the snapshot will be taken at full sensor resolution. This will error if used with timestamp.
    type: bool
  serial:
    description: Serial path parameter.
    type: str
  timestamp:
    description: Optional The snapshot will be taken from this time on the camera. The timestamp is expected to be in ISO 8601 format. If no timestamp
      is specified, we will assume current time.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for camera generateDeviceCameraSnapshot
    description: Complete reference of the generateDeviceCameraSnapshot API.
    link: https://developer.cisco.com/meraki/api-v1/#!generate-device-camera-snapshot
notes:
  - SDK Method used are
    camera.Camera.generate_device_camera_snapshot,
  - Paths used are
    post /devices/{serial}/camera/generateSnapshot,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.devices_camera_generate_snapshot:
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
    fullframe: false
    serial: string
    timestamp: '2021-04-30T15:18:08Z'
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "expiry": "string",
      "url": "string"
    }
"""
