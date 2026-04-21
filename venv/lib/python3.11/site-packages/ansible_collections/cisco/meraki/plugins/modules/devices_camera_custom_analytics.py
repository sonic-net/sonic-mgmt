#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_camera_custom_analytics
short_description: Resource module for devices _camera _custom _analytics
description:
  - Manage operation update of the resource devices _camera _custom _analytics.
  - Update custom analytics settings for a camera.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  artifactId:
    description: The ID of the custom analytics artifact.
    type: str
  enabled:
    description: Enable custom analytics.
    type: bool
  parameters:
    description: Parameters for the custom analytics workload.
    elements: dict
    suboptions:
      name:
        description: Name of the parameter.
        type: str
      value:
        description: Value of the parameter.
        type: str
    type: list
  serial:
    description: Serial path parameter.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for camera updateDeviceCameraCustomAnalytics
    description: Complete reference of the updateDeviceCameraCustomAnalytics API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-camera-custom-analytics
notes:
  - SDK Method used are
    camera.Camera.update_device_camera_custom_analytics,
  - Paths used are
    put /devices/{serial}/camera/customAnalytics,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.devices_camera_custom_analytics:
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
    artifactId: '1'
    enabled: true
    parameters:
      - name: detection_threshold
        value: '0.5'
    serial: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "artifactId": "string",
      "enabled": true,
      "parameters": [
        {
          "name": "string",
          "value": 0
        }
      ]
    }
"""
