#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_camera_sense
short_description: Resource module for devices _camera _sense
description:
  - Manage operation update of the resource devices _camera _sense.
  - Update sense settings for the given camera.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  audioDetection:
    description: The details of the audio detection config.
    suboptions:
      enabled:
        description: Boolean indicating if audio detection is enabled(true) or disabled(false) on the camera.
        type: bool
    type: dict
  detectionModelId:
    description: The ID of the object detection model.
    type: str
  mqttBrokerId:
    description: The ID of the MQTT broker to be enabled on the camera. A value of null will disable MQTT on the camera.
    type: str
  senseEnabled:
    description: Boolean indicating if sense(license) is enabled(true) or disabled(false) on the camera.
    type: bool
  serial:
    description: Serial path parameter.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for camera updateDeviceCameraSense
    description: Complete reference of the updateDeviceCameraSense API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-camera-sense
notes:
  - SDK Method used are
    camera.Camera.update_device_camera_sense,
  - Paths used are
    put /devices/{serial}/camera/sense,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.devices_camera_sense:
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
    audioDetection:
      enabled: false
    mqttBrokerId: '1234'
    senseEnabled: true
    serial: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
