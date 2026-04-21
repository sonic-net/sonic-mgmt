#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_camera_quality_and_retention
short_description: Resource module for devices _camera _quality _and _retention
description:
  - Manage operation update of the resource devices _camera _quality _and _retention.
  - Update quality and retention settings for the given camera.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  audioRecordingEnabled:
    description: Boolean indicating if audio recording is enabled(true) or disabled(false) on the camera.
    type: bool
  motionBasedRetentionEnabled:
    description: Boolean indicating if motion-based retention is enabled(true) or disabled(false) on the camera.
    type: bool
  motionDetectorVersion:
    description: The version of the motion detector that will be used by the camera. Only applies to Gen 2 cameras. Defaults to v2.
    type: int
  profileId:
    description: The ID of a quality and retention profile to assign to the camera. The profile's settings will override all of the per-camera
      quality and retention settings. If the value of this parameter is null, any existing profile will be unassigned from the camera.
    type: str
  quality:
    description: Quality of the camera. Can be one of 'Standard', 'High', 'Enhanced' or 'Ultra'. Not all qualities are supported by every camera
      model.
    type: str
  resolution:
    description: Resolution of the camera. Can be one of '1280x720', '1920x1080', '1080x1080', '2112x2112', '2880x2880', '2688x1512' or '3840x2160'.Not
      all resolutions are supported by every camera model.
    type: str
  restrictedBandwidthModeEnabled:
    description: Boolean indicating if restricted bandwidth is enabled(true) or disabled(false) on the camera. This setting does not apply to
      MV2 cameras.
    type: bool
  serial:
    description: Serial path parameter.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for camera updateDeviceCameraQualityAndRetention
    description: Complete reference of the updateDeviceCameraQualityAndRetention API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-camera-quality-and-retention
notes:
  - SDK Method used are
    camera.Camera.update_device_camera_quality_and_retention,
  - Paths used are
    put /devices/{serial}/camera/qualityAndRetention,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.devices_camera_quality_and_retention:
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
    audioRecordingEnabled: false
    motionBasedRetentionEnabled: false
    motionDetectorVersion: 2
    profileId: '1234'
    quality: Standard
    resolution: 1280x720
    restrictedBandwidthModeEnabled: false
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
