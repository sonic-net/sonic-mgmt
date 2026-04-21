#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_wireless_bluetooth_settings
short_description: Resource module for devices _wireless _bluetooth _settings
description:
  - Manage operation update of the resource devices _wireless _bluetooth _settings.
  - Update the bluetooth settings for a wireless device.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  major:
    description: Desired major value of the beacon. If the value is set to null it will reset to Dashboard's automatically generated value.
    type: int
  minor:
    description: Desired minor value of the beacon. If the value is set to null it will reset to Dashboard's automatically generated value.
    type: int
  serial:
    description: Serial path parameter.
    type: str
  uuid:
    description: Desired UUID of the beacon. If the value is set to null it will reset to Dashboard's automatically generated value.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateDeviceWirelessBluetoothSettings
    description: Complete reference of the updateDeviceWirelessBluetoothSettings API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-wireless-bluetooth-settings
notes:
  - SDK Method used are
    wireless.Wireless.update_device_wireless_bluetooth_settings,
  - Paths used are
    put /devices/{serial}/wireless/bluetooth/settings,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.devices_wireless_bluetooth_settings:
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
    major: 13
    minor: 125
    serial: string
    uuid: 00000000-0000-0000-000-000000000000
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "major": 0,
      "minor": 0,
      "uuid": "string"
    }
"""
