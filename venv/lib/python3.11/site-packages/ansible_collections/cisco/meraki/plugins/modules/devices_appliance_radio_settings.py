#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_appliance_radio_settings
short_description: Resource module for devices _appliance _radio _settings
description:
  - Manage operation update of the resource devices _appliance _radio _settings.
  - Update the radio settings of an appliance.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  fiveGhzSettings:
    description: Manual radio settings for 5 GHz.
    suboptions:
      channel:
        description: Sets a manual channel for 5 GHz. Can be '36', '40', '44', '48', '52', '56', '60', '64', '100', '104', '108', '112', '116',
          '120', '124', '128', '132', '136', '140', '144', '149', '153', '157', '161', '165', '169', '173' or '177' or null for using auto channel.
        type: int
      channelWidth:
        description: Sets a manual channel width for 5 GHz. Can be '0', '20', '40', '80' or '160' or null for using auto channel width.
        type: int
      targetPower:
        description: Set a manual target power for 5 GHz (dBm). Enter null for using auto power range.
        type: int
    type: dict
  rfProfileId:
    description: The ID of an RF profile to assign to the device. If the value of this parameter is null, the appropriate basic RF profile (indoor
      or outdoor) will be assigned to the device. Assigning an RF profile will clear ALL manually configured overrides on the device (channel
      width, channel, power).
    type: str
  serial:
    description: Serial path parameter.
    type: str
  twoFourGhzSettings:
    description: Manual radio settings for 2.4 GHz.
    suboptions:
      channel:
        description: Sets a manual channel for 2.4 GHz. Can be '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13' or '14' or
          null for using auto channel.
        type: int
      targetPower:
        description: Set a manual target power for 2.4 GHz (dBm). Enter null for using auto power range.
        type: int
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateDeviceApplianceRadioSettings
    description: Complete reference of the updateDeviceApplianceRadioSettings API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-appliance-radio-settings
notes:
  - SDK Method used are
    appliance.Appliance.update_device_appliance_radio_settings,
  - Paths used are
    put /devices/{serial}/appliance/radio/settings,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.devices_appliance_radio_settings:
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
    fiveGhzSettings:
      channel: 149
      channelWidth: 20
      targetPower: 15
    rfProfileId: '1234'
    serial: string
    twoFourGhzSettings:
      channel: 11
      targetPower: 21
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "fiveGhzSettings": {
        "channel": 0,
        "channelWidth": 0,
        "targetPower": 0
      },
      "rfProfileId": "string",
      "serial": "string",
      "twoFourGhzSettings": {
        "channel": 0,
        "targetPower": 0
      }
    }
"""
