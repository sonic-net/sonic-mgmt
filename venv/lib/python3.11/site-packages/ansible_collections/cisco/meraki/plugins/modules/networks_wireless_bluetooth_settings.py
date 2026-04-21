#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_bluetooth_settings
short_description: Resource module for networks _wireless _bluetooth _settings
description:
  - Manage operation update of the resource networks _wireless _bluetooth _settings.
  - Update the Bluetooth settings for a network. See the docs page for Bluetooth.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  advertisingEnabled:
    description: Whether APs will advertise beacons.
    type: bool
  major:
    description: The major number to be used in the beacon identifier. Only valid in 'Non-unique' mode.
    type: int
  majorMinorAssignmentMode:
    description: The way major and minor number should be assigned to nodes in the network. ('Unique', 'Non-unique').
    type: str
  minor:
    description: The minor number to be used in the beacon identifier. Only valid in 'Non-unique' mode.
    type: int
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  scanningEnabled:
    description: Whether APs will scan for Bluetooth enabled clients.
    type: bool
  uuid:
    description: The UUID to be used in the beacon identifier.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessBluetoothSettings
    description: Complete reference of the updateNetworkWirelessBluetoothSettings API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-bluetooth-settings
notes:
  - SDK Method used are
    wireless.Wireless.update_network_wireless_bluetooth_settings,
  - Paths used are
    put /networks/{networkId}/wireless/bluetooth/settings,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_wireless_bluetooth_settings:
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
    advertisingEnabled: true
    major: 1
    majorMinorAssignmentMode: Non-unique
    minor: 1
    networkId: string
    scanningEnabled: true
    uuid: 00000000-0000-0000-000-000000000000
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "advertisingEnabled": true,
      "eslEnabled": true,
      "major": 0,
      "majorMinorAssignmentMode": "string",
      "minor": 0,
      "scanningEnabled": true,
      "uuid": "string"
    }
"""
