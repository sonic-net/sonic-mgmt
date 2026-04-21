#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_bluetooth_clients_info
short_description: Information module for networks _bluetooth _clients
description:
  - Get networks _bluetooth _clients by id.
  - Return a Bluetooth client. Bluetooth clients can be identified by their ID or their MAC.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  networkId:
    description:
      - NetworkId path parameter. Network ID.
    type: str
  bluetoothClientId:
    description:
      - BluetoothClientId path parameter. Bluetooth client ID.
    type: str
  includeConnectivityHistory:
    description:
      - IncludeConnectivityHistory query parameter. Include the connectivity history for this client.
    type: bool
  connectivityHistoryTimespan:
    description:
      - >
        ConnectivityHistoryTimespan query parameter. The timespan, in seconds, for the connectivityHistory data. By default 1 day, 86400, will
        be used.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks getNetworkBluetoothClient
    description: Complete reference of the getNetworkBluetoothClient API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-bluetooth-client
notes:
  - SDK Method used are
    networks.Networks.get_network_bluetooth_client,
  - Paths used are
    get /networks/{networkId}/bluetoothClients/{bluetoothClientId},
"""

EXAMPLES = r"""
- name: Get networks _bluetooth _clients by id
  cisco.meraki.networks_bluetooth_clients_info:
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
    includeConnectivityHistory: true
    connectivityHistoryTimespan: 0
    networkId: string
    bluetoothClientId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "deviceName": "string",
      "id": "string",
      "inSightAlert": true,
      "lastSeen": 0,
      "mac": "string",
      "manufacturer": "string",
      "name": "string",
      "networkId": "string",
      "outOfSightAlert": true,
      "seenByDeviceMac": "string",
      "tags": [
        "string"
      ]
    }
"""
