#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_pii_pii_keys_info
short_description: Information module for networks _pii _pii _keys
description:
  - Get all networks _pii _pii _keys. - > List the keys required to access Personally Identifiable Information PII for a given identifier. Exactly
    one identifier will be accepted. If the organization contains org-wide Systems Manager users matching the key provided then there will be
    an entry with the key "0" containing the applicable keys.
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
  username:
    description:
      - Username query parameter. The username of a Systems Manager user.
    type: str
  email:
    description:
      - Email query parameter. The email of a network user account or a Systems Manager device.
    type: str
  mac:
    description:
      - Mac query parameter. The MAC of a network client device or a Systems Manager device.
    type: str
  serial:
    description:
      - Serial query parameter. The serial of a Systems Manager device.
    type: str
  imei:
    description:
      - Imei query parameter. The IMEI of a Systems Manager device.
    type: str
  bluetoothMac:
    description:
      - BluetoothMac query parameter. The MAC of a Bluetooth client.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks getNetworkPiiPiiKeys
    description: Complete reference of the getNetworkPiiPiiKeys API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-pii-pii-keys
notes:
  - SDK Method used are
    networks.Networks.get_network_pii_pii_keys,
  - Paths used are
    get /networks/{networkId}/pii/piiKeys,
"""

EXAMPLES = r"""
- name: Get all networks _pii _pii _keys
  cisco.meraki.networks_pii_pii_keys_info:
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
    username: string
    email: string
    mac: string
    serial: string
    imei: string
    bluetoothMac: string
    networkId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "bluetoothMacs": [
        "string"
      ],
      "emails": [
        "string"
      ],
      "imeis": [
        "string"
      ],
      "macs": [
        "string"
      ],
      "serials": [
        "string"
      ],
      "usernames": [
        "string"
      ]
    }
"""
