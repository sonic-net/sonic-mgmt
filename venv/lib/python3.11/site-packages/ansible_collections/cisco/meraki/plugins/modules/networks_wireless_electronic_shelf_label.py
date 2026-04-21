#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_electronic_shelf_label
short_description: Resource module for networks _wireless _electronic _shelf _label
description:
  - Manage operation update of the resource networks _wireless _electronic _shelf _label.
  - Update the ESL settings of a wireless network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  enabled:
    description: Turn ESL features on and off for this network.
    type: bool
  hostname:
    description: Desired ESL hostname of the network.
    type: str
  mode:
    description: Electronic shelf label mode of the network. Valid options are 'Bluetooth', 'high frequency'.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessElectronicShelfLabel
    description: Complete reference of the updateNetworkWirelessElectronicShelfLabel API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-electronic-shelf-label
notes:
  - SDK Method used are
    wireless.Wireless.update_network_wireless_electronic_shelf_label,
  - Paths used are
    put /networks/{networkId}/wireless/electronicShelfLabel,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_wireless_electronic_shelf_label:
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
    enabled: true
    hostname: example.com
    mode: high frequency
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "enabled": true,
      "hostname": "string",
      "mode": "string"
    }
"""
