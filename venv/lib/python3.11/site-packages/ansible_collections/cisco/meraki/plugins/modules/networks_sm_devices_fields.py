#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_sm_devices_fields
short_description: Resource module for networks _sm _devices _fields
description:
  - Manage operation update of the resource networks _sm _devices _fields.
  - Modify the fields of a device.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  deviceFields:
    description: The new fields of the device. Each field of this object is optional.
    suboptions:
      name:
        description: New name for the device.
        type: str
      notes:
        description: New notes for the device.
        type: str
    type: dict
  id:
    description: The id of the device to be modified.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  serial:
    description: The serial of the device to be modified.
    type: str
  wifiMac:
    description: The wifiMac of the device to be modified.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for sm updateNetworkSmDevicesFields
    description: Complete reference of the updateNetworkSmDevicesFields API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-sm-devices-fields
notes:
  - SDK Method used are
    sm.Sm.update_network_sm_devices_fields,
  - Paths used are
    put /networks/{networkId}/sm/devices/fields,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_sm_devices_fields:
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
    deviceFields:
      name: Miles's phone
      notes: Here's some info about my device
    id: '1284392014819'
    networkId: string
    serial: XY0XX0Y0X0
    wifiMac: 00:11:22:33:44:55
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: list
  sample: >
    [
      {
        "id": "string",
        "name": "string",
        "notes": "string",
        "serial": "string",
        "wifiMac": "string"
      }
    ]
"""
