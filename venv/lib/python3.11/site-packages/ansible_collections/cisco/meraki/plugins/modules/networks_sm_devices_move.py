#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_sm_devices_move
short_description: Resource module for networks _sm _devices _move
description:
  - Manage operation create of the resource networks _sm _devices _move.
  - Move a set of devices to a new network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  ids:
    description: The ids of the devices to be moved.
    elements: str
    type: list
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  newNetwork:
    description: The new network to which the devices will be moved.
    type: str
  scope:
    description: The scope (one of all, none, withAny, withAll, withoutAny, or withoutAll) and a set of tags of the devices to be moved.
    elements: str
    type: list
  serials:
    description: The serials of the devices to be moved.
    elements: str
    type: list
  wifiMacs:
    description: The wifiMacs of the devices to be moved.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for sm moveNetworkSmDevices
    description: Complete reference of the moveNetworkSmDevices API.
    link: https://developer.cisco.com/meraki/api-v1/#!move-network-sm-devices
notes:
  - SDK Method used are
    sm.Sm.move_network_sm_devices,
  - Paths used are
    post /networks/{networkId}/sm/devices/move,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_sm_devices_move:
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
    ids:
      - '1284392014819'
      - '2983092129865'
    networkId: string
    newNetwork: '1284392014819'
    scope:
      - withAny
      - tag1
      - tag2
    serials:
      - XY0XX0Y0X0
      - A01B01CD00E
      - X02YZ1ZYZX
    wifiMacs:
      - 00:11:22:33:44:55
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "ids": [
        "string"
      ],
      "newNetwork": "string"
    }
"""
