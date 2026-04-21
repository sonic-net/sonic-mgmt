#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_cellular_gateway_lan
short_description: Resource module for devices _cellular _gateway _lan
description:
  - Manage operation update of the resource devices _cellular _gateway _lan.
  - Update the LAN Settings for a single MG.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  fixedIpAssignments:
    description: List of all fixed IP assignments for a single MG.
    elements: dict
    suboptions:
      ip:
        description: The IP address you want to assign to a specific server or device.
        type: str
      mac:
        description: The MAC address of the server or device that hosts the internal resource that you wish to receive the specified IP address.
        type: str
      name:
        description: A descriptive name of the assignment.
        type: str
    type: list
  reservedIpRanges:
    description: List of all reserved IP ranges for a single MG.
    elements: dict
    suboptions:
      comment:
        description: Comment explaining the reserved IP range.
        type: str
      end:
        description: Ending IP included in the reserved range of IPs.
        type: str
      start:
        description: Starting IP included in the reserved range of IPs.
        type: str
    type: list
  serial:
    description: Serial path parameter.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for cellularGateway updateDeviceCellularGatewayLan
    description: Complete reference of the updateDeviceCellularGatewayLan API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-cellular-gateway-lan
notes:
  - SDK Method used are
    cellular_gateway.CellularGateway.update_device_cellular_gateway_lan,
  - Paths used are
    put /devices/{serial}/cellularGateway/lan,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.devices_cellular_gateway_lan:
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
    fixedIpAssignments:
      - ip: 192.168.0.10
        mac: 0b:00:00:00:00:ac
        name: server 1
    reservedIpRanges:
      - comment: A reserved IP range
        end: 192.168.1.1
        start: 192.168.1.0
    serial: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "deviceLanIp": "string",
      "deviceName": "string",
      "deviceSubnet": "string",
      "fixedIpAssignments": [
        {
          "ip": "string",
          "mac": "string",
          "name": "string"
        }
      ],
      "reservedIpRanges": [
        {
          "comment": "string",
          "end": "string",
          "start": "string"
        }
      ]
    }
"""
