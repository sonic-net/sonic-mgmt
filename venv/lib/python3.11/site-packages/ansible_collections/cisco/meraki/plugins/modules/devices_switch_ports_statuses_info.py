#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_switch_ports_statuses_info
short_description: Information module for devices _switch _ports _statuses
description:
  - Get all devices _switch _ports _statuses.
  - Return the status for all the ports of a switch.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  serial:
    description:
      - Serial path parameter.
    type: str
  t0:
    description:
      - T0 query parameter. The beginning of the timespan for the data. The maximum lookback period is 31 days from today.
    type: str
  timespan:
    description:
      - >
        Timespan query parameter. The timespan for which the information will be fetched. If specifying timespan, do not specify parameter t0.
        The value must be in seconds and be less than or equal to 31 days. The default is 1 day.
    type: float
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch getDeviceSwitchPortsStatuses
    description: Complete reference of the getDeviceSwitchPortsStatuses API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-device-switch-ports-statuses
notes:
  - SDK Method used are
    switch.Switch.get_device_switch_ports_statuses,
  - Paths used are
    get /devices/{serial}/switch/ports/statuses,
"""

EXAMPLES = r"""
- name: Get all devices _switch _ports _statuses
  cisco.meraki.devices_switch_ports_statuses_info:
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
    t0: string
    timespan: 0
    serial: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "cdp": {
          "address": "string",
          "capabilities": "string",
          "deviceId": "string",
          "managementAddress": "string",
          "nativeVlan": 0,
          "platform": "string",
          "portId": "string",
          "systemName": "string",
          "version": "string",
          "vtpManagementDomain": "string"
        },
        "clientCount": 0,
        "duplex": "string",
        "enabled": true,
        "errors": [
          "string"
        ],
        "isUplink": true,
        "lldp": {
          "chassisId": "string",
          "managementAddress": "string",
          "managementVlan": 0,
          "portDescription": "string",
          "portId": "string",
          "portVlan": 0,
          "systemCapabilities": "string",
          "systemDescription": "string",
          "systemName": "string"
        },
        "poe": {
          "isAllocated": true
        },
        "portId": "string",
        "powerUsageInWh": 0,
        "securePort": {
          "active": true,
          "authenticationStatus": "string",
          "configOverrides": {
            "allowedVlans": "string",
            "type": "string",
            "vlan": 0,
            "voiceVlan": 0
          },
          "enabled": true
        },
        "spanningTree": {
          "statuses": [
            "string"
          ]
        },
        "speed": "string",
        "status": "string",
        "trafficInKbps": {
          "recv": 0,
          "sent": 0,
          "total": 0
        },
        "usageInKb": {
          "recv": 0,
          "sent": 0,
          "total": 0
        },
        "warnings": [
          "string"
        ]
      }
    ]
"""
