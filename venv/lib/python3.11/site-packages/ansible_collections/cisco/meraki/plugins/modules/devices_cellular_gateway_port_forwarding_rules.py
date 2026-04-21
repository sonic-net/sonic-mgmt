#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_cellular_gateway_port_forwarding_rules
short_description: Resource module for devices _cellular _gateway _port _forwarding _rules
description:
  - Manage operation update of the resource devices _cellular _gateway _port _forwarding _rules.
  - Updates the port forwarding rules for a single MG.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  rules:
    description: An array of port forwarding params.
    elements: dict
    suboptions:
      access:
        description: '`any` or `restricted`. Specify the right to make inbound connections on the specified ports or port ranges. If `restricted`,
          a list of allowed IPs is mandatory.'
        type: str
      allowedIps:
        description: An array of ranges of WAN IP addresses that are allowed to make inbound connections on the specified ports or port ranges.
        elements: str
        type: list
      lanIp:
        description: The IP address of the server or device that hosts the internal resource that you wish to make available on the WAN.
        type: str
      localPort:
        description: A port or port ranges that will receive the forwarded traffic from the WAN.
        type: str
      name:
        description: A descriptive name for the rule.
        type: str
      protocol:
        description: TCP or UDP.
        type: str
      publicPort:
        description: A port or port ranges that will be forwarded to the host on the LAN.
        type: str
    type: list
  serial:
    description: Serial path parameter.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for cellularGateway updateDeviceCellularGatewayPortForwardingRules
    description: Complete reference of the updateDeviceCellularGatewayPortForwardingRules API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-cellular-gateway-port-forwarding-rules
notes:
  - SDK Method used are
    cellular_gateway.CellularGateway.update_device_cellular_gateway_port_forwarding_rules,
  - Paths used are
    put /devices/{serial}/cellularGateway/portForwardingRules,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.devices_cellular_gateway_port_forwarding_rules:
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
    rules:
      - access: any
        allowedIps:
          - 10.10.10.10
          - 10.10.10.11
        lanIp: 172.31.128.5
        localPort: '4'
        name: test
        protocol: tcp
        publicPort: 11-12
    serial: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    [
      {
        "access": "string",
        "allowedIps": [
          "string"
        ],
        "lanIp": "string",
        "localPort": "string",
        "name": "string",
        "protocol": "string",
        "publicPort": "string"
      }
    ]
"""
