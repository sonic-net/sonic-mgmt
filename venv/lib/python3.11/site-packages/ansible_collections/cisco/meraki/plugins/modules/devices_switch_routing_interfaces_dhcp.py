#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_switch_routing_interfaces_dhcp
short_description: Resource module for devices _switch _routing _interfaces _dhcp
description:
  - Manage operation update of the resource devices _switch _routing _interfaces _dhcp.
  - Update a layer 3 interface DHCP configuration for a switch.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  bootFileName:
    description: The PXE boot server filename for the DHCP server running on the switch interface.
    type: str
  bootNextServer:
    description: The PXE boot server IP for the DHCP server running on the switch interface.
    type: str
  bootOptionsEnabled:
    description: Enable DHCP boot options to provide PXE boot options configs for the dhcp server running on the switch interface.
    type: bool
  dhcpLeaseTime:
    description: The DHCP lease time config for the dhcp server running on switch interface ('30 minutes', '1 hour', '4 hours', '12 hours', '1
      day' or '1 week').
    type: str
  dhcpMode:
    description: The DHCP mode options for the switch interface ('dhcpDisabled', 'dhcpRelay' or 'dhcpServer').
    type: str
  dhcpOptions:
    description: Array of DHCP options consisting of code, type and value for the DHCP server running on the switch interface.
    elements: dict
    suboptions:
      code:
        description: The code for DHCP option which should be from 2 to 254.
        type: str
      type:
        description: The type of the DHCP option which should be one of ('text', 'ip', 'integer' or 'hex').
        type: str
      value:
        description: The value of the DHCP option.
        type: str
    type: list
  dhcpRelayServerIps:
    description: The DHCP relay server IPs to which DHCP packets would get relayed for the switch interface.
    elements: str
    type: list
  dnsCustomNameservers:
    description: The DHCP name server IPs when DHCP name server option is 'custom'.
    elements: str
    type: list
  dnsNameserversOption:
    description: The DHCP name server option for the dhcp server running on the switch interface ('googlePublicDns', 'openDns' or 'custom').
    type: str
  fixedIpAssignments:
    description: Array of DHCP fixed IP assignments for the DHCP server running on the switch interface.
    elements: dict
    suboptions:
      ip:
        description: The IP address of the client which has fixed IP address assigned to it.
        type: str
      mac:
        description: The MAC address of the client which has fixed IP address.
        type: str
      name:
        description: The name of the client which has fixed IP address.
        type: str
    type: list
  interfaceId:
    description: InterfaceId path parameter. Interface ID.
    type: str
  reservedIpRanges:
    description: Array of DHCP reserved IP assignments for the DHCP server running on the switch interface.
    elements: dict
    suboptions:
      comment:
        description: The comment for the reserved IP range.
        type: str
      end:
        description: The ending IP address of the reserved IP range.
        type: str
      start:
        description: The starting IP address of the reserved IP range.
        type: str
    type: list
  serial:
    description: Serial path parameter.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch updateDeviceSwitchRoutingInterfaceDhcp
    description: Complete reference of the updateDeviceSwitchRoutingInterfaceDhcp API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-switch-routing-interface-dhcp
notes:
  - SDK Method used are
    switch.Switch.update_device_switch_routing_interface_dhcp,
  - Paths used are
    put /devices/{serial}/switch/routing/interfaces/{interfaceId}/dhcp,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.devices_switch_routing_interfaces_dhcp:
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
    bootFileName: home_boot_file
    bootNextServer: 1.2.3.4
    bootOptionsEnabled: true
    dhcpLeaseTime: 1 day
    dhcpMode: dhcpServer
    dhcpOptions:
      - code: '5'
        type: text
        value: five
    dhcpRelayServerIps:
      - 1.2.3.4
    dnsCustomNameservers:
      - 8.8.8.8, 8.8.4.4
    dnsNameserversOption: custom
    fixedIpAssignments:
      - ip: 192.168.1.12
        mac: 22:33:44:55:66:77
        name: Cisco Meraki valued client
    interfaceId: string
    reservedIpRanges:
      - comment: A reserved IP range
        end: 192.168.1.10
        start: 192.168.1.1
    serial: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "bootFileName": "string",
      "bootNextServer": "string",
      "bootOptionsEnabled": true,
      "dhcpLeaseTime": "string",
      "dhcpMode": "string",
      "dhcpOptions": [
        {
          "code": "string",
          "type": "string",
          "value": "string"
        }
      ],
      "dhcpRelayServerIps": [
        "string"
      ],
      "dnsCustomNameservers": [
        "string"
      ],
      "dnsNameserversOption": "string",
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
