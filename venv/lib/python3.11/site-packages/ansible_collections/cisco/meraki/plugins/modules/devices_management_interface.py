#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_management_interface
short_description: Resource module for devices _management _interface
description:
  - Manage operations create and update of the resource devices _management _interface.
  - Reboot a device. This endpoint has a sustained rate limit of one request every 60 seconds.
  - Update the management interface settings for a device.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  serial:
    description: Serial path parameter.
    type: str
  wan1:
    description: WAN 1 settings.
    suboptions:
      staticDns:
        description: Up to two DNS IPs.
        elements: str
        type: list
      staticGatewayIp:
        description: The IP of the gateway on the WAN.
        type: str
      staticIp:
        description: The IP the device should use on the WAN.
        type: str
      staticSubnetMask:
        description: The subnet mask for the WAN.
        type: str
      usingStaticIp:
        description: Configure the interface to have static IP settings or use DHCP.
        type: bool
      vlan:
        description: The VLAN that management traffic should be tagged with. Applies whether usingStaticIp is true or false.
        type: int
      wanEnabled:
        description: Enable or disable the interface (only for MX devices). Valid values are 'enabled', 'disabled', and 'not configured'.
        type: str
    type: dict
  wan2:
    description: WAN 2 settings (only for MX devices).
    suboptions:
      staticDns:
        description: Up to two DNS IPs.
        elements: str
        type: list
      staticGatewayIp:
        description: The IP of the gateway on the WAN.
        type: str
      staticIp:
        description: The IP the device should use on the WAN.
        type: str
      staticSubnetMask:
        description: The subnet mask for the WAN.
        type: str
      usingStaticIp:
        description: Configure the interface to have static IP settings or use DHCP.
        type: bool
      vlan:
        description: The VLAN that management traffic should be tagged with. Applies whether usingStaticIp is true or false.
        type: int
      wanEnabled:
        description: Enable or disable the interface (only for MX devices). Valid values are 'enabled', 'disabled', and 'not configured'.
        type: str
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for devices rebootDevice
    description: Complete reference of the rebootDevice API.
    link: https://developer.cisco.com/meraki/api-v1/#!reboot-device
  - name: Cisco Meraki documentation for devices updateDeviceManagementInterface
    description: Complete reference of the updateDeviceManagementInterface API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-management-interface
notes:
  - SDK Method used are
    devices.Devices.reboot_device,
    devices.Devices.update_device_management_interface,
  - Paths used are
    post /devices/{serial}/reboot,
    put /devices/{serial}/managementInterface,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.devices_management_interface:
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
    serial: string
    wan1:
      staticDns:
        - 1.2.3.2
        - 1.2.3.3
      staticGatewayIp: 1.2.3.1
      staticIp: 1.2.3.4
      staticSubnetMask: 255.255.255.0
      usingStaticIp: true
      vlan: 7
      wanEnabled: not configured
    wan2:
      staticDns:
        - 1.2.3.2
        - 1.2.3.3
      staticGatewayIp: 1.2.3.1
      staticIp: 1.2.3.4
      staticSubnetMask: 255.255.255.0
      usingStaticIp: false
      vlan: 2
      wanEnabled: enabled
- name: Create
  cisco.meraki.devices_management_interface:
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
    serial: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "ddnsHostnames": {
        "activeDdnsHostname": "string",
        "ddnsHostnameWan1": "string",
        "ddnsHostnameWan2": "string"
      },
      "wan1": {
        "staticDns": [
          "string"
        ],
        "staticGatewayIp": "string",
        "staticIp": "string",
        "staticSubnetMask": "string",
        "usingStaticIp": true,
        "vlan": 0,
        "wanEnabled": "string"
      },
      "wan2": {
        "staticDns": [
          "string"
        ],
        "staticGatewayIp": "string",
        "staticIp": "string",
        "staticSubnetMask": "string",
        "usingStaticIp": true,
        "vlan": 0,
        "wanEnabled": "string"
      }
    }
"""
