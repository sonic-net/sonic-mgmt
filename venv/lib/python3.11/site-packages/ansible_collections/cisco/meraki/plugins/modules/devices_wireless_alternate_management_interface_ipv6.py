#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_wireless_alternate_management_interface_ipv6
short_description: Resource module for devices _wireless _alternate _management _interface _ipv6
description:
  - Manage operation update of the resource devices _wireless _alternate _management _interface _ipv6.
  - Update alternate management interface IPv6 address.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  addresses:
    description: Configured alternate management interface addresses.
    elements: dict
    suboptions:
      address:
        description: The IP address configured for the alternate management interface.
        type: str
      assignmentMode:
        description: The type of address assignment. Either static or dynamic.
        type: str
      gateway:
        description: The gateway address configured for the alternate managment interface.
        type: str
      nameservers:
        description: The DNS servers settings for this address.
        suboptions:
          addresses:
            description: Up to 2 nameserver addresses to use, ordered in priority from highest to lowest priority.
            elements: str
            type: list
        type: dict
      prefix:
        description: The IPv6 prefix length of the IPv6 interface. Required if IPv6 object is included.
        type: str
      protocol:
        description: The IP protocol used for the address.
        type: str
    type: list
  serial:
    description: Serial path parameter.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateDeviceWirelessAlternateManagementInterfaceIpv6
    description: Complete reference of the updateDeviceWirelessAlternateManagementInterfaceIpv6 API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-wireless-alternate-management-interface-ipv6
notes:
  - SDK Method used are
    wireless.Wireless.update_device_wireless_alternate_management_interface_ipv6,
  - Paths used are
    put /devices/{serial}/wireless/alternateManagementInterface/ipv6,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.devices_wireless_alternate_management_interface_ipv6:
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
    addresses:
      - address: 2001:db8:3c4d:15::1
        assignmentMode: static
        gateway: fe80:db8:c15:c0:d0c::10ca:1d02
        nameservers:
          addresses:
            - 2001:db8:3c4d:15::1
            - 2001:db8:3c4d:15::1
        prefix: 2001:db8:3c4d:15::/64
        protocol: ipv6
    serial: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "addresses": [
        {
          "address": "string",
          "assignmentMode": "string",
          "gateway": "string",
          "nameservers": {
            "addresses": [
              "string"
            ]
          },
          "prefix": "string",
          "protocol": "string"
        }
      ]
    }
"""
