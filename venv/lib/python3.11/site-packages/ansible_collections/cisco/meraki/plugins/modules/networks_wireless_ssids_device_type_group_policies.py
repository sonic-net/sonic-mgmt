#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_ssids_device_type_group_policies
short_description: Resource module for networks _wireless _ssids _device _type _group _policies
description:
  - Manage operation update of the resource networks _wireless _ssids _device _type _group _policies.
  - Update the device type group policies for the SSID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  deviceTypePolicies:
    description: List of device type policies.
    elements: dict
    suboptions:
      devicePolicy:
        description: The device policy. Can be one of 'Allowed', 'Blocked' or 'Group policy'.
        type: str
      deviceType:
        description: The device type. Can be one of 'Android', 'BlackBerry', 'Chrome OS', 'iPad', 'iPhone', 'iPod', 'Mac OS X', 'Windows', 'Windows
          Phone', 'B&N Nook' or 'Other OS'.
        type: str
      groupPolicyId:
        description: ID of the group policy object.
        type: int
    type: list
  enabled:
    description: If true, the SSID device type group policies are enabled.
    type: bool
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  number:
    description: Number path parameter.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessSsidDeviceTypeGroupPolicies
    description: Complete reference of the updateNetworkWirelessSsidDeviceTypeGroupPolicies API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-ssid-device-type-group-policies
notes:
  - SDK Method used are
    wireless.Wireless.update_network_wireless_ssid_device_type_group_policies,
  - Paths used are
    put /networks/{networkId}/wireless/ssids/{number}/deviceTypeGroupPolicies,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_wireless_ssids_device_type_group_policies:
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
    deviceTypePolicies:
      - devicePolicy: Allowed
        deviceType: Android
      - devicePolicy: Group policy
        deviceType: iPhone
        groupPolicyId: 101
    enabled: true
    networkId: string
    number: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
