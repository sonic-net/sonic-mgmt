#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_vlans_info
short_description: Information module for networks _appliance _vlans
description:
  - Get all networks _appliance _vlans.
  - Get networks _appliance _vlans by id.
  - List the VLANs for an MX network.
  - Return a VLAN.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  networkId:
    description:
      - NetworkId path parameter. Network ID.
    type: str
  vlanId:
    description:
      - VlanId path parameter. Vlan ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance getNetworkApplianceVlan
    description: Complete reference of the getNetworkApplianceVlan API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-appliance-vlan
  - name: Cisco Meraki documentation for appliance getNetworkApplianceVlans
    description: Complete reference of the getNetworkApplianceVlans API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-appliance-vlans
notes:
  - SDK Method used are
    appliance.Appliance.get_network_appliance_vlan,
    appliance.Appliance.get_network_appliance_vlans,
  - Paths used are
    get /networks/{networkId}/appliance/vlans,
    get /networks/{networkId}/appliance/vlans/{vlanId},
"""

EXAMPLES = r"""
- name: Get all networks _appliance _vlans
  cisco.meraki.networks_appliance_vlans_info:
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
    networkId: string
  register: result
- name: Get networks _appliance _vlans by id
  cisco.meraki.networks_appliance_vlans_info:
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
    networkId: string
    vlanId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "applianceIp": "string",
      "cidr": "string",
      "dhcpBootFilename": "string",
      "dhcpBootNextServer": "string",
      "dhcpBootOptionsEnabled": true,
      "dhcpHandling": "string",
      "dhcpLeaseTime": "string",
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
      "dnsNameservers": "string",
      "fixedIpAssignments": {},
      "groupPolicyId": "string",
      "id": "string",
      "interfaceId": "string",
      "ipv6": {
        "enabled": true,
        "prefixAssignments": [
          {
            "autonomous": true,
            "origin": {
              "interfaces": [
                "string"
              ],
              "type": "string"
            },
            "staticApplianceIp6": "string",
            "staticPrefix": "string"
          }
        ]
      },
      "mandatoryDhcp": {
        "enabled": true
      },
      "mask": 0,
      "name": "string",
      "reservedIpRanges": [
        {
          "comment": "string",
          "end": "string",
          "start": "string"
        }
      ],
      "subnet": "string",
      "templateVlanType": "string",
      "vpnNatSubnet": "string"
    }
"""
