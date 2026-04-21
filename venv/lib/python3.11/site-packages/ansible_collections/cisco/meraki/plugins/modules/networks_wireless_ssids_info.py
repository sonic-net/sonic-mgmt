#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_ssids_info
short_description: Information module for networks _wireless _ssids
description:
  - Get all networks _wireless _ssids.
  - Get networks _wireless _ssids by id.
  - List the MR SSIDs in a network.
  - Return a single MR SSID.
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
  number:
    description:
      - Number path parameter.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless getNetworkWirelessSsid
    description: Complete reference of the getNetworkWirelessSsid API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-wireless-ssid
  - name: Cisco Meraki documentation for wireless getNetworkWirelessSsids
    description: Complete reference of the getNetworkWirelessSsids API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-wireless-ssids
notes:
  - SDK Method used are
    wireless.Wireless.get_network_wireless_ssid,
    wireless.Wireless.get_network_wireless_ssids,
  - Paths used are
    get /networks/{networkId}/wireless/ssids,
    get /networks/{networkId}/wireless/ssids/{number},
"""

EXAMPLES = r"""
- name: Get all networks _wireless _ssids
  cisco.meraki.networks_wireless_ssids_info:
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
- name: Get networks _wireless _ssids by id
  cisco.meraki.networks_wireless_ssids_info:
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
    number: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "adminSplashUrl": "string",
      "authMode": "string",
      "availabilityTags": [
        "string"
      ],
      "availableOnAllAps": true,
      "bandSelection": "string",
      "enabled": true,
      "encryptionMode": "string",
      "ipAssignmentMode": "string",
      "localAuth": true,
      "mandatoryDhcpEnabled": true,
      "minBitrate": 0,
      "name": "string",
      "number": 0,
      "perClientBandwidthLimitDown": 0,
      "perClientBandwidthLimitUp": 0,
      "perSsidBandwidthLimitDown": 0,
      "perSsidBandwidthLimitUp": 0,
      "radiusAccountingEnabled": true,
      "radiusAccountingServers": [
        {
          "caCertificate": "string",
          "host": "string",
          "openRoamingCertificateId": 0,
          "port": 0
        }
      ],
      "radiusAttributeForGroupPolicies": "string",
      "radiusEnabled": true,
      "radiusFailoverPolicy": "string",
      "radiusLoadBalancingPolicy": "string",
      "radiusServers": [
        {
          "caCertificate": "string",
          "host": "string",
          "openRoamingCertificateId": 0,
          "port": 0
        }
      ],
      "splashPage": "string",
      "splashTimeout": "string",
      "ssidAdminAccessible": true,
      "visible": true,
      "walledGardenEnabled": true,
      "walledGardenRanges": [
        "string"
      ],
      "wpaEncryptionMode": "string"
    }
"""
