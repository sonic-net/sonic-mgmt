#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_ssids_bonjour_forwarding
short_description: Resource module for networks _wireless _ssids _bonjour _forwarding
description:
  - Manage operation update of the resource networks _wireless _ssids _bonjour _forwarding.
  - Update the bonjour forwarding setting and rules for the SSID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  enabled:
    description: If true, Bonjour forwarding is enabled on this SSID.
    type: bool
  exception:
    description: Bonjour forwarding exception.
    suboptions:
      enabled:
        description: If true, Bonjour forwarding exception is enabled on this SSID. Exception is required to enable L2 isolation and Bonjour forwarding
          to work together.
        type: bool
    type: dict
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  number:
    description: Number path parameter.
    type: str
  rules:
    description: List of bonjour forwarding rules.
    elements: dict
    suboptions:
      description:
        description: A description for your Bonjour forwarding rule. Optional.
        type: str
      services:
        description: A list of Bonjour services. At least one service must be specified. Available services are 'All Services', 'AFP', 'AirPlay',
          'Apple screen share', 'BitTorrent', 'Chromecast', 'FTP', 'iChat', 'iTunes', 'Printers', 'Samba', 'Scanners', 'Spotify' and 'SSH'.
        elements: str
        type: list
      vlanId:
        description: The ID of the service VLAN. Required.
        type: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessSsidBonjourForwarding
    description: Complete reference of the updateNetworkWirelessSsidBonjourForwarding API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-ssid-bonjour-forwarding
notes:
  - SDK Method used are
    wireless.Wireless.update_network_wireless_ssid_bonjour_forwarding,
  - Paths used are
    put /networks/{networkId}/wireless/ssids/{number}/bonjourForwarding,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_wireless_ssids_bonjour_forwarding:
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
    enabled: true
    exception:
      enabled: true
    networkId: string
    number: string
    rules:
      - description: A simple bonjour rule
        services:
          - All Services
        vlanId: '1'
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "enabled": true,
      "exception": {
        "enabled": true
      },
      "rules": [
        {
          "description": "string",
          "services": [
            "string"
          ],
          "vlanId": "string"
        }
      ]
    }
"""
