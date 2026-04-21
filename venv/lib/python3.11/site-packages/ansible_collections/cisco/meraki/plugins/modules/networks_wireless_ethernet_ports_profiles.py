#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_ethernet_ports_profiles
short_description: Resource module for networks _wireless _ethernet _ports _profiles
description:
  - Manage operations update and delete of the resource networks _wireless _ethernet _ports _profiles.
  - Delete an AP port profile.
  - Update the AP port profile by ID for this network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  name:
    description: AP port profile name.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  ports:
    description: AP ports configuration.
    elements: dict
    suboptions:
      enabled:
        description: AP port enabled.
        type: bool
      name:
        description: AP port name.
        type: str
      pskGroupId:
        description: AP port PSK Group number.
        type: str
      ssid:
        description: AP port ssid number.
        type: int
    type: list
  profileId:
    description: ProfileId path parameter. Profile ID.
    type: str
  usbPorts:
    description: AP usb ports configuration.
    elements: dict
    suboptions:
      enabled:
        description: AP usb port enabled.
        type: bool
      name:
        description: AP usb port name.
        type: str
      ssid:
        description: AP usb port ssid number.
        type: int
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless deleteNetworkWirelessEthernetPortsProfile
    description: Complete reference of the deleteNetworkWirelessEthernetPortsProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-wireless-ethernet-ports-profile
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessEthernetPortsProfile
    description: Complete reference of the updateNetworkWirelessEthernetPortsProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-ethernet-ports-profile
notes:
  - SDK Method used are
    wireless.Wireless.delete_network_wireless_ethernet_ports_profile,
    wireless.Wireless.update_network_wireless_ethernet_ports_profile,
  - Paths used are
    delete /networks/{networkId}/wireless/ethernet/ports/profiles/{profileId},
    put /networks/{networkId}/wireless/ethernet/ports/profiles/{profileId},
"""

EXAMPLES = r"""
- name: Delete by id
  cisco.meraki.networks_wireless_ethernet_ports_profiles:
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
    state: absent
    networkId: string
    profileId: string
- name: Update by id
  cisco.meraki.networks_wireless_ethernet_ports_profiles:
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
    name: string
    networkId: string
    ports:
      - enabled: true
        name: string
        pskGroupId: string
        ssid: 0
    profileId: string
    usbPorts:
      - enabled: true
        name: string
        ssid: 0
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "isDefault": true,
      "name": "string",
      "ports": [
        {
          "enabled": true,
          "name": "string",
          "number": 0,
          "pskGroupId": "string",
          "ssid": 0
        }
      ],
      "profileId": "string",
      "usbPorts": [
        {
          "enabled": true,
          "name": "string",
          "ssid": 0
        }
      ]
    }
"""
