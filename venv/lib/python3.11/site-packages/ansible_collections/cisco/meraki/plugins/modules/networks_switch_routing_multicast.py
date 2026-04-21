#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_routing_multicast
short_description: Resource module for networks _switch _routing _multicast
description:
  - Manage operation update of the resource networks _switch _routing _multicast.
  - Update multicast settings for a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  defaultSettings:
    description: Default multicast setting for entire network. IGMP snooping and Flood unknown multicast traffic settings are enabled by default.
    suboptions:
      floodUnknownMulticastTrafficEnabled:
        description: Flood unknown multicast traffic setting for entire network.
        type: bool
      igmpSnoopingEnabled:
        description: IGMP snooping setting for entire network.
        type: bool
    type: dict
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  overrides:
    description: Array of paired switches/stacks/profiles and corresponding multicast settings. An empty array will clear the multicast settings.
    elements: dict
    suboptions:
      floodUnknownMulticastTrafficEnabled:
        description: Flood unknown multicast traffic setting for switches, switch stacks or switch templates.
        type: bool
      igmpSnoopingEnabled:
        description: IGMP snooping setting for switches, switch stacks or switch templates.
        type: bool
      stacks:
        description: List of switch stack ids for non-template network.
        elements: str
        type: list
      switchProfiles:
        description: List of switch templates ids for template network.
        elements: str
        type: list
      switches:
        description: List of switch serials for non-template network.
        elements: str
        type: list
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch updateNetworkSwitchRoutingMulticast
    description: Complete reference of the updateNetworkSwitchRoutingMulticast API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-routing-multicast
notes:
  - SDK Method used are
    switch.Switch.update_network_switch_routing_multicast,
  - Paths used are
    put /networks/{networkId}/switch/routing/multicast,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_switch_routing_multicast:
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
    defaultSettings:
      floodUnknownMulticastTrafficEnabled: true
      igmpSnoopingEnabled: true
    networkId: string
    overrides:
      - floodUnknownMulticastTrafficEnabled: true
        igmpSnoopingEnabled: true
        stacks:
          - '789102'
          - '123456'
          - '129102'
        switchProfiles:
          - '1234'
          - '4567'
        switches:
          - Q234-ABCD-0001
          - Q234-ABCD-0002
          - Q234-ABCD-0003
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "defaultSettings": {
        "floodUnknownMulticastTrafficEnabled": true,
        "igmpSnoopingEnabled": true
      },
      "overrides": [
        {
          "floodUnknownMulticastTrafficEnabled": true,
          "igmpSnoopingEnabled": true,
          "stacks": [
            "string"
          ],
          "switchProfiles": [
            "string"
          ],
          "switches": [
            "string"
          ]
        }
      ]
    }
"""
