#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_storm_control
short_description: Resource module for networks _switch _storm _control
description:
  - Manage operation update of the resource networks _switch _storm _control.
  - Update the storm control configuration for a switch network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  broadcastThreshold:
    description: Percentage (1 to 99) of total available port bandwidth for broadcast traffic type. Default value 100 percent rate is to clear
      the configuration.
    type: int
  multicastThreshold:
    description: Percentage (1 to 99) of total available port bandwidth for multicast traffic type. Default value 100 percent rate is to clear
      the configuration.
    type: int
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  treatTheseTrafficTypesAsOneThreshold:
    description: Grouped traffic types.
    elements: str
    type: list
  unknownUnicastThreshold:
    description: Percentage (1 to 99) of total available port bandwidth for unknown unicast (dlf-destination lookup failure) traffic type. Default
      value 100 percent rate is to clear the configuration.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch updateNetworkSwitchStormControl
    description: Complete reference of the updateNetworkSwitchStormControl API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-storm-control
notes:
  - SDK Method used are
    switch.Switch.update_network_switch_storm_control,
  - Paths used are
    put /networks/{networkId}/switch/stormControl,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_switch_storm_control:
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
    broadcastThreshold: 30
    multicastThreshold: 30
    networkId: string
    treatTheseTrafficTypesAsOneThreshold:
      - broadcast
      - multicast
    unknownUnicastThreshold: 30
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "broadcastThreshold": 0,
      "multicastThreshold": 0,
      "treatTheseTrafficTypesAsOneThreshold": [
        "string"
      ],
      "unknownUnicastThreshold": 0
    }
"""
