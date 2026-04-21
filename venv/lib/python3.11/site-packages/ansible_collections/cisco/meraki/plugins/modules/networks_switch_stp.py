#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_stp
short_description: Resource module for networks _switch _stp
description:
  - Manage operation update of the resource networks _switch _stp.
  - Updates STP settings.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  rstpEnabled:
    description: The spanning tree protocol status in network.
    type: bool
  stpBridgePriority:
    description: STP bridge priority for switches/stacks or switch templates. An empty array will clear the STP bridge priority settings.
    elements: dict
    suboptions:
      stacks:
        description: List of stack IDs.
        elements: str
        type: list
      stpPriority:
        description: STP priority for switch, stacks, or switch templates.
        type: int
      switchProfiles:
        description: List of switch template IDs.
        elements: str
        type: list
      switches:
        description: List of switch serial numbers.
        elements: str
        type: list
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch updateNetworkSwitchStp
    description: Complete reference of the updateNetworkSwitchStp API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-stp
notes:
  - SDK Method used are
    switch.Switch.update_network_switch_stp,
  - Paths used are
    put /networks/{networkId}/switch/stp,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_switch_stp:
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
    networkId: string
    rstpEnabled: true
    stpBridgePriority:
      - stacks:
          - '789102'
          - '123456'
          - '129102'
        stpPriority: 4096
        switchProfiles:
          - '1098'
          - '1099'
          - '1100'
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
      "rstpEnabled": true,
      "stpBridgePriority": [
        {
          "stacks": [
            "string"
          ],
          "stpPriority": 0,
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
