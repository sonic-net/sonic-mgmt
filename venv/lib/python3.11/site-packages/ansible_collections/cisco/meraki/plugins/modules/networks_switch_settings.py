#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_settings
short_description: Resource module for networks _switch _settings
description:
  - Manage operation update of the resource networks _switch _settings.
  - Update switch network settings.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  macBlocklist:
    description: MAC blocklist.
    suboptions:
      enabled:
        description: Enable MAC blocklist.
        type: bool
    type: dict
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  powerExceptions:
    description: Exceptions on a per switch basis to "useCombinedPower".
    elements: dict
    suboptions:
      powerType:
        description: Per switch exception (combined, redundant, useNetworkSetting).
        type: str
      serial:
        description: Serial number of the switch.
        type: str
    type: list
  uplinkClientSampling:
    description: Uplink client sampling.
    suboptions:
      enabled:
        description: Enable uplink client sampling.
        type: bool
    type: dict
  useCombinedPower:
    description: The use Combined Power as the default behavior of secondary power supplies on supported devices.
    type: bool
  vlan:
    description: Management VLAN.
    type: int
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch updateNetworkSwitchSettings
    description: Complete reference of the updateNetworkSwitchSettings API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-settings
notes:
  - SDK Method used are
    switch.Switch.update_network_switch_settings,
  - Paths used are
    put /networks/{networkId}/switch/settings,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_switch_settings:
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
    macBlocklist:
      enabled: true
    networkId: string
    powerExceptions:
      - powerType: string
        serial: string
    uplinkClientSampling:
      enabled: true
    useCombinedPower: true
    vlan: 0
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "macBlocklist": {
        "enabled": true
      },
      "powerExceptions": [
        {
          "powerType": "string",
          "serial": "string"
        }
      ],
      "uplinkClientSampling": {
        "enabled": true
      },
      "useCombinedPower": true,
      "vlan": 0
    }
"""
