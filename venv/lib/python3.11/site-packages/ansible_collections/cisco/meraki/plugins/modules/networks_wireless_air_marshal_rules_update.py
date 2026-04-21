#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_air_marshal_rules_update
short_description: Resource module for networks _wireless _air _marshal _rules _update
description:
  - Manage operation update of the resource networks _wireless _air _marshal _rules _update.
  - Update a rule.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  match:
    description: Object describing the rule specification.
    suboptions:
      string:
        description: The string used to match.
        type: str
      type:
        description: The type of match.
        type: str
    type: dict
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  ruleId:
    description: RuleId path parameter. Rule ID.
    type: str
  type:
    description: Indicates if this rule will allow, block, or alert.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessAirMarshalRule
    description: Complete reference of the updateNetworkWirelessAirMarshalRule API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-air-marshal-rule
notes:
  - SDK Method used are
    wireless.Wireless.update_network_wireless_air_marshal_rule,
  - Paths used are
    put /networks/{networkId}/wireless/airMarshal/rules/{ruleId},
"""

EXAMPLES = r"""
- name: Update by id
  cisco.meraki.networks_wireless_air_marshal_rules_update:
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
    match:
      string: 00:11:22:33:44:55
      type: bssid
    networkId: string
    ruleId: string
    type: allow
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "createdAt": "string",
      "match": {
        "string": "string",
        "type": "string"
      },
      "network": {
        "id": "string",
        "name": "string"
      },
      "ruleId": "string",
      "type": "string",
      "updatedAt": "string"
    }
"""
