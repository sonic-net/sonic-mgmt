#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_security_intrusion
short_description: Resource module for networks _appliance _security _intrusion
description:
  - Manage operation update of the resource networks _appliance _security _intrusion.
  - Set the supported intrusion settings for an MX network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  idsRulesets:
    description: Set the detection ruleset 'connectivity'/'balanced'/'security' (optional - omitting will leave current config unchanged). Default
      value is 'balanced' if none currently saved.
    type: str
  mode:
    description: Set mode to 'disabled'/'detection'/'prevention' (optional - omitting will leave current config unchanged).
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  protectedNetworks:
    description: Set the included/excluded networks from the intrusion engine (optional - omitting will leave current config unchanged). This
      is available only in 'passthrough' mode.
    suboptions:
      excludedCidr:
        description: List of IP addresses or subnets being excluded from protection (required if 'useDefault' is false).
        elements: str
        type: list
      includedCidr:
        description: List of IP addresses or subnets being protected (required if 'useDefault' is false).
        elements: str
        type: list
      useDefault:
        description: true/false whether to use special IPv4 addresses https //tools.ietf.org/html/rfc5735 (required). Default value is true if
          none currently saved.
        type: bool
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance updateNetworkApplianceSecurityIntrusion
    description: Complete reference of the updateNetworkApplianceSecurityIntrusion API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-security-intrusion
notes:
  - SDK Method used are
    appliance.Appliance.update_network_appliance_security_intrusion,
  - Paths used are
    put /networks/{networkId}/appliance/security/intrusion,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_appliance_security_intrusion:
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
    idsRulesets: balanced
    mode: prevention
    networkId: string
    protectedNetworks:
      excludedCidr:
        - 10.0.0.0/8
        - 127.0.0.0/8
      includedCidr:
        - 10.0.0.0/8
        - 127.0.0.0/8
        - 169.254.0.0/16
        - 172.16.0.0/12
      useDefault: false
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "idsRulesets": "string",
      "mode": "string",
      "protectedNetworks": {
        "excludedCidr": [
          "string"
        ],
        "includedCidr": [
          "string"
        ],
        "useDefault": true
      }
    }
"""
