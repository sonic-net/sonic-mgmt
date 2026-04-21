#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_access_policies_info
short_description: Information module for networks _switch _access _policies
description:
  - Get all networks _switch _access _policies.
  - Get networks _switch _access _policies by id. - > List the access policies for a switch network. Only returns access policies with 'my RADIUS
    server' as authentication method.
  - Return a specific access policy for a switch network.
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
  accessPolicyNumber:
    description:
      - AccessPolicyNumber path parameter. Access policy number.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch getNetworkSwitchAccessPolicies
    description: Complete reference of the getNetworkSwitchAccessPolicies API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-switch-access-policies
  - name: Cisco Meraki documentation for switch getNetworkSwitchAccessPolicy
    description: Complete reference of the getNetworkSwitchAccessPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-switch-access-policy
notes:
  - SDK Method used are
    switch.Switch.get_network_switch_access_policies,
    switch.Switch.get_network_switch_access_policy,
  - Paths used are
    get /networks/{networkId}/switch/accessPolicies,
    get /networks/{networkId}/switch/accessPolicies/{accessPolicyNumber},
"""

EXAMPLES = r"""
- name: Get all networks _switch _access _policies
  cisco.meraki.networks_switch_access_policies_info:
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
- name: Get networks _switch _access _policies by id
  cisco.meraki.networks_switch_access_policies_info:
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
    accessPolicyNumber: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "accessPolicyType": "string",
      "counts": {
        "ports": {
          "withThisPolicy": 0
        }
      },
      "dot1x": {
        "controlDirection": "string"
      },
      "guestPortBouncing": true,
      "guestVlanId": 0,
      "hostMode": "string",
      "increaseAccessSpeed": true,
      "name": "string",
      "radius": {
        "cache": {
          "enabled": true,
          "timeout": 0
        },
        "criticalAuth": {
          "dataVlanId": 0,
          "suspendPortBounce": true,
          "voiceVlanId": 0
        },
        "failedAuthVlanId": 0,
        "reAuthenticationInterval": 0
      },
      "radiusAccountingEnabled": true,
      "radiusAccountingServers": [
        {
          "host": "string",
          "organizationRadiusServerId": "string",
          "port": 0,
          "serverId": "string"
        }
      ],
      "radiusCoaSupportEnabled": true,
      "radiusGroupAttribute": "string",
      "radiusServers": [
        {
          "host": "string",
          "organizationRadiusServerId": "string",
          "port": 0,
          "serverId": "string"
        }
      ],
      "radiusTestingEnabled": true,
      "urlRedirectWalledGardenEnabled": true,
      "urlRedirectWalledGardenRanges": [
        "string"
      ],
      "voiceVlanClients": true
    }
"""
