#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_group_policies_info
short_description: Information module for networks _group _policies
description:
  - Get all networks _group _policies.
  - Get networks _group _policies by id.
  - Display a group policy.
  - List the group policies in a network.
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
  groupPolicyId:
    description:
      - GroupPolicyId path parameter. Group policy ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks getNetworkGroupPolicies
    description: Complete reference of the getNetworkGroupPolicies API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-group-policies
  - name: Cisco Meraki documentation for networks getNetworkGroupPolicy
    description: Complete reference of the getNetworkGroupPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-group-policy
notes:
  - SDK Method used are
    networks.Networks.get_network_group_policies,
    networks.Networks.get_network_group_policy,
  - Paths used are
    get /networks/{networkId}/groupPolicies,
    get /networks/{networkId}/groupPolicies/{groupPolicyId},
"""

EXAMPLES = r"""
- name: Get all networks _group _policies
  cisco.meraki.networks_group_policies_info:
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
- name: Get networks _group _policies by id
  cisco.meraki.networks_group_policies_info:
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
    groupPolicyId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "bandwidth": {
        "bandwidthLimits": {
          "limitDown": 0,
          "limitUp": 0
        },
        "settings": "string"
      },
      "bonjourForwarding": {
        "rules": [
          {
            "description": "string",
            "services": [
              "string"
            ],
            "vlanId": "string"
          }
        ],
        "settings": "string"
      },
      "contentFiltering": {
        "allowedUrlPatterns": {
          "patterns": [
            "string"
          ],
          "settings": "string"
        },
        "blockedUrlCategories": {
          "categories": [
            "string"
          ],
          "settings": "string"
        },
        "blockedUrlPatterns": {
          "patterns": [
            "string"
          ],
          "settings": "string"
        }
      },
      "firewallAndTrafficShaping": {
        "l3FirewallRules": [
          {
            "comment": "string",
            "destCidr": "string",
            "destPort": "string",
            "policy": "string",
            "protocol": "string"
          }
        ],
        "l7FirewallRules": [
          {
            "policy": "string",
            "type": "string",
            "value": "string"
          }
        ],
        "settings": "string",
        "trafficShapingRules": [
          {
            "definitions": [
              {
                "type": "string",
                "value": "string"
              }
            ],
            "dscpTagValue": 0,
            "pcpTagValue": 0,
            "perClientBandwidthLimits": {
              "bandwidthLimits": {
                "limitDown": 0,
                "limitUp": 0
              },
              "settings": "string"
            },
            "priority": "string"
          }
        ]
      },
      "groupPolicyId": "string",
      "scheduling": {
        "enabled": true,
        "friday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "monday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "saturday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "sunday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "thursday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "tuesday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "wednesday": {
          "active": true,
          "from": "string",
          "to": "string"
        }
      },
      "splashAuthSettings": "string",
      "vlanTagging": {
        "settings": "string",
        "vlanId": "string"
      }
    }
"""
