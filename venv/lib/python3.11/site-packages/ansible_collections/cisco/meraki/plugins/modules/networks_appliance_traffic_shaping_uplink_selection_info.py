#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_traffic_shaping_uplink_selection_info
short_description: Information module for networks _appliance _traffic _shaping _uplink _selection
description:
  - Get all networks _appliance _traffic _shaping _uplink _selection.
  - Show uplink selection settings for an MX network.
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
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance getNetworkApplianceTrafficShapingUplinkSelection
    description: Complete reference of the getNetworkApplianceTrafficShapingUplinkSelection API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-appliance-traffic-shaping-uplink-selection
notes:
  - SDK Method used are
    appliance.Appliance.get_network_appliance_traffic_shaping_uplink_selection,
  - Paths used are
    get /networks/{networkId}/appliance/trafficShaping/uplinkSelection,
"""

EXAMPLES = r"""
- name: Get all networks _appliance _traffic _shaping _uplink _selection
  cisco.meraki.networks_appliance_traffic_shaping_uplink_selection_info:
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
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "activeActiveAutoVpnEnabled": true,
      "defaultUplink": "string",
      "failoverAndFailback": {
        "immediate": {
          "enabled": true
        }
      },
      "loadBalancingEnabled": true,
      "vpnTrafficUplinkPreferences": [
        {
          "failOverCriterion": "string",
          "performanceClass": {
            "builtinPerformanceClassName": "string",
            "customPerformanceClassId": "string",
            "type": "string"
          },
          "preferredUplink": "string",
          "trafficFilters": [
            {
              "type": "string",
              "value": {
                "destination": {
                  "cidr": "string",
                  "fqdn": "string",
                  "host": 0,
                  "network": "string",
                  "port": "string",
                  "vlan": 0
                },
                "id": "string",
                "protocol": "string",
                "source": {
                  "cidr": "string",
                  "host": 0,
                  "network": "string",
                  "port": "string",
                  "vlan": 0
                }
              }
            }
          ]
        }
      ],
      "wanTrafficUplinkPreferences": [
        {
          "preferredUplink": "string",
          "trafficFilters": [
            {
              "type": "string",
              "value": {
                "destination": {
                  "applications": [
                    {
                      "id": "string",
                      "name": "string",
                      "type": "string"
                    }
                  ],
                  "cidr": "string",
                  "port": "string"
                },
                "protocol": "string",
                "source": {
                  "cidr": "string",
                  "host": 0,
                  "port": "string",
                  "vlan": 0
                }
              }
            }
          ]
        }
      ]
    }
"""
