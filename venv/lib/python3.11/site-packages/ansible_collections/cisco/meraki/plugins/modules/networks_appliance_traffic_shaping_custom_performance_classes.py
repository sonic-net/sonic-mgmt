#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_traffic_shaping_custom_performance_classes
short_description: Resource module for networks _appliance _traffic _shaping _custom _performance _classes
description:
  - Manage operation create of the resource networks _appliance _traffic _shaping _custom _performance _classes.
  - Add a custom performance class for an MX network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  maxJitter:
    description: Maximum jitter in milliseconds.
    type: int
  maxLatency:
    description: Maximum latency in milliseconds.
    type: int
  maxLossPercentage:
    description: Maximum percentage of packet loss.
    type: int
  name:
    description: Name of the custom performance class.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance createNetworkApplianceTrafficShapingCustomPerformanceClass
    description: Complete reference of the createNetworkApplianceTrafficShapingCustomPerformanceClass API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-appliance-traffic-shaping-custom-performance-class
notes:
  - SDK Method used are
    appliance.Appliance.create_network_appliance_traffic_shaping_custom_performance_class,
  - Paths used are
    post /networks/{networkId}/appliance/trafficShaping/customPerformanceClasses,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_appliance_traffic_shaping_custom_performance_classes:
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
    maxJitter: 100
    maxLatency: 100
    maxLossPercentage: 5
    name: myCustomPerformanceClass
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "customPerformanceClassId": "string",
      "maxJitter": 0,
      "maxLatency": 0,
      "maxLossPercentage": 0,
      "name": "string"
    }
"""
