#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_routing_multicast_rendezvous_points_info
short_description: Information module for networks _switch _routing _multicast _rendezvous _points
description:
  - Get all networks _switch _routing _multicast _rendezvous _points.
  - Get networks _switch _routing _multicast _rendezvous _points by id.
  - List multicast rendezvous points.
  - Return a multicast rendezvous point.
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
  rendezvousPointId:
    description:
      - RendezvousPointId path parameter. Rendezvous point ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch getNetworkSwitchRoutingMulticastRendezvousPoint
    description: Complete reference of the getNetworkSwitchRoutingMulticastRendezvousPoint API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-switch-routing-multicast-rendezvous-point
  - name: Cisco Meraki documentation for switch getNetworkSwitchRoutingMulticastRendezvousPoints
    description: Complete reference of the getNetworkSwitchRoutingMulticastRendezvousPoints API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-switch-routing-multicast-rendezvous-points
notes:
  - SDK Method used are
    switch.Switch.get_network_switch_routing_multicast_rendezvous_point,
    switch.Switch.get_network_switch_routing_multicast_rendezvous_points,
  - Paths used are
    get /networks/{networkId}/switch/routing/multicast/rendezvousPoints,
    get /networks/{networkId}/switch/routing/multicast/rendezvousPoints/{rendezvousPointId},
"""

EXAMPLES = r"""
- name: Get all networks _switch _routing _multicast _rendezvous _points
  cisco.meraki.networks_switch_routing_multicast_rendezvous_points_info:
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
- name: Get networks _switch _routing _multicast _rendezvous _points by id
  cisco.meraki.networks_switch_routing_multicast_rendezvous_points_info:
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
    rendezvousPointId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "interfaceIp": "string",
      "interfaceName": "string",
      "multicastGroup": "string",
      "rendezvousPointId": "string",
      "serial": "string"
    }
"""
