#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_stacks_routing_static_routes_info
short_description: Information module for networks _switch _stacks _routing _static _routes
description:
  - Get all networks _switch _stacks _routing _static _routes.
  - Get networks _switch _stacks _routing _static _routes by id.
  - List layer 3 static routes for a switch stack.
  - Return a layer 3 static route for a switch stack.
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
  switchStackId:
    description:
      - SwitchStackId path parameter. Switch stack ID.
    type: str
  staticRouteId:
    description:
      - StaticRouteId path parameter. Static route ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch getNetworkSwitchStackRoutingStaticRoute
    description: Complete reference of the getNetworkSwitchStackRoutingStaticRoute API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-switch-stack-routing-static-route
  - name: Cisco Meraki documentation for switch getNetworkSwitchStackRoutingStaticRoutes
    description: Complete reference of the getNetworkSwitchStackRoutingStaticRoutes API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-switch-stack-routing-static-routes
notes:
  - SDK Method used are
    switch.Switch.get_network_switch_stack_routing_static_route,
    switch.Switch.get_network_switch_stack_routing_static_routes,
  - Paths used are
    get /networks/{networkId}/switch/stacks/{switchStackId}/routing/staticRoutes,
    get /networks/{networkId}/switch/stacks/{switchStackId}/routing/staticRoutes/{staticRouteId},
"""

EXAMPLES = r"""
- name: Get all networks _switch _stacks _routing _static _routes
  cisco.meraki.networks_switch_stacks_routing_static_routes_info:
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
    switchStackId: string
  register: result
- name: Get networks _switch _stacks _routing _static _routes by id
  cisco.meraki.networks_switch_stacks_routing_static_routes_info:
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
    switchStackId: string
    staticRouteId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "advertiseViaOspfEnabled": true,
      "managementNextHop": "string",
      "name": "string",
      "nextHopIp": "string",
      "preferOverOspfRoutesEnabled": true,
      "staticRouteId": "string",
      "subnet": "string"
    }
"""
