#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: devices_switch_routing_static_routes
short_description: Resource module for devices _switch _routing _static _routes
description:
  - Manage operations create, update and delete of the resource devices _switch _routing _static _routes.
  - Create a layer 3 static route for a switch.
  - Delete a layer 3 static route for a switch.
  - Update a layer 3 static route for a switch.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  advertiseViaOspfEnabled:
    description: Option to advertise static route via OSPF.
    type: bool
  managementNextHop:
    description: Optional fallback IP address for management traffic.
    type: str
  name:
    description: Name or description for layer 3 static route.
    type: str
  nextHopIp:
    description: IP address of the next hop device to which the device sends its traffic for the subnet.
    type: str
  preferOverOspfRoutesEnabled:
    description: Option to prefer static route over OSPF routes.
    type: bool
  serial:
    description: Serial path parameter.
    type: str
  staticRouteId:
    description: StaticRouteId path parameter. Static route ID.
    type: str
  subnet:
    description: The subnet which is routed via this static route and should be specified in CIDR notation (ex. 1.2.3.0/24).
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch createDeviceSwitchRoutingStaticRoute
    description: Complete reference of the createDeviceSwitchRoutingStaticRoute API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-device-switch-routing-static-route
  - name: Cisco Meraki documentation for switch deleteDeviceSwitchRoutingStaticRoute
    description: Complete reference of the deleteDeviceSwitchRoutingStaticRoute API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-device-switch-routing-static-route
  - name: Cisco Meraki documentation for switch updateDeviceSwitchRoutingStaticRoute
    description: Complete reference of the updateDeviceSwitchRoutingStaticRoute API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-device-switch-routing-static-route
notes:
  - SDK Method used are
    switch.Switch.create_device_switch_routing_static_route,
    switch.Switch.delete_device_switch_routing_static_route,
    switch.Switch.update_device_switch_routing_static_route,
  - Paths used are
    post /devices/{serial}/switch/routing/staticRoutes,
    delete /devices/{serial}/switch/routing/staticRoutes/{staticRouteId},
    put
    /devices/{serial}/switch/routing/staticRoutes/{staticRouteId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.devices_switch_routing_static_routes:
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
    advertiseViaOspfEnabled: false
    name: My route
    nextHopIp: 1.2.3.4
    preferOverOspfRoutesEnabled: false
    serial: string
    subnet: 192.168.1.0/24
- name: Delete by id
  cisco.meraki.devices_switch_routing_static_routes:
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
    state: absent
    serial: string
    staticRouteId: string
- name: Update by id
  cisco.meraki.devices_switch_routing_static_routes:
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
    advertiseViaOspfEnabled: false
    managementNextHop: 1.2.3.5
    name: My route
    nextHopIp: 1.2.3.4
    preferOverOspfRoutesEnabled: false
    serial: string
    staticRouteId: string
    subnet: 192.168.1.0/24
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
