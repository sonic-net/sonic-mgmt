#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_routing_multicast_rendezvous_points
short_description: Resource module for networks _switch _routing _multicast _rendezvous _points
description:
  - Manage operations create, update and delete of the resource networks _switch _routing _multicast _rendezvous _points.
  - Create a multicast rendezvous point.
  - Delete a multicast rendezvous point.
  - Update a multicast rendezvous point.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  interfaceIp:
    description: The IP address of the interface where the RP needs to be created.
    type: str
  multicastGroup:
    description: '''Any'', or the IP address of a multicast group.'
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  rendezvousPointId:
    description: RendezvousPointId path parameter. Rendezvous point ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch createNetworkSwitchRoutingMulticastRendezvousPoint
    description: Complete reference of the createNetworkSwitchRoutingMulticastRendezvousPoint API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-switch-routing-multicast-rendezvous-point
  - name: Cisco Meraki documentation for switch deleteNetworkSwitchRoutingMulticastRendezvousPoint
    description: Complete reference of the deleteNetworkSwitchRoutingMulticastRendezvousPoint API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-switch-routing-multicast-rendezvous-point
  - name: Cisco Meraki documentation for switch updateNetworkSwitchRoutingMulticastRendezvousPoint
    description: Complete reference of the updateNetworkSwitchRoutingMulticastRendezvousPoint API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-routing-multicast-rendezvous-point
notes:
  - SDK Method used are
    switch.Switch.create_network_switch_routing_multicast_rendezvous_point,
    switch.Switch.delete_network_switch_routing_multicast_rendezvous_point,
    switch.Switch.update_network_switch_routing_multicast_rendezvous_point,
  - Paths used are
    post /networks/{networkId}/switch/routing/multicast/rendezvousPoints,
    delete /networks/{networkId}/switch/routing/multicast/rendezvousPoints/{rendezvousPointId},
    put /networks/{networkId}/switch/routing/multicast/rendezvousPoints/{rendezvousPointId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_switch_routing_multicast_rendezvous_points:
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
    interfaceIp: 192.168.1.2
    multicastGroup: Any
    networkId: string
- name: Delete by id
  cisco.meraki.networks_switch_routing_multicast_rendezvous_points:
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
    networkId: string
    rendezvousPointId: string
- name: Update by id
  cisco.meraki.networks_switch_routing_multicast_rendezvous_points:
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
    interfaceIp: 192.168.1.2
    multicastGroup: Any
    networkId: string
    rendezvousPointId: string
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
