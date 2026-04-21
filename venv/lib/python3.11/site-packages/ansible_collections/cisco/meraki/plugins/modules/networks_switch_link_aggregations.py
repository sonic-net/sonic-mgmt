#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_link_aggregations
short_description: Resource module for networks _switch _link _aggregations
description:
  - Manage operations create, update and delete of the resource networks _switch _link _aggregations.
  - Create a link aggregation group.
  - Split a link aggregation group into separate ports.
  - Update a link aggregation group.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  linkAggregationId:
    description: LinkAggregationId path parameter. Link aggregation ID.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  switchPorts:
    description: Array of switch or stack ports for creating aggregation group. Minimum 2 and maximum 8 ports are supported.
    elements: dict
    suboptions:
      portId:
        description: Port identifier of switch port. For modules, the identifier is "SlotNumber_ModuleType_PortNumber" (Ex "1_8X10G_1"), otherwise
          it is just the port number (Ex "8").
        type: str
      serial:
        description: Serial number of the switch.
        type: str
    type: list
  switchProfilePorts:
    description: Array of switch profile ports for creating aggregation group. Minimum 2 and maximum 8 ports are supported.
    elements: dict
    suboptions:
      portId:
        description: Port identifier of switch port. For modules, the identifier is "SlotNumber_ModuleType_PortNumber" (Ex "1_8X10G_1"), otherwise
          it is just the port number (Ex "8").
        type: str
      profile:
        description: Profile identifier.
        type: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch createNetworkSwitchLinkAggregation
    description: Complete reference of the createNetworkSwitchLinkAggregation API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-switch-link-aggregation
  - name: Cisco Meraki documentation for switch deleteNetworkSwitchLinkAggregation
    description: Complete reference of the deleteNetworkSwitchLinkAggregation API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-switch-link-aggregation
  - name: Cisco Meraki documentation for switch updateNetworkSwitchLinkAggregation
    description: Complete reference of the updateNetworkSwitchLinkAggregation API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-link-aggregation
notes:
  - SDK Method used are
    switch.Switch.create_network_switch_link_aggregation,
    switch.Switch.delete_network_switch_link_aggregation,
    switch.Switch.update_network_switch_link_aggregation,
  - Paths used are
    post /networks/{networkId}/switch/linkAggregations,
    delete /networks/{networkId}/switch/linkAggregations/{linkAggregationId},
    put /networks/{networkId}/switch/linkAggregations/{linkAggregationId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_switch_link_aggregations:
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
    networkId: string
    switchPorts:
      - portId: '1'
        serial: Q234-ABCD-0001
    switchProfilePorts:
      - portId: '2'
        profile: '1234'
- name: Delete by id
  cisco.meraki.networks_switch_link_aggregations:
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
    linkAggregationId: string
    networkId: string
- name: Update by id
  cisco.meraki.networks_switch_link_aggregations:
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
    linkAggregationId: string
    networkId: string
    switchPorts:
      - portId: '1'
        serial: Q234-ABCD-0001
    switchProfilePorts:
      - portId: '2'
        profile: '1234'
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "switchPorts": [
        {
          "portId": "string",
          "serial": "string"
        }
      ]
    }
"""
