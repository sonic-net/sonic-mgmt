#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_appliance_prefixes_delegated_statics
short_description: Resource module for networks _appliance _prefixes _delegated _statics
description:
  - Manage operations create, update and delete of the resource networks _appliance _prefixes _delegated _statics.
  - Add a static delegated prefix from a network.
  - Delete a static delegated prefix from a network.
  - Update a static delegated prefix from a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  description:
    description: A name or description for the prefix.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  origin:
    description: The origin of the prefix.
    suboptions:
      interfaces:
        description: Interfaces associated with the prefix.
        elements: str
        type: list
      type:
        description: Type of the origin.
        type: str
    type: dict
  prefix:
    description: A static IPv6 prefix.
    type: str
  staticDelegatedPrefixId:
    description: StaticDelegatedPrefixId path parameter. Static delegated prefix ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for appliance createNetworkAppliancePrefixesDelegatedStatic
    description: Complete reference of the createNetworkAppliancePrefixesDelegatedStatic API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-appliance-prefixes-delegated-static
  - name: Cisco Meraki documentation for appliance deleteNetworkAppliancePrefixesDelegatedStatic
    description: Complete reference of the deleteNetworkAppliancePrefixesDelegatedStatic API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-appliance-prefixes-delegated-static
  - name: Cisco Meraki documentation for appliance updateNetworkAppliancePrefixesDelegatedStatic
    description: Complete reference of the updateNetworkAppliancePrefixesDelegatedStatic API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-appliance-prefixes-delegated-static
notes:
  - SDK Method used are
    appliance.Appliance.create_network_appliance_prefixes_delegated_static,
    appliance.Appliance.delete_network_appliance_prefixes_delegated_static,
    appliance.Appliance.update_network_appliance_prefixes_delegated_static,
  - Paths used are
    post /networks/{networkId}/appliance/prefixes/delegated/statics,
    delete /networks/{networkId}/appliance/prefixes/delegated/statics/{staticDelegatedPrefixId},
    put /networks/{networkId}/appliance/prefixes/delegated/statics/{staticDelegatedPrefixId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_appliance_prefixes_delegated_statics:
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
    description: Prefix on WAN 1 of Long Island Office network
    networkId: string
    origin:
      interfaces:
        - wan1
      type: internet
    prefix: 2001:db8:3c4d:15::/64
- name: Delete by id
  cisco.meraki.networks_appliance_prefixes_delegated_statics:
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
    staticDelegatedPrefixId: string
- name: Update by id
  cisco.meraki.networks_appliance_prefixes_delegated_statics:
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
    description: Prefix on WAN 1 of Long Island Office network
    networkId: string
    origin:
      interfaces:
        - wan1
      type: internet
    prefix: 2001:db8:3c4d:15::/64
    staticDelegatedPrefixId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
