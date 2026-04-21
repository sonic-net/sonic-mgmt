#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_clients_policy
short_description: Resource module for networks _clients _policy
description:
  - Manage operation update of the resource networks _clients _policy. - > Update the policy assigned to a client on the network. Clients can
    be identified by a client key or either the MAC or IP depending on whether the network uses Track-by-IP.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  clientId:
    description: ClientId path parameter. Client ID.
    type: str
  devicePolicy:
    description: The policy to assign. Can be 'Whitelisted', 'Blocked', 'Normal' or 'Group policy'. Required.
    type: str
  groupPolicyId:
    description: Optional If 'devicePolicy' is set to 'Group policy' this param is used to specify the group policy ID.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks updateNetworkClientPolicy
    description: Complete reference of the updateNetworkClientPolicy API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-client-policy
notes:
  - SDK Method used are
    networks.Networks.update_network_client_policy,
  - Paths used are
    put /networks/{networkId}/clients/{clientId}/policy,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_clients_policy:
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
    clientId: string
    devicePolicy: Group policy
    groupPolicyId: '101'
    networkId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "devicePolicy": "string",
      "groupPolicyId": "string",
      "mac": "string"
    }
"""
