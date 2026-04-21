#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_vlan_profiles
short_description: Resource module for networks _vlan _profiles
description:
  - Manage operations create, update and delete of the resource networks _vlan _profiles.
  - Create a VLAN profile for a network.
  - Delete a VLAN profile of a network.
  - Update an existing VLAN profile of a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  iname:
    description: IName of the profile.
    type: str
  name:
    description: Name of the profile, string length must be from 1 to 255 characters.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  vlanGroups:
    description: An array of VLAN groups.
    elements: dict
    suboptions:
      name:
        description: Name of the VLAN, string length must be from 1 to 32 characters.
        type: str
      vlanIds:
        description: Comma-separated VLAN IDs or ID ranges.
        type: str
    type: list
  vlanNames:
    description: An array of named VLANs.
    elements: dict
    suboptions:
      adaptivePolicyGroup:
        description: Adaptive Policy Group assigned to Vlan ID.
        suboptions:
          id:
            description: Adaptive Policy Group ID.
            type: str
        type: dict
      name:
        description: Name of the VLAN, string length must be from 1 to 32 characters.
        type: str
      vlanId:
        description: VLAN ID.
        type: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks createNetworkVlanProfile
    description: Complete reference of the createNetworkVlanProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-vlan-profile
  - name: Cisco Meraki documentation for networks deleteNetworkVlanProfile
    description: Complete reference of the deleteNetworkVlanProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-vlan-profile
  - name: Cisco Meraki documentation for networks updateNetworkVlanProfile
    description: Complete reference of the updateNetworkVlanProfile API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-vlan-profile
notes:
  - SDK Method used are
    networks.Networks.create_network_vlan_profile,
    networks.Networks.delete_network_vlan_profile,
    networks.Networks.update_network_vlan_profile,
  - Paths used are
    post /networks/{networkId}/vlanProfiles,
    delete /networks/{networkId}/vlanProfiles/{iname},
    put /networks/{networkId}/vlanProfiles/{iname},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_vlan_profiles:
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
    iname: Profile1
    name: My VLAN profile name
    networkId: string
    vlanGroups:
      - name: named-group-1
        vlanIds: 2,5-7
    vlanNames:
      - adaptivePolicyGroup:
          id: '791'
        name: named-1
        vlanId: '1'
- name: Delete by name
  cisco.meraki.networks_vlan_profiles:
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
    iname: string
    networkId: string
- name: Update by name
  cisco.meraki.networks_vlan_profiles:
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
    iname: string
    name: My VLAN profile name
    networkId: string
    vlanGroups:
      - name: named-group-1
        vlanIds: 2,5-7
    vlanNames:
      - adaptivePolicyGroup:
          id: '791'
        name: named-1
        vlanId: '1'
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "iname": "string",
      "isDefault": true,
      "name": "string",
      "vlanGroups": [
        {
          "name": "string",
          "vlanIds": "string"
        }
      ],
      "vlanNames": [
        {
          "adaptivePolicyGroup": {
            "id": "string",
            "name": "string"
          },
          "name": "string",
          "vlanId": "string"
        }
      ]
    }
"""
