#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_vlan_profiles_assignments_by_device_info
short_description: Information module for networks _vlan _profiles _assignments _by _device
description:
  - Get all networks _vlan _profiles _assignments _by _device.
  - Get the assigned VLAN Profiles for devices in a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
  - cisco.meraki.module_info_pagination
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  networkId:
    description:
      - NetworkId path parameter. Network ID.
    type: str
  perPage:
    description:
      - PerPage query parameter. The number of entries per page returned. Acceptable range is 3 - 1000. Default is 1000.
    type: int
  startingAfter:
    description:
      - >
        StartingAfter query parameter. A token used by the server to indicate the start of the page. Often this is a timestamp or an ID but it
        is not limited to those. This parameter should not be defined by client applications. The link for the first, last, prev, or next page
        in the HTTP Link header should define it.
    type: str
  endingBefore:
    description:
      - >
        EndingBefore query parameter. A token used by the server to indicate the end of the page. Often this is a timestamp or an ID but it is
        not limited to those. This parameter should not be defined by client applications. The link for the first, last, prev, or next page in
        the HTTP Link header should define it.
    type: str
  serials:
    description:
      - >
        Serials query parameter. Optional parameter to filter devices by serials. All devices returned belong to serial numbers that are an exact
        match.
    elements: str
    type: list
  productTypes:
    description:
      - ProductTypes query parameter. Optional parameter to filter devices by product types.
    elements: str
    type: list
  stackIds:
    description:
      - StackIds query parameter. Optional parameter to filter devices by Switch Stack ids.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks getNetworkVlanProfilesAssignmentsByDevice
    description: Complete reference of the getNetworkVlanProfilesAssignmentsByDevice API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-vlan-profiles-assignments-by-device
notes:
  - SDK Method used are
    networks.Networks.get_network_vlan_profiles_assignments_by_device,
  - Paths used are
    get /networks/{networkId}/vlanProfiles/assignments/byDevice,
"""

EXAMPLES = r"""
- name: Get all networks _vlan _profiles _assignments _by _device
  cisco.meraki.networks_vlan_profiles_assignments_by_device_info:
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
    perPage: 0
    startingAfter: string
    endingBefore: string
    serials: []
    productTypes: []
    stackIds: []
    networkId: string
    total_pages: -1
    direction: next
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "mac": "string",
        "name": "string",
        "productType": "string",
        "serial": "string",
        "stack": {
          "id": "string"
        },
        "vlanProfile": {
          "iname": "string",
          "isDefault": true,
          "name": "string"
        }
      }
    ]
"""
