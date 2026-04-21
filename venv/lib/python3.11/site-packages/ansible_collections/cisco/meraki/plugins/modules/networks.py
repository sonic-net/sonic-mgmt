#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks
short_description: Resource module for networks
description:
  - Manage operations create, update and delete of the resource networks.
  - Create a network.
  - Delete a network.
  - Update a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  copyFromNetworkId:
    description: The ID of the network to copy configuration from. Other provided parameters will override the copied configuration, except type
      which must match this network's type exactly.
    type: str
  enrollmentString:
    description: A unique identifier which can be used for device enrollment or easy access through the Meraki SM Registration page or the Self
      Service Portal. Please note that changing this field may cause existing bookmarks to break.
    type: str
  name:
    description: The name of the network.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  notes:
    description: Add any notes or additional information about this network here.
    type: str
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
  productTypes:
    description: The product type(s) of the new network. If more than one type is included, the network will be a combined network.
    elements: str
    type: list
  tags:
    description: A list of tags to be applied to the network.
    elements: str
    type: list
  timeZone:
    description: The timezone of the network. For a list of allowed timezones, please see the 'TZ' column in the table in <a target='_blank' href='https
      //en.wikipedia.org/wiki/List_of_tz_databas... article.</a>.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks createOrganizationNetwork
    description: Complete reference of the createOrganizationNetwork API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-network
  - name: Cisco Meraki documentation for networks deleteNetwork
    description: Complete reference of the deleteNetwork API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network
  - name: Cisco Meraki documentation for networks updateNetwork
    description: Complete reference of the updateNetwork API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network
notes:
  - SDK Method used are
    networks.Networks.create_organization_network,
    networks.Networks.delete_network,
    networks.Networks.update_network,
  - Paths used are
    post /organizations/{organizationId}/networks,
    delete /networks/{networkId},
    put /networks/{networkId},
"""

EXAMPLES = r"""
- name: Delete by id
  cisco.meraki.networks:
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
- name: Update by id
  cisco.meraki.networks:
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
    enrollmentString: my-enrollment-string
    name: Main Office
    networkId: string
    notes: Additional description of the network
    tags:
      - tag1
      - tag2
    timeZone: America/Los_Angeles
- name: Create
  cisco.meraki.networks:
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
    copyFromNetworkId: N_24329156
    name: Main Office
    notes: Additional description of the network
    organizationId: string
    productTypes:
      - appliance
      - switch
      - wireless
    tags:
      - tag1
      - tag2
    timeZone: America/Los_Angeles
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "enrollmentString": "string",
      "id": "string",
      "isBoundToConfigTemplate": true,
      "name": "string",
      "notes": "string",
      "organizationId": "string",
      "productTypes": [
        "string"
      ],
      "tags": [
        "string"
      ],
      "timeZone": "string",
      "url": "string"
    }
"""
