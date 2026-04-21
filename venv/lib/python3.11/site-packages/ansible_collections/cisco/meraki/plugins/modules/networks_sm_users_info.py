#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_sm_users_info
short_description: Information module for networks _sm _users
description:
  - Get all networks _sm _users.
  - List the owners in an SM network with various specified fields and filters.
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
  ids:
    description:
      - Ids query parameter. Filter users by id(s).
    elements: str
    type: list
  usernames:
    description:
      - Usernames query parameter. Filter users by username(s).
    elements: str
    type: list
  emails:
    description:
      - Emails query parameter. Filter users by email(s).
    elements: str
    type: list
  scope:
    description:
      - >
        Scope query parameter. Specifiy a scope (one of all, none, withAny, withAll, withoutAny, withoutAll) and a set of tags.
    elements: str
    type: list
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for sm getNetworkSmUsers
    description: Complete reference of the getNetworkSmUsers API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-sm-users
notes:
  - SDK Method used are
    sm.Sm.get_network_sm_users,
  - Paths used are
    get /networks/{networkId}/sm/users,
"""

EXAMPLES = r"""
- name: Get all networks _sm _users
  cisco.meraki.networks_sm_users_info:
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
    ids: []
    usernames: []
    emails: []
    scope: []
    networkId: string
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
        "adGroups": [
          "string"
        ],
        "asmGroups": [
          "string"
        ],
        "azureAdGroups": [
          "string"
        ],
        "displayName": "string",
        "email": "string",
        "fullName": "string",
        "hasIdentityCertificate": true,
        "hasPassword": true,
        "id": "string",
        "isExternal": true,
        "samlGroups": [
          "string"
        ],
        "tags": "string",
        "userThumbnail": "string",
        "username": "string"
      }
    ]
"""
