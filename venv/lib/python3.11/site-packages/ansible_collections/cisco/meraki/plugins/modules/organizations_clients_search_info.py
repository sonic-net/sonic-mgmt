#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_clients_search_info
short_description: Information module for organizations _clients _search
description:
  - Get all organizations _clients _search.
  - Return the client details in an organization.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
  - cisco.meraki.module_info_pagination
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  organizationId:
    description:
      - OrganizationId path parameter. Organization ID.
    type: str
  perPage:
    description:
      - PerPage query parameter. The number of entries per page returned. Acceptable range is 3 - 5. Default is 5.
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
  mac:
    description:
      - Mac query parameter. The MAC address of the client. Required.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations getOrganizationClientsSearch
    description: Complete reference of the getOrganizationClientsSearch API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-organization-clients-search
notes:
  - SDK Method used are
    organizations.Organizations.get_organization_clients_search,
  - Paths used are
    get /organizations/{organizationId}/clients/search,
"""

EXAMPLES = r"""
- name: Get all organizations _clients _search
  cisco.meraki.organizations_clients_search_info:
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
    mac: string
    organizationId: string
    total_pages: -1
    direction: next
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "clientId": "string",
      "mac": "string",
      "manufacturer": "string",
      "records": [
        {
          "cdp": [
            [
              "string"
            ]
          ],
          "clientVpnConnections": [
            {
              "connectedAt": 0,
              "disconnectedAt": 0,
              "remoteIp": "string"
            }
          ],
          "description": "string",
          "firstSeen": 0,
          "ip": "string",
          "ip6": "string",
          "lastSeen": 0,
          "lldp": [
            [
              "string"
            ]
          ],
          "network": {
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
          },
          "os": "string",
          "recentDeviceMac": "string",
          "smInstalled": true,
          "ssid": "string",
          "status": "string",
          "switchport": "string",
          "user": "string",
          "vlan": "string",
          "wirelessCapabilities": "string"
        }
      ]
    }
"""
